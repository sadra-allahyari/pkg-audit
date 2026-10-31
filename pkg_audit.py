#!/usr/bin/env python3
"""Check that Docker registry mirrors serve what Docker Hub serves, for the images people pull.

A mirror that is compromised, or an insider, can answer `alpine:3.20` with a manifest that is not
Docker Hub's. Docker would accept it (a pull by tag checks no publisher signature), so the only
way to notice is to ask Docker Hub and the mirror the same question and compare. This does that
for any number of mirrors, ours and other operators', and writes a JSON report and a static page.

For every image in the list and every mirror:
  official  digest of the tag on registry-1.docker.io (asked directly, never through a mirror)
  mirror    digest the mirror answers for the same tag, and whether the manifest it serves by that
            digest really hashes to it (what Docker checks on a pull)
  verdict   ok        same digest as Docker Hub
            stale     another digest, but one Docker Hub itself still serves for this repository
                      (the tag moved and the mirror kept the old manifest): not an attack, the
                      mirror lags
            mismatch  a digest Docker Hub does not have at all, or a manifest whose bytes do not
                      hash to its digest: investigate at once
            error     the mirror did not answer usefully (HTTP status, timeout)
Layers are not downloaded: a manifest names its config and layers by hash, so equal manifest
digests mean equal content, and a client verifies every blob against the manifest it pulled.

Mirror list, one per line: `name https://host [ip]`. With an ip the TLS connection goes to that
address (SNI and certificate still for the host), to probe one PoP or one proxy of a mirror
instead of whatever DNS answers.

Limits, stated so nobody reads more into a green page than it says: this detects a mirror that
answers these questions wrongly. It cannot see one that answers the auditor correctly and other
clients (an address range, a time window such as an outage) wrongly; run it from several
networks, inside and outside Iran, and probe each PoP, and still pin digests in your own builds.

Python 3.8+, standard library only.
"""
import argparse
import contextlib
import hashlib
import html
import http.client
import json
import re
import signal
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

HUB = "https://registry-1.docker.io"
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


ITEM_LIMIT = 60      # seconds one check of one item may take, retries included
DEADLINE = None      # time.monotonic() value after which remaining checks are skipped (set by --max-seconds)
GIVE_UP_AFTER = 3    # consecutive items that timed out or could not connect: skip the rest of that mirror


@contextlib.contextmanager
def time_limit(seconds):
    """Hard wall-clock limit for the block. Socket timeouts only bound one read, so a server that
    sends a byte now and then could keep a check (and the whole CI job) alive for hours."""
    if not hasattr(signal, "SIGALRM"):  # Windows: no limit
        yield
        return

    def expired(*_):
        raise TimeoutError(f"no answer within {seconds}s")

    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def out_of_time():
    return DEADLINE is not None and time.monotonic() > DEADLINE


def skip_reason(down):
    if down >= GIVE_UP_AFTER:
        return f"skipped: {GIVE_UP_AFTER} requests in a row got no answer"
    return "skipped: the run's time budget (--max-seconds) was used up"


def unreachable(exc):
    """True for failures that say the host is not answering at all (not an HTTP status)."""
    return isinstance(exc, (TimeoutError, OSError, http.client.HTTPException)) and not isinstance(
        exc, urllib.error.HTTPError)


class Pinned(http.client.HTTPSConnection):
    """HTTPS to a fixed address; SNI and certificate check stay on the host name."""

    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self.ip = ip

    def connect(self):
        sock = socket.create_connection((self.ip, self.port), self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)


class Registry:
    """Anonymous pull access to one registry, following its Bearer challenge."""

    def __init__(self, base, ip=None):
        parts = urllib.parse.urlsplit(base)
        self.host, self.port, self.ip = parts.hostname, parts.port or 443, ip
        self.tokens = {}

    def request(self, method, path, repo, hops=0):
        for attempt in range(2):
            conn = (Pinned(self.host, self.ip, port=self.port, timeout=30) if self.ip
                    else http.client.HTTPSConnection(self.host, self.port, timeout=30))
            headers = {"Accept": ACCEPT, "User-Agent": "pkg-audit/1"}
            if repo in self.tokens:
                headers["Authorization"] = "Bearer " + self.tokens[repo]
            try:
                conn.request(method, path, headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                if resp.status == 401 and attempt == 0:
                    self.tokens[repo] = self.token(resp.getheader("WWW-Authenticate", ""), repo)
                    continue
                if resp.status in (301, 302, 303, 307, 308) and hops < 3:
                    # Docker follows these; Pulp answers manifests with a redirect to its content app
                    target = urllib.parse.urlsplit(urllib.parse.urljoin(
                        f"https://{self.host}{path}", resp.getheader("Location", "")))
                    if target.hostname == self.host:
                        return self.request(method, target.path + ("?" + target.query if target.query else ""),
                                            repo, hops + 1)
                    follow = urllib.request.Request(target.geturl(), method=method, headers={"Accept": ACCEPT})
                    with urllib.request.urlopen(follow, timeout=30) as final:
                        return final.status, final, final.read()
                return resp.status, resp, body
            finally:
                conn.close()

    @staticmethod
    def token(challenge, repo):
        if not challenge.lower().startswith("bearer "):
            raise RuntimeError("401 without a Bearer challenge")
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        query = urllib.parse.urlencode({"service": fields.get("service", ""),
                                        "scope": f"repository:{repo}:pull"})
        with urllib.request.urlopen(f"{fields['realm']}?{query}", timeout=30) as resp:
            data = json.load(resp)
        return data.get("token") or data["access_token"]

    def digest(self, repo, tag):
        status, resp, _ = self.request("HEAD", f"/v2/{repo}/manifests/{tag}", repo)
        value = resp.getheader("Docker-Content-Digest")
        if status != 200 or not value:
            raise RuntimeError(f"HTTP {status}")
        return value

    def manifest_hashes_to(self, repo, digest):
        status, _, body = self.request("GET", f"/v2/{repo}/manifests/{digest}", repo)
        if status != 200:
            raise RuntimeError(f"HTTP {status} fetching manifest by digest")
        return "sha256:" + hashlib.sha256(body).hexdigest() == digest


def split(ref):
    name, _, tag = ref.partition(":")
    return ("library/" + name if "/" not in name else name), tag


def read_list(path):
    return [line.split("#", 1)[0].split() for line in Path(path).read_text().splitlines()
            if line.split("#", 1)[0].strip()]


def audit_docker(refs, mirrors):
    hub = Registry(HUB)
    official = {}
    for ref in refs:
        repo, tag = split(ref)
        try:
            with time_limit(ITEM_LIMIT):
                official[ref] = hub.digest(repo, tag)
        except Exception as exc:
            sys.exit(f"{ref}: Docker Hub did not answer ({exc}); nothing to compare against")
    group = {"id": "docker", "title": "Docker", "items": refs, "mirrors": {},
             "note": "digest هر تگ در برابر Docker Hub"}
    for name, url, *ip in mirrors:
        reg, rows, down = Registry(url, ip[0] if ip else None), {}, 0
        for ref in refs:
            repo, tag = split(ref)
            row = {"verdict": "error", "value": None, "detail": ""}
            if out_of_time() or down >= GIVE_UP_AFTER:
                row["detail"] = skip_reason(down)
                rows[ref] = row
                continue
            try:
                with time_limit(ITEM_LIMIT):
                    row["value"] = reg.digest(repo, tag)
                    if not reg.manifest_hashes_to(repo, row["value"]):
                        row.update(verdict="mismatch", detail="manifest bytes do not hash to its digest")
                    elif row["value"] == official[ref]:
                        row["verdict"] = "ok"
                    else:
                        try:
                            known = hub.manifest_hashes_to(repo, row["value"])
                        except RuntimeError:
                            known = False
                        if known:
                            row.update(verdict="stale", detail="another digest Docker Hub serves for this repository")
                        else:
                            row.update(verdict="mismatch", detail="Docker Hub has no manifest with this digest")
                down = 0
            except Exception as exc:
                row["detail"] = str(exc)
                down = down + 1 if unreachable(exc) else 0
            rows[ref] = row
        group["mirrors"][name] = {"url": url, "ip": ip[0] if ip else None, "rows": rows}
    return group


# Package ecosystems: the same question as for Docker, asked of metadata that is immutable for a
# pinned version, so any difference from the official source is a mismatch (no `stale`).
OFFICIAL = {
    "npm": "https://registry.npmjs.org",
    "pypi": "https://pypi.org",
    "cargo": "https://index.crates.io",
    "maven": "https://repo1.maven.org/maven2",
    "nodejs": "https://nodejs.org/dist",
    "golang": "https://dl.google.com/go",
    "gradle": "https://services.gradle.org/distributions",
    "rubygems": "https://index.rubygems.org",
    "helm": "https://get.helm.sh",
    "k8s": "https://dl.k8s.io/release",
    "hashicorp": "https://releases.hashicorp.com",
}
TITLES = {
    "npm": ("npm", "هش integrity نسخه‌های ثابت بسته‌ها در برابر registry.npmjs.org"),
    "pypi": ("PyPI", "sha256 فایل‌های هر نسخه در برابر pypi.org"),
    "cargo": ("Cargo", "cksum هر crate در index رسمی crates.io"),
    "maven": ("Maven", "sha1 فایل jar در برابر Maven Central"),
    "nodejs": ("Node.js", "فایل SHASUMS256.txt هر نسخه در برابر nodejs.org"),
    "golang": ("Go", "فایل sha256 هر نسخه در برابر dl.google.com"),
    "gradle": ("Gradle", "فایل sha256 هر distribution در برابر services.gradle.org"),
    "rubygems": ("RubyGems", "checksum هر gem در compact index رسمی rubygems.org"),
    "helm": ("Helm", "فایل sha256 باینری Helm در برابر get.helm.sh"),
    "k8s": ("kubectl", "فایل sha256 باینری kubectl در برابر dl.k8s.io"),
    "hashicorp": ("HashiCorp", "فایل SHA256SUMS هر نسخه در برابر releases.hashicorp.com"),
}


def get(url, accept="*/*", tries=3):
    """GET with a few retries: a mirror or the official source resetting one connection is not a verdict."""
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "pkg-audit/1"})
    last = None
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                return resp.headers.get("Content-Type", ""), resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code < 500 and exc.code != 429:
                raise RuntimeError(f"HTTP {exc.code}")
            last = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError) as exc:
            last = str(getattr(exc, "reason", exc))[:60]
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(last or "no answer")


def pypi_files(base, name, version):
    norm = re.sub(r"[-_.]+", "-", name).lower()
    ctype, body = get(f"{base}/simple/{norm}/", "application/vnd.pypi.simple.v1+json, text/html;q=0.1")
    pairs = []
    if "json" in ctype:
        pairs = [(f["filename"], f["hashes"].get("sha256", "")) for f in json.loads(body)["files"]]
    else:  # PEP 503 HTML: <a href="...file#sha256=...">file</a>
        for href, text in re.findall(r'<a [^>]*href="([^"]+)"[^>]*>([^<]+)</a>', body.decode("utf-8", "replace")):
            pairs.append((text.strip(), href.partition("#sha256=")[2]))
    ours = sorted(f"{fn} {h}" for fn, h in pairs
                  if f"-{version}-" in fn or fn.endswith((f"-{version}.tar.gz", f"-{version}.zip")))
    if not ours:
        raise RuntimeError(f"no files for {version}")
    return "\n".join(ours)


def cargo_path(name):
    """Sparse-index path of a crate (https://doc.rust-lang.org/cargo/reference/registry-index.html)."""
    n = len(name)
    return f"{n}/{name}" if n < 3 else f"3/{name[0]}/{name}" if n == 3 else f"{name[:2]}/{name[2:4]}/{name}"


def fetch_value(kind, base, item):
    if kind == "npm":
        name, _, version = item.rpartition("@")
        _, body = get(f"{base}/{urllib.parse.quote(name, safe='@')}", "application/vnd.npm.install-v1+json")
        return json.loads(body)["versions"][version]["dist"]["integrity"]
    if kind == "pypi":
        name, _, version = item.partition("==")
        return pypi_files(base, name, version)
    if kind == "cargo":
        name, _, version = item.rpartition("@")
        _, body = get(f"{base}/{cargo_path(name)}")
        for line in body.decode().splitlines():
            entry = json.loads(line)
            if entry["vers"] == version:
                return entry["cksum"]
        raise RuntimeError(f"{version} not in the index")
    if kind == "maven":
        group, artifact, version = item.split(":")
        _, body = get(f"{base}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar.sha1")
        value = body.decode("utf-8", "replace").split()[0].lower() if body.strip() else ""
        if not re.fullmatch(r"[0-9a-f]{40}", value):  # an HTML page or error text is no answer
            raise RuntimeError("not a sha1 checksum")
        return value
    if kind == "rubygems":
        name, _, version = item.rpartition("@")
        _, body = get(f"{base}/info/{name}")
        for line in body.decode().splitlines():
            if line.startswith(version + " "):
                return re.search(r"checksum:([0-9a-f]{64})", line).group(1)
        raise RuntimeError(f"{version} not in the index")
    _, body = get(f"{base}/{item}")  # nodejs, golang, gradle, helm, k8s, hashicorp: a small checksum file
    return "sha256:" + hashlib.sha256(body).hexdigest()


def audit_packages(kind, items, targets):
    official = {}
    for item in items:
        try:
            with time_limit(ITEM_LIMIT):
                official[item] = fetch_value(kind, OFFICIAL[kind], item)
        except Exception as exc:
            print(f"{kind} {item}: official source did not answer ({exc}); skipped", file=sys.stderr)
    items = [i for i in items if i in official]
    if not items:
        return None
    title, note = TITLES[kind]
    group = {"id": kind, "title": title, "items": items, "mirrors": {}, "note": note}
    for name, base in targets:
        rows, down = {}, 0
        for item in items:
            row = {"verdict": "error", "value": None, "detail": ""}
            if out_of_time() or down >= GIVE_UP_AFTER:
                row["detail"] = skip_reason(down)
                rows[item] = row
                continue
            try:
                with time_limit(ITEM_LIMIT):
                    row["value"] = fetch_value(kind, base.rstrip("/"), item)
                if row["value"] == official[item]:
                    row["verdict"] = "ok"
                else:
                    row.update(verdict="mismatch", detail="differs from the official source")
                down = 0
            except Exception as exc:
                row["detail"] = str(exc)
                down = down + 1 if unreachable(exc) else 0
            rows[item] = row
        group["mirrors"][name] = {"url": base, "ip": None, "rows": rows}
    return group


FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
BADGE = {  # verdict -> (css class, icon, Persian label)
    "ok": ("ok", "✓", "سالم"),
    "stale": ("stale", "◷", "قدیمی"),
    "mismatch": ("bad", "✕", "ناهمخوان"),
    "error": ("err", "!", "بدون پاسخ"),
}
DEFAULT_BRAND = {
    "ours": "",                      # name (as in the targets files) of the operator's own mirror
    "ours_label": "",                # label shown on that mirror's column, e.g. "ما"
    "title": "پایش میرورها",
    "name": "",                      # name in the page header
    "tagline": "",                   # line under it
    "description": "مقایسه‌ی مستقل بسته‌ها و ایمیج‌های میرورها با منبع رسمی",
    "footer_html": "",               # trusted HTML for the page footer
}
BRAND = dict(DEFAULT_BRAND)

CSS = """
@font-face{font-family:Vazirmatn;src:url(/vazirmatn.woff2) format('woff2');font-weight:100 900;font-display:swap}
:root{--bg:#f4f1ea;--card:#fff;--fg:#0e2218;--muted:#5d6d63;--line:#e2ddd0;--primary:#157a4a;
--ok:#1f9d5c;--stale:#d19a1a;--bad:#d6334a;--err:#98a39c;
--okbg:#1f9d5c1c;--stalebg:#d19a1a24;--badbg:#d6334a1f;--errbg:#98a39c26;
--font:Vazirmatn,Tahoma,'Segoe UI',system-ui,sans-serif}
@media(prefers-color-scheme:dark){:root{--bg:#0b1411;--card:#111c18;--fg:#e4ede7;--muted:#8ea196;--line:#1d2d26;
--primary:#6fd69a;--ok:#4ccf86;--stale:#e6b640;--bad:#ff6f83;--err:#6f8178;
--okbg:#4ccf8622;--stalebg:#e6b64024;--badbg:#ff6f8326;--errbg:#6f817826}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%;scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.8 var(--font)}
a{color:var(--primary);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:980px;margin:0 auto;padding:0 18px}
header{padding:26px 0 0;display:flex;align-items:center;gap:12px}
header img{width:40px;height:40px;border-radius:11px;flex:none}
header .brand{font-weight:700;line-height:1.4}header .brand small{display:block;color:var(--muted);font-weight:400;font-size:12.5px}
h1{font-size:clamp(26px,5vw,40px);line-height:1.35;margin:22px 0 8px;font-weight:800;letter-spacing:-.01em}
h1 span{color:var(--primary)}
.lead{color:var(--muted);margin:0 0 20px;max-width:64ch}
.verdict{display:flex;align-items:center;gap:14px;border-radius:16px;padding:14px 18px;margin-bottom:18px;font-weight:600}
.verdict.good{background:var(--okbg);color:var(--ok)}.verdict.warn{background:var(--stalebg);color:var(--stale)}
.verdict.alert{background:var(--badbg);color:var(--bad)}
.verdict b{font-size:22px}.verdict small{display:block;font-weight:400;color:var(--muted);font-size:13px}
.nums{display:flex;flex-wrap:wrap;gap:8px 20px;margin-bottom:6px;color:var(--muted);font-size:13.5px}
.nums b{color:var(--fg);font-weight:700}
nav.tabs{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(8px);
display:flex;gap:6px;overflow-x:auto;padding:10px 0;margin:6px 0 4px;scrollbar-width:none}
nav.tabs::-webkit-scrollbar{display:none}
nav.tabs a{flex:none;border-radius:999px;padding:3px 14px;font-size:13.5px;color:var(--muted);border:1px solid var(--line);background:var(--card)}
nav.tabs a:hover{color:var(--fg);border-color:var(--primary);text-decoration:none}
h2.gt{font-size:21px;margin:30px 0 2px;scroll-margin-top:56px}
p.gn{color:var(--muted);font-size:13.5px;margin:0 0 12px}
.list{background:var(--card);border:1px solid var(--line);border-radius:18px;overflow:hidden}
details.m{border-bottom:1px solid var(--line)}details.m:last-child{border-bottom:0}
details.m summary{list-style:none;cursor:pointer;display:grid;grid-template-columns:minmax(0,1.25fr) auto minmax(0,1.6fr) 18px;
align-items:center;gap:6px 18px;padding:13px 18px}
details.m summary::-webkit-details-marker{display:none}
details.m summary:hover{background:var(--errbg)}
details.m summary:after{content:"‹";color:var(--muted);font-size:20px;line-height:1;transition:transform .15s}
details.m[open] summary:after{transform:rotate(-90deg)}
.who{min-width:0}.who .host{direction:ltr;text-align:right;display:block;font:13px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.tag{display:inline-block;font-size:11.5px;font-weight:700;color:var(--primary);border:1px solid var(--primary);border-radius:999px;padding:0 8px;margin-inline-start:8px;vertical-align:1px}
.score{font-weight:800;font-size:17px;min-width:3.2em;text-align:center}.score small{font-weight:400;color:var(--muted);font-size:11.5px;display:block;line-height:1.2}
.score.good{color:var(--ok)}.score.warn{color:var(--stale)}.score.alert{color:var(--bad)}.score.none{color:var(--err)}
.strip{display:flex;flex-wrap:wrap;gap:3px}
.sq{width:14px;height:14px;border-radius:4px;background:var(--ok);display:block}
.sq.stale{background:var(--stale)}.sq.bad{background:var(--bad)}.sq.err{background:var(--err)}
.items{margin:0;padding:2px 18px 12px;list-style:none;border-top:1px dashed var(--line)}
.items li{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)}
.items li:last-child{border-bottom:0}
.items code{direction:ltr;font:13px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.b{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:1px 10px;font-size:12px;font-weight:600;flex:none}
.b.ok{color:var(--ok);background:var(--okbg)}.b.stale{color:var(--stale);background:var(--stalebg)}
.b.bad{color:var(--bad);background:var(--badbg)}.b.err{color:var(--err);background:var(--errbg)}
.legend{display:flex;flex-wrap:wrap;gap:8px 22px;margin:22px 0 6px;color:var(--muted);font-size:13px}
.legend div{display:flex;align-items:center;gap:8px}
section.note{margin:26px 0;padding:6px 0}
section.note h2{font-size:17px;margin:18px 0 4px}section.note p,section.note li{color:var(--muted);margin:4px 0}
section.note ul{padding-inline-start:20px;margin:6px 0}
footer{border-top:1px solid var(--line);padding:22px 0 44px;color:var(--muted);font-size:13.5px}
footer .row{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:8px}
@media(max-width:680px){
details.m summary{grid-template-columns:minmax(0,1fr) auto 18px;padding:12px 14px}
.strip{grid-column:1/-1;order:5}
.items{padding:2px 14px 10px}
}
"""


def render_group(g, fa):
    refs, mirrors = g["items"], g["mirrors"]
    summary = []
    for n, m in mirrors.items():
        rows = m["rows"]
        done = sum(r["verdict"] == "ok" for r in rows.values())
        bad = sum(r["verdict"] == "mismatch" for r in rows.values())
        answered = sum(r["verdict"] != "error" for r in rows.values())
        ours = bool(BRAND["ours"]) and n == BRAND["ours"]
        summary.append((not ours, -bad, -done, n, m, done, bad, answered, ours))
    summary.sort(key=lambda t: t[:4])  # ours first, then problems, then best score
    out = ""
    for _, _, _, n, m, done, bad, answered, ours in summary:
        rows = m["rows"]
        pct = round(100 * done / len(refs)) if refs else 0
        tone = "none" if not answered else "alert" if bad else "good" if done == len(refs) else "warn"
        host = html.escape(m["url"].split("://", 1)[-1])
        tag = f'<span class="tag">{html.escape(BRAND["ours_label"])}</span>' if ours else ""
        strip = ""
        for ref in refs:
            cls = BADGE[rows[ref]["verdict"]][0]
            tip = html.escape(f'{ref}: {BADGE[rows[ref]["verdict"]][2]} {rows[ref]["detail"]}'.strip())
            strip += f'<i class="sq {"" if cls == "ok" else cls}" title="{tip}"></i>'
        items = ""
        for ref in sorted(refs, key=lambda r: rows[r]["verdict"] == "ok"):  # problems first
            cls, icon, label = BADGE[rows[ref]["verdict"]]
            tip = html.escape(((rows[ref]["value"] or "") + " " + rows[ref]["detail"]).strip())
            items += (f'<li><code>{html.escape(ref)}</code><span class="b {cls}" title="{tip}">'
                      f'<span aria-hidden="true">{icon}</span>{label}</span></li>')
        opened = " open" if bad else ""
        out += (f'<details class="m"{opened}><summary><div class="who"><span class="host">{host}</span>{tag}</div>'
                f'<div class="score {tone}">{fa(pct)}٪<small>{fa(done)} از {fa(len(refs))}</small></div>'
                f'<div class="strip">{strip}</div></summary><ul class="items">{items}</ul></details>')
    return (f'<h2 class="gt" id="{g["id"]}">{html.escape(g["title"])}</h2>'
            f'<p class="gn">{html.escape(g["note"])}</p><div class="list">{out}</div>')


def page(report):
    groups = report["groups"]
    counts = {"ok": 0, "stale": 0, "mismatch": 0, "error": 0}
    total = mirror_hosts = 0
    seen = set()
    for g in groups:
        for n, m in g["mirrors"].items():
            seen.add(m["url"].split("/")[2])
            for row in m["rows"].values():
                counts[row["verdict"]] += 1
                total += 1
    try:
        stamp = datetime.strptime(report["generated"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        tehran = stamp.astimezone(timezone(timedelta(hours=3, minutes=30)))
        when = tehran.strftime("%Y/%m/%d ساعت %H:%M").translate(FA_DIGITS) + " به وقت تهران"
    except ValueError:
        when = html.escape(report["generated"])
    fa = lambda n: str(n).translate(FA_DIGITS)
    legend = "".join(
        f'<div><span class="b {c}"><span aria-hidden="true">{i}</span>{l}</span>{t}</div>' for c, i, l, t in [
            ("ok", "✓", "سالم", "همان مقداری که منبع رسمی می‌دهد"),
            ("stale", "◷", "قدیمی", "فقط Docker: تگ جابه‌جا شده و میرور نسخه‌ی قبلی را دارد؛ حمله نیست"),
            ("bad", "✕", "ناهمخوان", "مقداری که منبع رسمی ندارد؛ باید بررسی شود"),
            ("err", "!", "بدون پاسخ", "میرور جواب قابل استفاده نداد")])
    if counts["mismatch"]:
        vclass, vtext, vsub = "alert", f"{fa(counts['mismatch'])} مورد ناهمخوان", "با منبع رسمی نمی‌خواند؛ جزئیات را ببینید"
    elif counts["stale"] or counts["error"]:
        vclass, vtext, vsub = "warn", "ناهمخوانی دیده نشد", "فقط بعضی میرورها نسخه‌ی قدیمی دارند یا جواب نداده‌اند"
    else:
        vclass, vtext, vsub = "good", "همه‌چیز با منبع رسمی می‌خواند", "هیچ ناهمخوانی دیده نشد"
    nav = "".join(f'<a href="#{g["id"]}">{html.escape(g["title"])}</a>' for g in groups)
    sections = "".join(render_group(g, fa) for g in groups)

    return f"""<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(BRAND["title"])}</title>
<meta name="description" content="{html.escape(BRAND["description"])}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><style>{CSS}</style></head>
<body><div class="wrap">
<header><img src="/favicon.svg" alt="" width="44" height="44">
<div class="brand">{html.escape(BRAND["name"])}<small>{html.escape(BRAND["tagline"])}</small></div></header>
<h1>پایش <span>میرورها</span></h1>
<p class="lead">بسته‌ها و ایمیج‌های پرکاربرد را از هر میرور می‌پرسیم و با پاسخ منبع رسمی مقایسه می‌کنیم،
از سروری مستقل از میرورها. آخرین بررسی: {when}. هر ساعت تکرار می‌شود.</p>
<div class="verdict {vclass}"><div><b>{vtext}</b><small>{vsub}</small></div></div>
<div class="nums"><span><b>{fa(len(seen))}</b> میزبان</span><span><b>{fa(len(groups))}</b> اکوسیستم</span>
<span><b>{fa(counts["ok"])}</b> از <b>{fa(total)}</b> پاسخ سالم</span><span><b>{fa(counts["stale"])}</b> قدیمی</span>
<span><b>{fa(counts["error"])}</b> بدون پاسخ</span></div>
<nav class="tabs">{nav}</nav>
{sections}
<div class="legend">{legend}</div>
<section class="note"><h2>این صفحه چه چیزی را نشان می‌دهد؟</h2>
<p>برای هر اکوسیستم، همان داده‌ای را از میرور و از منبع رسمی می‌گیریم که ابزار نصب به آن اعتماد می‌کند
(digest در Docker، هش در npm و PyPI، cksum در Cargo، sha1 در Maven، فایل checksum نصب‌کننده‌ها) و مقایسه می‌کنیم.
بسته‌ها روی نسخه‌ی ثابت سنجیده می‌شوند، پس هر تفاوتی باید توضیح داشته باشد.</p>
<h2>چه چیزی را نشان نمی‌دهد؟</h2>
<ul><li>سبز یعنی بازرس ما جواب درست گرفته؛ نه اینکه همه‌ی کاربران و در همه‌ی زمان‌ها همین را می‌گیرند.</li>
<li>حمله‌ای که فقط برای بعضی نشانی‌ها یا فقط هنگام قطعی اینترنت اجرا شود، با این بررسی دیده نمی‌شود.</li>
<li>فایل بسته دانلود نمی‌شود؛ مقدار هش و checksumی سنجیده می‌شود که ابزار نصب از میرور می‌گیرد.</li>
<li>نام ستون‌ها فقط نشانی میزبان است؛ اینکه کدام شرکت اداره‌اش می‌کند را خودش باید تأیید کند.
میرورهایی که بدون ثبت‌نام یا اعتبار پاسخ نمی‌دهند بررسی نشده‌اند.</li></ul>
<h2>برای پروژه‌های حساس</h2>
<p>هش را از منبع رسمی ثابت کنید: lockfile با هش (<bdi dir="ltr">package-lock.json</bdi>، <bdi dir="ltr">uv.lock</bdi>،
<bdi dir="ltr">pip --require-hashes</bdi>)، <bdi dir="ltr">distributionSha256Sum</bdi> در Gradle Wrapper، و در Docker
<bdi dir="ltr">alpine:3.20@sha256:…</bdi>. آن‌وقت هیچ میرور نمی‌تواند محتوای دیگری بدهد. خروجی کامل:
<a href="/report.json" dir="ltr">report.json</a>.</p></section>
<footer>{BRAND["footer_html"]}</footer>
</div></body></html>"""


def write_atomic(path, text):
    tmp = Path(path + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("images", help="file with one name:tag per line")
    ap.add_argument("mirrors", help="file with `name https://host [ip]` per line (Docker registries)")
    ap.add_argument("--packages", help="file with `kind item` per line (npm, pypi, cargo, maven, rubygems, nodejs, golang, gradle, helm, k8s, hashicorp)")
    ap.add_argument("--targets", help="file with `kind name base-url` per line: the mirrors to check for those kinds")
    ap.add_argument("--brand", help="JSON file overriding the page branding (keys of DEFAULT_BRAND)")
    ap.add_argument("--max-seconds", type=int, default=1200,
                    help="stop starting new checks after this long and report the rest as skipped (default %(default)s)")
    ap.add_argument("--json", help="write the report here")
    ap.add_argument("--html", help="write the static page here")
    args = ap.parse_args()
    global DEADLINE
    DEADLINE = time.monotonic() + args.max_seconds
    if args.brand:
        BRAND.update(json.loads(Path(args.brand).read_text()))
    refs = [line[0] for line in read_list(args.images)]
    report = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "groups": [audit_docker(refs, read_list(args.mirrors))]}
    if args.packages and args.targets:
        items, targets = {}, {}
        for kind, item in read_list(args.packages):
            items.setdefault(kind, []).append(item)
        for kind, name, base in read_list(args.targets):
            targets.setdefault(kind, []).append((name, base))
        for kind in OFFICIAL:
            if items.get(kind) and targets.get(kind):
                group = audit_packages(kind, items[kind], targets[kind])
                if group:
                    report["groups"].append(group)
    if args.json:
        write_atomic(args.json, json.dumps(report, indent=2) + "\n")
    if args.html:
        write_atomic(args.html, page(report))
    bad = 0
    for g in report["groups"]:
        for name, mirror in g["mirrors"].items():
            counts = {}
            for row in mirror["rows"].values():
                counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
            bad += counts.get("mismatch", 0)
            print(f"{g['id']:7} {name:28} " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
            for ref, row in mirror["rows"].items():
                if row["verdict"] in ("mismatch", "error"):
                    print(f"   {row['verdict'].upper()} {ref} {row['value']} {row['detail']}")
    sys.exit(2 if bad else 0)


if __name__ == "__main__":
    main()
