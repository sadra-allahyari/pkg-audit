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
import hashlib
import html
import http.client
import json
import re
import socket
import ssl
import sys
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
            official[ref] = hub.digest(repo, tag)
        except Exception as exc:
            sys.exit(f"{ref}: Docker Hub did not answer ({exc}); nothing to compare against")
    group = {"id": "docker", "title": "Docker", "items": refs, "mirrors": {},
             "note": "digest هر تگ در برابر Docker Hub"}
    for name, url, *ip in mirrors:
        reg, rows = Registry(url, ip[0] if ip else None), {}
        for ref in refs:
            repo, tag = split(ref)
            row = {"verdict": "error", "value": None, "detail": ""}
            try:
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
            except Exception as exc:
                row["detail"] = str(exc)
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


def get(url, accept="*/*"):
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "pkg-audit/1"})
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            return resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}")


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
        return body.decode().split()[0].lower()
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
            official[item] = fetch_value(kind, OFFICIAL[kind], item)
        except Exception as exc:
            print(f"{kind} {item}: official source did not answer ({exc}); skipped", file=sys.stderr)
    items = [i for i in items if i in official]
    title, note = TITLES[kind]
    group = {"id": kind, "title": title, "items": items, "mirrors": {}, "note": note}
    for name, base in targets:
        rows = {}
        for item in items:
            row = {"verdict": "error", "value": None, "detail": ""}
            try:
                row["value"] = fetch_value(kind, base.rstrip("/"), item)
                if row["value"] == official[item]:
                    row["verdict"] = "ok"
                else:
                    row.update(verdict="mismatch", detail="differs from the official source")
            except Exception as exc:
                row["detail"] = str(exc)
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
:root{--bg:#f3efe6;--card:#faf7f0;--fg:#0e2218;--muted:#5a6a60;--line:#dcd6c8;--primary:#157a4a;
--ok:#157a4a;--okbg:#157a4a1f;--stale:#9a6700;--stalebg:#bf870026;--bad:#c4263c;--badbg:#c4263c24;
--err:#5a6a60;--errbg:#5a6a6020;--font:Vazirmatn,Tahoma,'Segoe UI',system-ui,sans-serif}
@media(prefers-color-scheme:dark){:root{--bg:#0e1714;--card:#131f1b;--fg:#e2ebe5;--muted:#93a69b;--line:#1f302a;
--primary:#6fd69a;--ok:#6fd69a;--okbg:#6fd69a22;--stale:#e3b341;--stalebg:#e3b34124;--bad:#ff7a8a;--badbg:#ff7a8a24;
--err:#93a69b;--errbg:#93a69b1c}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.8 var(--font)}
a{color:var(--primary);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1120px;margin:0 auto;padding:0 16px}
header{padding:28px 0 8px;display:flex;align-items:center;gap:14px}
header img{width:44px;height:44px;border-radius:12px;flex:none}
header .brand{font-weight:700;font-size:15px}header .brand small{display:block;color:var(--muted);font-weight:400;font-size:12.5px}
h2.gt{font-size:20px;margin:26px 0 10px;display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 12px}
h2.gt small{color:var(--muted);font-size:13px;font-weight:400}
.tabs{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 6px}
.tabs a{background:var(--card);border:1px solid var(--line);border-radius:999px;padding:3px 14px;font-size:13.5px;color:var(--fg)}
.tabs a:hover{border-color:var(--primary);text-decoration:none}
h1{font-size:clamp(24px,4vw,34px);line-height:1.4;margin:18px 0 6px;font-weight:800}
h1 span{color:var(--primary)}
.lead{color:var(--muted);margin:0 0 22px;max-width:72ch}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 16px}
.stat b{display:block;font-size:26px;line-height:1.3}.stat span{color:var(--muted);font-size:13px}
.stat.good b{color:var(--ok)}.stat.warn b{color:var(--stale)}.stat.alert b{color:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;overflow:hidden;margin-bottom:22px}
.scroll{overflow-x:auto}
table{border-collapse:separate;border-spacing:0;width:100%;min-width:880px}
th,td{padding:9px 6px;text-align:center;border-bottom:1px solid var(--line);white-space:nowrap}
thead th{white-space:normal;overflow-wrap:anywhere;min-width:96px;font-size:12.5px;font-weight:600;color:var(--muted);vertical-align:bottom;background:var(--card)}
thead th.ours{color:var(--primary)}
tbody th{padding-inline:12px;text-align:left;direction:ltr;position:sticky;right:0;background:var(--card);font-weight:500;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
tbody tr:last-child th,tbody tr:last-child td{border-bottom:0}
.host{direction:ltr;display:block;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;font-weight:500;line-height:1.5}
.name{display:block;font-size:13px;color:var(--fg)}
.meter{height:5px;border-radius:3px;background:var(--errbg);margin:7px auto 0;width:84px;overflow:hidden}
.meter i{display:block;height:100%;background:var(--ok)}
.pct{font-size:12px;color:var(--muted)}
.b{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600}
.b.ok{color:var(--ok);background:var(--okbg)}.b.stale{color:var(--stale);background:var(--stalebg)}
.b.bad{color:var(--bad);background:var(--badbg)}.b.err{color:var(--err);background:var(--errbg)}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px 18px;padding:14px 16px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
.legend div{display:flex;align-items:center;gap:8px}
section.note{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:6px 20px 14px;margin-bottom:22px}
section.note h2{font-size:17px;margin:14px 0 4px}section.note p,section.note li{color:var(--muted);margin:4px 0}
section.note ul{padding-inline-start:20px;margin:6px 0}
.cards{display:none}
.mc{background:var(--card);border:1px solid var(--line);border-radius:16px;margin-bottom:10px;overflow:hidden}
.mc.ours{border-color:var(--primary)}
.mc summary{list-style:none;cursor:pointer;padding:14px 16px;display:flex;align-items:center;gap:12px}
.mc summary::-webkit-details-marker{display:none}
.mc .who{flex:1;min-width:0}.mc .who .host{font-size:12.5px;overflow-wrap:anywhere}
.mc .who .name{font-weight:700;color:var(--primary)}
.mc .sum{display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex:none}
.mc .sum .meter{width:72px;margin:0}
.mc summary:after{content:"‹";color:var(--muted);font-size:20px;transition:transform .2s;flex:none}
.mc[open] summary:after{transform:rotate(-90deg)}
.mc ul{list-style:none;margin:0;padding:0 16px 10px;border-top:1px solid var(--line)}
.mc li{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)}
.mc li:last-child{border-bottom:0}
.mc li code{direction:ltr;font:13px ui-monospace,Menlo,Consolas,monospace;overflow-wrap:anywhere}
@media(max-width:720px){
.card{display:none}.cards{display:block;margin-bottom:22px}
.stats{grid-template-columns:repeat(2,1fr);gap:10px}.stats .stat:last-child{grid-column:1/-1}
.stat{padding:12px 14px}.stat b{font-size:22px}
header{padding-top:20px}.lead{font-size:14px}
section.note{padding:2px 16px 12px}
}
footer{border-top:1px solid var(--line);padding:22px 0 40px;color:var(--muted);font-size:13.5px}
footer .row{display:flex;flex-wrap:wrap;gap:6px 18px;margin-top:8px}
"""


def render_group(g, fa):
    names, refs, rows = list(g["mirrors"]), g["items"], g["mirrors"]
    head = body = ""
    for n in names:
        done = sum(r["verdict"] == "ok" for r in rows[n]["rows"].values())
        pct = round(100 * done / len(refs)) if refs else 0
        ours = bool(BRAND["ours"]) and n == BRAND["ours"]
        label = f'<span class="name">{html.escape(BRAND["ours_label"])}</span>' if ours else ""
        host = html.escape(rows[n]["url"].split("://", 1)[-1])
        head += (f'<th class="{"ours" if ours else ""}">{label}<span class="host">{host}</span>'
                 f'<div class="meter" title="{fa(done)} از {fa(len(refs))} سالم"><i style="width:{pct}%"></i></div>'
                 f'<span class="pct">{fa(pct)}٪ سالم</span></th>')
    for ref in refs:
        cells = ""
        for n in names:
            row = rows[n]["rows"][ref]
            cls, icon, label = BADGE[row["verdict"]]
            tip = html.escape(((row["value"] or "") + " " + row["detail"]).strip())
            cells += f'<td><span class="b {cls}" title="{tip}"><span aria-hidden="true">{icon}</span>{label}</span></td>'
        body += f"<tr><th scope=\"row\">{html.escape(ref)}</th>{cells}</tr>"
    mobile = '<div class="cards">'
    for n in names:
        mi = rows[n]["rows"]
        done = sum(r["verdict"] == "ok" for r in mi.values())
        pct = round(100 * done / len(refs)) if refs else 0
        ours = bool(BRAND["ours"]) and n == BRAND["ours"]
        host = html.escape(rows[n]["url"].split("://", 1)[-1])
        items = ""
        for ref in sorted(refs, key=lambda r: mi[r]["verdict"] == "ok"):  # problems first
            cls, icon, label = BADGE[mi[ref]["verdict"]]
            items += (f'<li><code>{html.escape(ref)}</code><span class="b {cls}">'
                      f'<span aria-hidden="true">{icon}</span>{label}</span></li>')
        opened = " open" if done != len(refs) else ""
        name = f'<span class="name">{html.escape(BRAND["ours_label"])}</span>' if ours else ""
        mobile += (f'<details class="mc{" ours" if ours else ""}"{opened}><summary><div class="who">{name}'
                   f'<span class="host">{host}</span></div><div class="sum"><span class="pct">{fa(done)} از {fa(len(refs))} سالم</span>'
                   f'<div class="meter"><i style="width:{pct}%"></i></div></div></summary><ul>{items}</ul></details>')
    mobile += "</div>"
    return (f'<h2 class="gt" id="{g["id"]}">{html.escape(g["title"])}<small>{html.escape(g["note"])}</small></h2>'
            f'<div class="card"><div class="scroll"><table><thead><tr><th></th>{head}</tr></thead>'
            f'<tbody>{body}</tbody></table></div></div>{mobile}')


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
<div class="stats">
<div class="stat"><b>{fa(len(seen))}</b><span>میزبان بررسی‌شده</span></div>
<div class="stat"><b>{fa(len(groups))}</b><span>اکوسیستم</span></div>
<div class="stat good"><b>{fa(counts["ok"])}<small style="font-size:14px;font-weight:400"> از {fa(total)}</small></b><span>پاسخ سالم</span></div>
<div class="stat warn"><b>{fa(counts["stale"])}</b><span>نسخه‌ی قدیمی</span></div>
<div class="stat alert"><b>{fa(counts["mismatch"])}</b><span>ناهمخوان</span></div>
</div>
<nav class="tabs">{nav}</nav>
{sections}
<div class="card"><div class="legend">{legend}</div></div>
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
    ap.add_argument("--json", help="write the report here")
    ap.add_argument("--html", help="write the static page here")
    args = ap.parse_args()
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
                report["groups"].append(audit_packages(kind, items[kind], targets[kind]))
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
