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
import os
import re
import socket
import queue
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows: no locking (the re-check queue then needs one writer)
    fcntl = None

HUB = "https://registry-1.docker.io"
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


DEADLINE = None      # time.monotonic() value after which remaining checks are skipped (set by --max-seconds)
STUCK_AFTER = 120    # seconds a thread may go without finishing a request before it is abandoned
GRACE = 45           # seconds after the budget before stuck threads are abandoned
GIVE_UP_AFTER = 3    # consecutive items that timed out or could not connect: skip the rest of that mirror


PROGRESS = {}


def progress():
    """Called by a worker whenever it starts or finishes something: proof of life for run_jobs."""
    PROGRESS[threading.get_ident()] = time.monotonic()


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


def check_rows(items, rows, check):
    """Run `check(item, row)` for each item, one after another, so a host sees one request at a
    time. `rows` is filled as it goes: if the run is cut short, what was done is still there.
    An item that was not checked (out of time) gets no row: it shows as "in the queue" and the
    mirror counts as unfinished, so the next run checks it, instead of an error that would stand
    until the mirror's next turn."""
    down = 0
    for item in items:
        progress()
        if out_of_time():
            continue
        row = rows[item] = {"verdict": "error", "value": None, "detail": ""}
        if down >= GIVE_UP_AFTER:  # a host that answers nothing is a finding, and is reported
            row["detail"] = skip_reason(down)
            continue
        try:
            check(item, row)
            down = 0
        except Exception as exc:
            row["detail"] = str(exc)
            down = down + 1 if unreachable(exc) else 0
        progress()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def keep_or_new(prior, name, url, ip, active):
    """A mirror's entry: fresh when it is checked in this run, else the previous run's result
    (shown until its next turn comes), else empty."""
    if not active and prior and prior.get("url") == url:
        return {"url": url, "ip": ip, "rows": prior["rows"], "checked_at": prior.get("checked_at")}
    return {"url": url, "ip": ip, "rows": {}, "checked_at": now_iso() if active else None}


def docker_group(refs, mirrors, active, prior_group=None):
    """The group, the job that asks Docker Hub (None if no mirror of it is checked now) and a
    function returning the mirror jobs once Docker Hub's answers are in."""
    hub = Registry(HUB)
    official, failed = {}, []
    group = {"id": "docker", "title": "Docker", "items": list(refs), "mirrors": {},
             "note": "digest هر تگ در برابر Docker Hub"}
    prior = (prior_group or {}).get("mirrors", {})

    def ask_hub():
        for ref in refs:
            repo, tag = split(ref)
            try:
                official[ref] = hub.digest(repo, tag)
            except Exception as exc:
                failed.append(f"{ref}: Docker Hub did not answer ({exc})")
                return

    def one_mirror(reg, rows):
        def check(ref, row):
            repo, tag = split(ref)
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
        return lambda: check_rows(refs, rows, check)

    def after_official():
        if failed:
            sys.exit(failed[0] + "; nothing to compare against")
        return [(urllib.parse.urlsplit(url).hostname,
                 one_mirror(Registry(url, (ip or [None])[0]), group["mirrors"][name]["rows"]))
                for name, url, *ip in mirrors if name in active]

    for name, url, *ip in mirrors:
        group["mirrors"][name] = keep_or_new(prior.get(name), name, url, ip[0] if ip else None, name in active)
    return group, (("registry-1.docker.io", ask_hub) if active else None), after_official


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


def package_group(kind, items, targets, active, prior_group=None):
    """Like docker_group, for one package ecosystem."""
    official = {}
    title, note = TITLES[kind]
    group = {"id": kind, "title": title, "items": list(items), "mirrors": {}, "note": note}
    prior = (prior_group or {}).get("mirrors", {})

    def ask_official():
        for item in items:
            try:
                official[item] = fetch_value(kind, OFFICIAL[kind], item)
            except Exception as exc:
                print(f"{kind} {item}: official source did not answer ({exc}); skipped", file=sys.stderr)

    def one_mirror(base, rows):
        def check(item, row):
            row["value"] = fetch_value(kind, base.rstrip("/"), item)
            if row["value"] == official[item]:
                row["verdict"] = "ok"
            else:
                row.update(verdict="mismatch", detail="differs from the official source")
        return lambda: check_rows(group["items"], rows, check)

    def after_official():
        if active:  # items the official source could not answer are not compared
            group["items"] = [i for i in items if i in official]
        return [(urllib.parse.urlsplit(base).hostname, one_mirror(base, group["mirrors"][name]["rows"]))
                for name, base in targets if name in active and group["items"]]

    for name, base in targets:
        group["mirrors"][name] = keep_or_new(prior.get(name), name, base, None, name in active)
    return group, ((urllib.parse.urlsplit(OFFICIAL[kind]).hostname, ask_official) if active else None), after_official


def run_jobs(jobs, workers):
    """Run (host, fn) jobs on up to `workers` threads. Jobs of one host run one after another
    (one request at a time per host, however many ecosystems it serves); different hosts overlap.
    Returns when all are done or the run's time budget plus a grace period has passed: a thread
    stuck in a network call cannot be killed, so it is abandoned (daemon threads)."""
    by_host = {}
    for host, fn in jobs:
        by_host.setdefault(host, []).append(fn)
    todo = queue.Queue()
    for fns in by_host.values():
        todo.put(fns)

    def worker():
        while True:
            progress()
            try:
                fns = todo.get_nowait()
            except queue.Empty:
                return
            for fn in fns:
                try:
                    fn()
                except Exception as exc:  # a bug in one check must not stop the others
                    print(f"job failed: {exc!r}", file=sys.stderr)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, min(workers, len(by_host))))]
    for t in threads:
        t.start()
    while True:
        alive = [t for t in threads if t.is_alive()]
        if not alive:
            return
        now = time.monotonic()
        if DEADLINE is not None and now > DEADLINE + GRACE:
            return
        # every thread left has made no progress for a long time: they are stuck in a network
        # call that cannot be interrupted, so stop waiting for them (daemon threads)
        if all(now - PROGRESS.get(t.ident, now) > STUCK_AFTER for t in alive):
            print(f"giving up on {len(alive)} stuck thread(s)", file=sys.stderr)
            return
        time.sleep(0.2)


def settle(report, active):
    """A row still empty after the run is one whose check was cut off mid-request: drop it, so it
    reads "in the queue" and is checked again, rather than storing an error nobody measured."""
    for g in report["groups"]:
        for name, m in g["mirrors"].items():
            if (g["id"], name) not in active:
                continue
            for item in list(m["rows"]):
                row = m["rows"][item]
                if row["verdict"] == "error" and not row["detail"] and row["value"] is None:
                    del m["rows"][item]


@contextlib.contextmanager
def queue_lock(path):
    """Exclusive lock for the queue file, shared by the job and the server."""
    if fcntl is None:
        yield
        return
    with open(str(path) + ".lock", "a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def queue_read(path):
    """{ "<group id>/<mirror name>": requested-at ISO time } (empty if the file is missing or broken)."""
    try:
        data = json.loads(Path(path).read_text())
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def queue_write(path, queue):
    write_atomic(str(path), json.dumps(queue, indent=2, sort_keys=True) + "\n")


def queue_add(path, qid):
    with queue_lock(path):
        queue = queue_read(path)
        queue.setdefault(qid, now_iso())
        queue_write(path, queue)


def queue_remove(path, qids):
    with queue_lock(path):
        queue = queue_read(path)
        for qid in qids:
            queue.pop(qid, None)
        queue_write(path, queue)


def row_of(rows, item):
    return rows.get(item) or {"verdict": "pending", "value": None, "detail": "waiting for its first check"}


LEGACY_UNCHECKED = ("skipped: the run's time budget", "no answer before the run's time budget")


def load_state(path):
    """Previous report by group id; anything unreadable is simply no state. Rows that older versions
    saved for checks they never made (out of time) are dropped, so those mirrors are checked again."""
    try:
        data = json.loads(Path(path).read_text())
        groups = {g["id"]: g for g in data["groups"]}
        for g in groups.values():
            for m in g.get("mirrors", {}).values():
                rows = m.get("rows", {})
                for item in [i for i, r in rows.items() if str(r.get("detail", "")).startswith(LEGACY_UNCHECKED)]:
                    del rows[item]
        return groups
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def asked_pairs(queue, specs):
    """The (group id, mirror name) pairs of the queue that exist in the lists (a request for a
    mirror that was removed from them is dropped on the next run)."""
    known = {(gid, name) for gid, _, ms in specs for name, _ in ms}
    return {tuple(qid.split("/", 1)) for qid in queue if "/" in qid} & known


def pick_active(specs, prior, slots, slot):
    """specs: [(group id, items, [(mirror name, url)])]. Which (group id, name) pairs to check now.
    Hosts are spread evenly over `slots` turns; a mirror with no usable earlier result (new, URL
    changed, items added) is checked at once whatever its turn."""
    hosts = sorted({urllib.parse.urlsplit(url).hostname for _, _, ms in specs for _, url in ms})
    turn = {h: i % slots for i, h in enumerate(hosts)}
    active = set()
    for gid, items, ms in specs:
        for name, url in ms:
            old = prior.get(gid, {}).get("mirrors", {}).get(name)
            fresh = bool(old) and old.get("url") == url and all(i in old.get("rows", {}) for i in items)
            if slots <= 1 or not fresh or turn[urllib.parse.urlsplit(url).hostname] == slot:
                active.add((gid, name))
    return active


FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")
BADGE = {  # verdict -> (css class, icon, Persian label)
    "ok": ("ok", "✓", "سالم"),
    "stale": ("stale", "◷", "قدیمی"),
    "mismatch": ("bad", "✕", "ناهمخوان"),
    "error": ("err", "!", "بدون پاسخ"),
    "pending": ("err", "…", "در صف بررسی"),
}
DEFAULT_BRAND = {
    "ours": "",                      # name (as in the targets files) of the operator's own mirror
    "ours_label": "",                # label shown on that mirror's column, e.g. "ما"
    "title": "پایش میرورها",
    "name": "",                      # name in the page header
    "tagline": "",                   # line under it
    "description": "مقایسه‌ی مستقل بسته‌ها و ایمیج‌های میرورها با منبع رسمی",
    "footer_html": "",               # trusted HTML for the page footer
    "site_url": "",                  # public URL of the page, e.g. https://audit.example.com; enables link previews
    "source_url": "",                # public repository of this tool; shown in the header and the notes
    "og_image": "/og.jpg",
    "recheck_minutes": 0,            # >0: show "request a re-check" buttons; a mirror can be re-checked
                                     # this many minutes after its last check (needs serve.py)           # 1200x630 JPEG, path under site_url, for link previews (Telegram, Bale, ...)
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
header .src{margin-inline-start:auto;direction:ltr;font:600 12.5px ui-monospace,Menlo,Consolas,monospace;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:999px;padding:4px 12px;white-space:nowrap}
header .src:hover{border-color:var(--primary);color:var(--primary);text-decoration:none}
h1{font-size:clamp(26px,5vw,40px);line-height:1.35;margin:22px 0 8px;font-weight:800;letter-spacing:-.01em}
h1 span{color:var(--primary)}
.lead{color:var(--muted);margin:0 0 20px;max-width:64ch}
.verdict{display:flex;align-items:center;gap:14px;border-radius:16px;padding:14px 18px;margin-bottom:18px;font-weight:600}
.verdict.good{background:var(--okbg);color:var(--ok)}.verdict.warn{background:var(--stalebg);color:var(--stale)}
.verdict.alert{background:var(--badbg);color:var(--bad)}
.verdict b{font-size:22px}.vsub{font-weight:400;color:var(--muted);font-size:13.5px}
.vsub p{margin:6px 0 0}.vsub ul{margin:8px 0 0;padding:0;list-style:none}
.vsub li{margin:6px 0;display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 12px}
.vsub .eco{display:inline-flex;align-items:baseline;gap:8px;background:var(--card);border-radius:10px;padding:1px 10px}
.vsub .eco a{font-weight:700;color:var(--fg);text-decoration:none}.vsub .eco bdi{font:12.5px ui-monospace,Menlo,Consolas,monospace}.vsub .more{color:var(--muted)}
.vsub a{color:inherit;text-decoration:underline dotted}.vsub b{font-size:inherit;color:var(--fg)}.vsub em{color:var(--primary);font-style:normal}
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
.when{display:block;color:var(--muted);font-size:12px;margin-top:2px}.when.old{color:var(--stale)}
.items li.req{justify-content:flex-start;gap:12px;border-bottom:1px dashed var(--line);padding:9px 0}
.re{font:600 13px var(--font);color:var(--primary);background:transparent;border:1px solid var(--primary);border-radius:999px;padding:3px 14px;cursor:pointer}
.re:disabled{color:var(--muted);border-color:var(--line);cursor:default}.rs{color:var(--muted);font-size:12.5px}
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


STALE_AFTER = 3 * 3600   # a result older than this is shown as old


def checked_label(iso):
    """('آخرین بررسی ساعت HH:MM', is_old) in Tehran time, from a mirror's checked_at."""
    try:
        t = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "در صف بررسی", True
    local = t.astimezone(timezone(timedelta(hours=3, minutes=30)))
    old = (datetime.now(timezone.utc) - t).total_seconds() > STALE_AFTER
    return ("آخرین بررسی " + local.strftime("%H:%M").translate(FA_DIGITS)
            + (" · قدیمی" if old else "")), old


SCRIPT = r'''<script>
(function(){var CD=__MIN__*60000;
function fa(n){return String(n).replace(/\d/g,function(d){return '۰۱۲۳۴۵۶۷۸۹'[d]})}
function say(b,t,off){b.nextElementSibling.textContent=t;b.disabled=!!off}
function wait(b,left){say(b,'بررسی بعدی تا '+fa(Math.ceil(left/60000))+' دقیقه‌ی دیگر ممکن است',true)}
document.querySelectorAll('button.re').forEach(function(b){
  if(b.dataset.queued){say(b,'در صف بررسی',true);return}
  var t=Date.parse(b.dataset.checked||'');
  if(t&&CD-(Date.now()-t)>0)wait(b,CD-(Date.now()-t));
});
document.addEventListener('click',function(e){
  var b=e.target.closest&&e.target.closest('button.re');if(!b||b.disabled)return;
  say(b,'در حال ثبت…',true);
  fetch('/api/recheck',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({group:b.dataset.g,mirror:b.dataset.m})})
  .then(function(r){return r.json().then(function(j){return[r.status,j]})})
  .then(function(x){var s=x[0],j=x[1];
    if(j.status==='queued')say(b,'در صف بررسی؛ نتیجه تا چند دقیقه‌ی دیگر می‌آید',true);
    else if(j.status==='cooldown')wait(b,j.retry_after*1000);
    else say(b,'ثبت نشد؛ کمی بعد دوباره امتحان کنید',false)})
  .catch(function(){say(b,'ثبت نشد؛ کمی بعد دوباره امتحان کنید',false)});
});})();
</script>'''


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
        seen = checked_label(m.get("checked_at"))
        rows = m["rows"]
        pct = round(100 * done / len(refs)) if refs else 0
        tone = "none" if not answered else "alert" if bad else "good" if done == len(refs) else "warn"
        host = html.escape(m["url"].split("://", 1)[-1])
        tag = f'<span class="tag">{html.escape(BRAND["ours_label"])}</span>' if ours else ""
        strip = ""
        for ref in refs:
            cls = BADGE[row_of(rows, ref)["verdict"]][0]
            tip = html.escape(f'{ref}: {BADGE[row_of(rows, ref)["verdict"]][2]} {row_of(rows, ref)["detail"]}'.strip())
            strip += f'<i class="sq {"" if cls == "ok" else cls}" title="{tip}"></i>'
        items = ""
        if BRAND["recheck_minutes"] > 0:
            items += (f'<li class="req"><button type="button" class="re" data-g="{html.escape(g["id"])}" '
                      f'data-m="{html.escape(n)}" data-checked="{html.escape(m.get("checked_at") or "")}"'
                      f'{" data-queued=1" if m.get("queued") else ""}>درخواست بررسی مجدد</button>'
                      f'<span class="rs" aria-live="polite"></span></li>')
        for ref in sorted(refs, key=lambda r: row_of(rows, r)["verdict"] == "ok"):  # problems first
            cls, icon, label = BADGE[row_of(rows, ref)["verdict"]]
            tip = html.escape(((row_of(rows, ref)["value"] or "") + " " + row_of(rows, ref)["detail"]).strip())
            items += (f'<li><code>{html.escape(ref)}</code><span class="b {cls}" title="{tip}">'
                      f'<span aria-hidden="true">{icon}</span>{label}</span></li>')
        opened = " open" if bad else ""
        out += (f'<details class="m"{opened}><summary><div class="who"><span class="host">{host}</span>{tag}<span class="when{" old" if seen[1] else ""}">{seen[0]}{" · در صف بررسی" if m.get("queued") and m.get("checked_at") else ""}</span></div>'
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
    def who(verdict, limit=6):
        """`host (ecosystem): item, item` lines for every mirror with that verdict, worst first."""
        found = {}
        for g in groups:
            for n, m in g["mirrors"].items():
                items = [i for i, r in m["rows"].items() if r["verdict"] == verdict]
                if items:
                    found.setdefault(n, []).append((g, m, items))
        lines = []
        for n, entries in sorted(found.items(), key=lambda kv: -sum(len(e[2]) for e in kv[1])):
            host = html.escape(entries[0][1]["url"].split("://", 1)[-1].split("/")[0])
            ours = bool(BRAND["ours"]) and n == BRAND["ours"]
            tag = f' <em>{html.escape(BRAND["ours_label"])}</em>' if ours else ""
            parts = []
            for g, m, items in entries:
                shown = "  ·  ".join(html.escape(i) for i in items[:3])
                more = f' <span class="more">+{fa(len(items) - 3)}</span>' if len(items) > 3 else ""
                parts.append(f'<span class="eco"><a href="#{g["id"]}">{html.escape(g["title"])}</a>'
                             f'<bdi dir="ltr">{shown}</bdi>{more}</span>')
            lines.append(f'<li><b><bdi dir="ltr">{host}</bdi>{tag}</b>{"".join(parts)}</li>')
        extra = f"<li>و {fa(len(lines) - limit)} میرور دیگر</li>" if len(lines) > limit else ""
        return "<ul>" + "".join(lines[:limit]) + extra + "</ul>" if lines else ""

    if counts["mismatch"]:
        vclass, vtext = "alert", f"{fa(counts['mismatch'])} مورد ناهمخوان با منبع رسمی"
        vsub = who("mismatch")
    elif counts["stale"] or counts["error"]:
        vclass, vtext = "warn", "ناهمخوانی دیده نشد"
        stale, err = who("stale", 4), who("error", 4)
        vsub = ((f"<p>نسخه‌ی قدیمی (تگ جابه‌جا شده):</p>{stale}") if stale else "") + \
               ((f"<p>بدون پاسخ:</p>{err}") if err else "")
    else:
        vclass, vtext, vsub = "good", "همه‌چیز با منبع رسمی می‌خواند", "هیچ ناهمخوانی دیده نشد"
    nav = "".join(f'<a href="#{g["id"]}">{html.escape(g["title"])}</a>' for g in groups)
    sections = "".join(render_group(g, fa) for g in groups)

    src = BRAND["source_url"]
    src_label = html.escape(src.split("://", 1)[-1].rstrip("/"))
    src_link = f'<a class="src" href="{html.escape(src)}" rel="noopener">{src_label} ↗</a>' if src else ""
    src_note = (f'<p>کد این بازرس متن‌باز است و هر کسی می‌تواند بخواند، اجرا کند و میرور خودش را اضافه کند: '
                f'<a href="{html.escape(src)}" dir="ltr">{src_label}</a>.</p>') if src else ""
    script = SCRIPT.replace("__MIN__", str(int(BRAND["recheck_minutes"]))) if BRAND["recheck_minutes"] > 0 else ""
    social = ""
    if BRAND["site_url"]:
        base = BRAND["site_url"].rstrip("/")
        img = html.escape(base + BRAND["og_image"])
        t, d = html.escape(BRAND["title"]), html.escape(BRAND["description"])
        social = (f'<link rel="canonical" href="{html.escape(base)}/"><meta name="theme-color" content="#0f1916">'
                  f'<meta property="og:type" content="website"><meta property="og:locale" content="fa_IR">'
                  f'<meta property="og:url" content="{html.escape(base)}/"><meta property="og:title" content="{t}">'
                  f'<meta property="og:description" content="{d}"><meta property="og:image" content="{img}">'
                  f'<meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">'
                  f'<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="{t}">'
                  f'<meta name="twitter:description" content="{d}"><meta name="twitter:image" content="{img}">')
    return f"""<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(BRAND["title"])}</title>
<meta name="description" content="{html.escape(BRAND["description"])}">
{social}<link rel="icon" href="/favicon.svg" type="image/svg+xml"><style>{CSS}</style></head>
<body><div class="wrap">
<header><img src="/favicon.svg" alt="" width="44" height="44">
<div class="brand">{html.escape(BRAND["name"])}<small>{html.escape(BRAND["tagline"])}</small></div>{src_link}</header>
<h1>پایش <span>میرورها</span></h1>
<p class="lead">بسته‌ها و ایمیج‌های پرکاربرد را از هر میرور می‌پرسیم و با پاسخ منبع رسمی مقایسه می‌کنیم،
از سروری مستقل از میرورها. آخرین بررسی: {when}. هر ساعت تکرار می‌شود.</p>
<div class="verdict {vclass}"><div><b>{vtext}</b><div class="vsub">{vsub}</div></div></div>
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
<h2>کد منبع</h2>
{src_note}
<h2>برای پروژه‌های حساس</h2>
<p>هش را از منبع رسمی ثابت کنید: lockfile با هش (<bdi dir="ltr">package-lock.json</bdi>، <bdi dir="ltr">uv.lock</bdi>،
<bdi dir="ltr">pip --require-hashes</bdi>)، <bdi dir="ltr">distributionSha256Sum</bdi> در Gradle Wrapper، و در Docker
<bdi dir="ltr">alpine:3.20@sha256:…</bdi>. آن‌وقت هیچ میرور نمی‌تواند محتوای دیگری بدهد. خروجی کامل:
<a href="/report.json" dir="ltr">report.json</a>.</p></section>
<footer>{BRAND["footer_html"]}</footer>
</div>{script}</body></html>"""


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
    ap.add_argument("--workers", type=int, default=6,
                    help="hosts checked at the same time; each host still gets one request at a time (default %(default)s)")
    ap.add_argument("--state", help="previous report.json: mirrors not checked in this run keep their last result "
                                    "(and its time) until their turn comes")
    ap.add_argument("--slots", type=int, default=1,
                    help="spread the hosts over this many runs: a run checks 1/N of them (default 1 = all every run)")
    ap.add_argument("--slot-minutes", type=int, default=5,
                    help="how often the job runs; with --slots it picks this run's turn from the clock (default %(default)s)")
    ap.add_argument("--slot", type=int, help="force this turn (0..slots-1) instead of reading the clock")
    ap.add_argument("--queue", help="re-check requests (written by serve.py): the mirrors in it are checked in this "
                                    "run whatever their turn, then removed from it")
    ap.add_argument("--json", help="write the report here")
    ap.add_argument("--html", help="write the static page here")
    args = ap.parse_args()
    global DEADLINE
    DEADLINE = time.monotonic() + args.max_seconds
    if args.brand:
        BRAND.update(json.loads(Path(args.brand).read_text()))
    refs = [line[0] for line in read_list(args.images)]
    docker_mirrors = read_list(args.mirrors)
    items, targets = {}, {}
    if args.packages and args.targets:
        for kind, item in read_list(args.packages):
            items.setdefault(kind, []).append(item)
        for kind, name, base in read_list(args.targets):
            targets.setdefault(kind, []).append((name, base))
    kinds = [k for k in OFFICIAL if items.get(k) and targets.get(k)]

    prior = load_state(args.state) if args.state else {}
    slots = max(1, args.slots)
    slot = args.slot if args.slot is not None else int(time.time() // (args.slot_minutes * 60)) % slots
    specs = [("docker", refs, [(m[0], m[1]) for m in docker_mirrors])] + [(k, items[k], targets[k]) for k in kinds]
    active = pick_active(specs, prior, slots, slot)
    asked = set()
    if args.queue:  # visitors' re-check requests
        asked = asked_pairs(queue_read(args.queue), specs)
        active |= asked
    names = lambda gid: {n for g, n in active if g == gid}
    plans = [docker_group(refs, docker_mirrors, names("docker"), prior.get("docker"))]
    plans += [package_group(k, items[k], targets[k], names(k), prior.get(k)) for k in kinds]
    # Phase 1: ask every official source that is needed now (different sources at the same time).
    run_jobs([official for _, official, _ in plans if official], args.workers)
    # Phase 2: ask this run's mirrors; one request at a time per host, several hosts at once.
    mirror_jobs = [job for _, _, after in plans for job in after()]
    run_jobs(mirror_jobs, args.workers)
    report = {"generated": now_iso(), "groups": [g for g, _, _ in plans if g["items"]]}
    settle(report, active)
    if args.queue:
        queue_remove(args.queue, [f"{gid}/{name}" for gid, name in asked])
        waiting = queue_read(args.queue)
        for g in report["groups"]:
            for name, m in g["mirrors"].items():
                m["queued"] = f"{g['id']}/{name}" in waiting
    if args.json:
        write_atomic(args.json, json.dumps(report, indent=2) + "\n")
    if args.html:
        write_atomic(args.html, page(report))
    bad = 0
    print(f"turn {slot + 1}/{slots}: {len(active)} mirror entries checked, "
          f"{sum(len(g['mirrors']) for g in report['groups']) - len(active)} kept from the previous run")
    for g in report["groups"]:
        for name, mirror in g["mirrors"].items():
            if (g["id"], name) not in active:
                continue
            counts = {}
            for row in mirror["rows"].values():
                counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
            bad += counts.get("mismatch", 0)
            print(f"{g['id']:7} {name:28} " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
            for ref, row in mirror["rows"].items():
                if row["verdict"] in ("mismatch", "error"):
                    print(f"   {row['verdict'].upper()} {ref} {row['value']} {row['detail']}")
    sys.stdout.flush()
    os._exit(2 if bad else 0)  # abandoned threads must not keep the process alive


if __name__ == "__main__":
    main()
