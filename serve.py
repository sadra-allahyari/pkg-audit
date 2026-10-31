#!/usr/bin/env python3
"""Serve the report page and take re-check requests from visitors.

  python3 serve.py --site site --queue queue.json --cooldown 30 --port 8080

Static files come from --site (the folder pkg_audit.py writes index.html and report.json to).
One API call, POST /api/recheck with {"group": "npm", "mirror": "mirror.example.com"}, puts that
mirror in the queue file; the next pkg_audit.py run with --queue checks it and removes it.

What keeps this from being used to hammer a mirror:
  - only a (group, mirror) pair that exists in report.json can be queued, never an address;
  - a mirror checked less than --cooldown minutes ago (by anyone, scheduled or requested) is refused
    with the minutes left, so no mirror is checked more than once in that time because of visitors;
  - a pair already in the queue is not added twice, so the queue never exceeds the number of mirrors;
  - a small per-client rate limit keeps the endpoint itself cheap.
No access log, no cookies; the client address is used in memory only for that rate limit.
Standard library only.
"""
import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pkg_audit as pa  # noqa: E402

MAX_BODY = 1024
RATE_PER_MINUTE = 20


def parse_iso(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def decide(report, queue, group, mirror, now, cooldown_minutes):
    """(HTTP status, JSON body). Pure, so it is easy to test."""
    entry = None
    for g in report.get("groups", []):
        if g.get("id") == group:
            entry = g.get("mirrors", {}).get(mirror)
    if entry is None:
        return 404, {"status": "unknown"}
    if f"{group}/{mirror}" in queue:
        return 202, {"status": "queued"}
    checked = parse_iso(entry.get("checked_at"))
    if checked is not None:
        left = cooldown_minutes * 60 - (now - checked).total_seconds()
        if left > 0:
            return 429, {"status": "cooldown", "retry_after": int(left) + 1}
    return 202, {"status": "queued", "add": True}


class Limiter:
    def __init__(self, per_minute):
        self.per_minute, self.hits, self.lock = per_minute, {}, threading.Lock()

    def allow(self, who, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            recent = [t for t in self.hits.get(who, []) if now - t < 60]
            ok = len(recent) < self.per_minute
            if ok:
                recent.append(now)
            self.hits[who] = recent
            if len(self.hits) > 5000:  # forget clients that went quiet
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < 60}
            return ok


def make_handler(site, queue_path, cooldown, limiter):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(site), **kwargs)

        def log_message(self, *args):  # no access log
            pass

        def end_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            if not getattr(self, "_api", False):
                self.send_header("Cache-Control", "public, max-age=300")
            super().end_headers()

        def list_directory(self, path):  # never list a folder
            self.send_error(HTTPStatus.NOT_FOUND)
            return None

        def send_json(self, status, body):
            self._api = True
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/healthz":
                return self.send_json(200, {"ok": True})
            if self.path.split("?", 1)[0].startswith("/api/"):
                return self.send_error(HTTPStatus.NOT_FOUND)
            return super().do_GET()

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/api/recheck":
                return self.send_json(404, {"status": "unknown"})
            who = (self.headers.get("X-Forwarded-For") or self.client_address[0]).split(",")[0].strip()
            if not limiter.allow(who):
                return self.send_json(429, {"status": "slow-down", "retry_after": 60})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    raise ValueError
                body = json.loads(self.rfile.read(length))
                group, mirror = str(body["group"]), str(body["mirror"])
            except (ValueError, KeyError, TypeError):
                return self.send_json(400, {"status": "bad-request"})
            try:
                report = json.loads((site / "report.json").read_text())
            except (OSError, ValueError):
                return self.send_json(503, {"status": "no-report"})
            status, answer = decide(report, pa.queue_read(queue_path), group, mirror,
                                    datetime.now(timezone.utc), cooldown)
            if answer.pop("add", False):
                pa.queue_add(queue_path, f"{group}/{mirror}")
            self.send_json(status, answer)

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--site", required=True, help="folder with index.html and report.json")
    ap.add_argument("--queue", required=True, help="queue file shared with pkg_audit.py --queue")
    ap.add_argument("--cooldown", type=int, default=30, help="minutes before a mirror can be re-checked (default %(default)s)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    site = Path(args.site).resolve()
    handler = make_handler(site, args.queue, args.cooldown, Limiter(RATE_PER_MINUTE))
    ThreadingHTTPServer((args.host, args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
