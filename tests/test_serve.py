#!/usr/bin/env python3
"""Offline tests for serve.py and the queue helpers. Run: python3 tests/test_serve.py"""
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pkg_audit as pa  # noqa: E402
import serve  # noqa: E402

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def iso(minutes_ago):
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def report(checked_at):
    return {"groups": [{"id": "npm", "mirrors": {"m.example": {"checked_at": checked_at}}}]}


class Decide(unittest.TestCase):
    def test_unknown_group_or_mirror_is_refused(self):
        self.assertEqual(serve.decide(report(iso(99)), {}, "npm", "other", NOW, 30)[0], 404)
        self.assertEqual(serve.decide(report(iso(99)), {}, "pypi", "m.example", NOW, 30)[0], 404)

    def test_recently_checked_mirror_waits_out_the_cooldown(self):
        status, body = serve.decide(report(iso(10)), {}, "npm", "m.example", NOW, 30)
        self.assertEqual((status, body["status"]), (429, "cooldown"))
        self.assertAlmostEqual(body["retry_after"], 20 * 60, delta=2)

    def test_old_enough_mirror_is_queued(self):
        status, body = serve.decide(report(iso(31)), {}, "npm", "m.example", NOW, 30)
        self.assertEqual((status, body.get("add")), (202, True))

    def test_never_checked_mirror_can_be_queued(self):
        self.assertEqual(serve.decide(report(None), {}, "npm", "m.example", NOW, 30)[0], 202)

    def test_already_queued_is_not_added_again(self):
        status, body = serve.decide(report(iso(99)), {"npm/m.example": "x"}, "npm", "m.example", NOW, 30)
        self.assertEqual((status, body), (202, {"status": "queued"}))


class Limit(unittest.TestCase):
    def test_per_client_rate_limit(self):
        lim = serve.Limiter(3)
        self.assertEqual([lim.allow("a", now=t) for t in (0, 1, 2, 3)], [True, True, True, False])
        self.assertTrue(lim.allow("b", now=3))     # another client is unaffected
        self.assertTrue(lim.allow("a", now=61))    # the window moves on


class Queue(unittest.TestCase):
    def test_add_remove_and_unreadable_file(self):
        with tempfile.TemporaryDirectory() as d:
            q = Path(d) / "queue.json"
            self.assertEqual(pa.queue_read(q), {})
            pa.queue_add(q, "npm/a")
            pa.queue_add(q, "npm/a")  # twice: still one entry, first time kept
            pa.queue_add(q, "pypi/b")
            self.assertEqual(sorted(pa.queue_read(q)), ["npm/a", "pypi/b"])
            pa.queue_remove(q, ["npm/a", "never-there"])
            self.assertEqual(sorted(pa.queue_read(q)), ["pypi/b"])
            q.write_text("not json")
            self.assertEqual(pa.queue_read(q), {})


class Page(unittest.TestCase):
    def group(self, queued=False, checked="2026-01-01T10:00:00Z"):
        return {"id": "npm", "title": "npm", "note": "n", "items": ["x@1"], "mirrors": {
            "m.example": {"url": "https://m.example", "ip": None, "checked_at": checked, "queued": queued,
                          "rows": {"x@1": {"verdict": "ok", "value": "v", "detail": ""}}}}}

    def test_button_only_when_rechecks_are_enabled(self):
        r = {"generated": "2026-01-01T10:05:00Z", "groups": [self.group()]}
        pa.BRAND["recheck_minutes"] = 0
        self.assertNotIn("button", pa.page(r))
        pa.BRAND["recheck_minutes"] = 30
        try:
            out = pa.page(r)
        finally:
            pa.BRAND["recheck_minutes"] = 0
        self.assertIn('class="re" data-g="npm" data-m="m.example"', out)
        self.assertIn("/api/recheck", out)
        self.assertIn("var CD=30*60000", out)

    def test_queued_and_never_checked_say_in_the_queue(self):
        pa.BRAND["recheck_minutes"] = 30
        try:
            queued = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [self.group(queued=True)]})
            never = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [self.group(checked=None)]})
        finally:
            pa.BRAND["recheck_minutes"] = 0
        self.assertIn("data-queued=1", queued)
        self.assertIn("در صف بررسی", queued)
        self.assertIn("در صف بررسی", never)
        self.assertNotIn("هنوز بررسی نشده", never)

    def test_asked_pairs_ignores_mirrors_not_in_the_lists(self):
        specs = [("npm", ["x@1"], [("m.example", "https://m.example")])]
        self.assertEqual(pa.asked_pairs({"npm/m.example": "t", "npm/gone": "t", "junk": "t"}, specs),
                         {("npm", "m.example")})


class Server(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = Path(self.tmp.name) / "site"
        self.site.mkdir()
        (self.site / "index.html").write_text("<h1>hi</h1>")
        (self.site / "report.json").write_text(json.dumps(report(iso(99))))
        (Path(self.tmp.name) / "secret.txt").write_text("secret")
        self.queue = Path(self.tmp.name) / "queue.json"
        handler = serve.make_handler(self.site, self.queue, 30, serve.Limiter(100))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.tmp.cleanup()

    def call(self, path, data=None, raw=None):
        body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)
        req = urllib.request.Request(self.base + path, data=body, method="POST" if body is not None else "GET",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read(), dict(e.headers)

    def test_static_files_and_headers(self):
        status, body, headers = self.call("/")
        self.assertEqual((status, body), (200, b"<h1>hi</h1>"))
        self.assertIn("max-age", headers["Cache-Control"])
        self.assertEqual(self.call("/../secret.txt")[0], 404)
        self.assertEqual(self.call("/%2e%2e/secret.txt")[0], 404)

    def test_recheck_queues_once_then_cooldown_follows_the_check(self):
        status, body, headers = self.call("/api/recheck", {"group": "npm", "mirror": "m.example"})
        self.assertEqual((status, json.loads(body)), (202, {"status": "queued"}))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(list(pa.queue_read(self.queue)), ["npm/m.example"])
        self.call("/api/recheck", {"group": "npm", "mirror": "m.example"})   # again: no second entry
        self.assertEqual(len(pa.queue_read(self.queue)), 1)
        # the job ran: entry removed and the mirror was just checked
        pa.queue_remove(self.queue, ["npm/m.example"])
        (self.site / "report.json").write_text(json.dumps(report(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))))
        status, body, _ = self.call("/api/recheck", {"group": "npm", "mirror": "m.example"})
        self.assertEqual((status, json.loads(body)["status"]), (429, "cooldown"))
        self.assertEqual(pa.queue_read(self.queue), {})

    def test_bad_requests(self):
        self.assertEqual(self.call("/api/recheck", raw=b"not json")[0], 400)
        self.assertEqual(self.call("/api/recheck", {"group": "npm"})[0], 400)
        self.assertEqual(self.call("/api/recheck", raw=b"x" * 5000)[0], 400)
        self.assertEqual(self.call("/api/recheck", {"group": "npm", "mirror": "evil.example"})[0], 404)
        self.assertEqual(self.call("/api/other", {"a": 1})[0], 404)
        self.assertEqual(self.call("/api/recheck")[0], 404)  # GET is not the API
        self.assertEqual(pa.queue_read(self.queue), {})


if __name__ == "__main__":
    unittest.main()
