#!/usr/bin/env python3
"""Offline tests: no network. Run: python3 tests/test_pkg_audit.py"""
import importlib.util
import json
import sys
import threading
import time
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("pkg_audit", Path(__file__).resolve().parent.parent / "pkg_audit.py")
pa = importlib.util.module_from_spec(spec)
sys.modules["pkg_audit"] = pa
spec.loader.exec_module(pa)


class Paths(unittest.TestCase):
    def test_cargo_path(self):
        self.assertEqual(pa.cargo_path("a"), "1/a")
        self.assertEqual(pa.cargo_path("ab"), "2/ab")
        self.assertEqual(pa.cargo_path("abc"), "3/a/abc")
        self.assertEqual(pa.cargo_path("serde"), "se/rd/serde")

    def test_split(self):
        self.assertEqual(pa.split("alpine:3.20"), ("library/alpine", "3.20"))
        self.assertEqual(pa.split("curlimages/curl:8"), ("curlimages/curl", "8"))


class Values(unittest.TestCase):
    def setUp(self):
        self.real_get = pa.get

    def tearDown(self):
        pa.get = self.real_get

    def test_npm_integrity(self):
        doc = {"versions": {"1.0.0": {"dist": {"integrity": "sha512-abc"}}}}
        pa.get = lambda url, accept="*/*": ("application/json", json.dumps(doc).encode())
        self.assertEqual(pa.fetch_value("npm", "https://m", "left-pad@1.0.0"), "sha512-abc")

    def test_pypi_html_and_json_agree(self):
        html = b'<a href="x/requests-2.0.0.tar.gz#sha256=aa">requests-2.0.0.tar.gz</a><a href="x/requests-2.1.0.tar.gz#sha256=bb">requests-2.1.0.tar.gz</a>'
        js = json.dumps({"files": [{"filename": "requests-2.0.0.tar.gz", "hashes": {"sha256": "aa"}},
                                     {"filename": "requests-2.1.0.tar.gz", "hashes": {"sha256": "bb"}}]}).encode()
        pa.get = lambda url, accept="*/*": ("text/html", html)
        from_html = pa.fetch_value("pypi", "https://m", "requests==2.0.0")
        pa.get = lambda url, accept="*/*": ("application/vnd.pypi.simple.v1+json", js)
        self.assertEqual(from_html, pa.fetch_value("pypi", "https://m", "requests==2.0.0"))
        self.assertEqual(from_html, "requests-2.0.0.tar.gz aa")

    def test_cargo_and_rubygems(self):
        pa.get = lambda url, accept="*/*": ("", b'{"vers":"1.0.0","cksum":"c1"}\n{"vers":"1.0.1","cksum":"c2"}\n')
        self.assertEqual(pa.fetch_value("cargo", "https://m", "serde@1.0.1"), "c2")
        pa.get = lambda url, accept="*/*": ("", b"---\n13.2.1 |checksum:" + b"a" * 64 + b",ruby:>= 2\n")
        self.assertEqual(pa.fetch_value("rubygems", "https://m", "rake@13.2.1"), "a" * 64)

    def test_maven_rejects_html(self):
        pa.get = lambda url, accept="*/*": ("text/html", b"<!doctype html><html>")
        with self.assertRaises(RuntimeError):
            pa.fetch_value("maven", "https://m", "junit:junit:4.13.2")
        pa.get = lambda url, accept="*/*": ("text/plain", b"8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12\n")
        self.assertEqual(pa.fetch_value("maven", "https://m", "junit:junit:4.13.2"), "8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12")

    def test_missing_version_is_an_error(self):
        pa.get = lambda url, accept="*/*": ("", b'{"vers":"1.0.0","cksum":"c1"}\n')
        with self.assertRaises(RuntimeError):
            pa.fetch_value("cargo", "https://m", "serde@9.9.9")


def run_group(kind, items, targets, workers=1, active=None, prior=None):
    """Drive package_group the way main() does."""
    active = {n for n, _ in targets} if active is None else active
    group, official, after = pa.package_group(kind, items, targets, active, prior)
    pa.run_jobs([official] if official else [], workers)
    pa.run_jobs(after(), workers)
    return group


class Verdicts(unittest.TestCase):
    def setUp(self):
        self.real = pa.fetch_value
        pa.OFFICIAL["npm"] = "https://official"

    def tearDown(self):
        pa.fetch_value, pa.DEADLINE = self.real, None

    def test_package_verdicts(self):
        values = {"https://official": "good", "https://ok": "good", "https://bad": "evil"}

        def fake(kind, base, item):
            if base == "https://down":
                raise RuntimeError("HTTP 500")
            return values[base]
        pa.fetch_value = fake
        g = run_group("npm", ["x@1.0.0"], [("ok", "https://ok"), ("bad", "https://bad"), ("down", "https://down")])
        got = {n: m["rows"]["x@1.0.0"]["verdict"] for n, m in g["mirrors"].items()}
        self.assertEqual(got, {"ok": "ok", "bad": "mismatch", "down": "error"})

    def test_a_mirror_that_never_answers_is_given_up_on(self):
        calls = []

        def fake(kind, base, item):
            if base == "https://official":
                return "good"
            calls.append(item)
            raise TimeoutError("no answer")
        pa.fetch_value = fake
        g = run_group("npm", [f"p{i}@1.0.0" for i in range(8)], [("dead", "https://dead")])
        self.assertEqual(len(calls), pa.GIVE_UP_AFTER)
        rows = g["mirrors"]["dead"]["rows"]
        self.assertEqual({r["verdict"] for r in rows.values()}, {"error"})
        self.assertIn("skipped", rows["p7@1.0.0"]["detail"])

    def test_run_budget_skips_the_rest(self):
        pa.DEADLINE = time.monotonic() - 1  # already used up
        pa.fetch_value = lambda kind, base, item: "good"
        g = run_group("npm", ["a@1.0.0"], [("m", "https://m")])
        self.assertIn("time budget", g["mirrors"]["m"]["rows"]["a@1.0.0"]["detail"])


class Turns(unittest.TestCase):
    def specs(self):
        return [("npm", ["a@1"], [("m%d" % i, f"https://h{i}.example") for i in range(6)])]

    def prior(self, specs):
        return {gid: {"mirrors": {n: {"url": u, "rows": {i: {"verdict": "ok"} for i in items}}
                                  for n, u in ms}} for gid, items, ms in specs}

    def test_each_host_is_checked_once_over_the_slots(self):
        specs, seen = self.specs(), []
        prior = self.prior(specs)
        for slot in range(3):
            seen += sorted(n for _, n in pa.pick_active(specs, prior, 3, slot))
        self.assertEqual(sorted(seen), ["m0", "m1", "m2", "m3", "m4", "m5"])  # all, none twice
        self.assertEqual(len(pa.pick_active(specs, prior, 3, 0)), 2)          # a third per run

    def test_everything_runs_when_there_is_one_slot_or_no_state(self):
        specs = self.specs()
        self.assertEqual(len(pa.pick_active(specs, self.prior(specs), 1, 0)), 6)
        self.assertEqual(len(pa.pick_active(specs, {}, 12, 5)), 6)  # no state: all, whatever the turn

    def test_a_mirror_with_a_new_item_or_url_is_checked_at_once(self):
        specs = self.specs()
        prior = self.prior(specs)
        specs[0] = ("npm", ["a@1", "b@1"], specs[0][2])  # an item the state has no row for
        self.assertEqual(len(pa.pick_active(specs, prior, 12, 11)), 6)

    def test_mirrors_not_checked_now_keep_their_last_result_and_time(self):
        pa.OFFICIAL["npm"] = "https://official"
        real = pa.fetch_value
        pa.fetch_value = lambda kind, base, item: "good"
        try:
            old = {"mirrors": {"idle": {"url": "https://idle", "ip": None, "checked_at": "2026-01-01T10:00:00Z",
                                       "rows": {"x@1": {"verdict": "mismatch", "value": "evil", "detail": "kept"}}}}}
            g = run_group("npm", ["x@1"], [("idle", "https://idle"), ("now", "https://now")], active={"now"}, prior=old)
        finally:
            pa.fetch_value = real
        self.assertEqual(g["mirrors"]["idle"]["rows"]["x@1"]["detail"], "kept")
        self.assertEqual(g["mirrors"]["idle"]["checked_at"], "2026-01-01T10:00:00Z")
        self.assertEqual(g["mirrors"]["now"]["rows"]["x@1"]["verdict"], "ok")
        self.assertNotEqual(g["mirrors"]["now"]["checked_at"], "2026-01-01T10:00:00Z")

    def test_no_official_request_when_no_mirror_of_a_group_is_due(self):
        group, official, after = pa.package_group("npm", ["a@1"], [("m", "https://m")], set(), None)
        self.assertIsNone(official)
        self.assertEqual(after(), [])


class Pool(unittest.TestCase):
    def test_one_request_at_a_time_per_host_but_hosts_overlap(self):
        lock, state = threading.Lock(), {"now": {}, "max_same": 0, "max_all": 0}

        def job(host):
            def run():
                with lock:
                    state["now"][host] = state["now"].get(host, 0) + 1
                    state["max_same"] = max(state["max_same"], state["now"][host])
                    state["max_all"] = max(state["max_all"], sum(state["now"].values()))
                time.sleep(0.05)
                with lock:
                    state["now"][host] -= 1
            return run
        jobs = [("a", job("a")) for _ in range(4)] + [("b", job("b")) for _ in range(4)]
        pa.run_jobs(jobs, 4)
        self.assertEqual(state["max_same"], 1)   # never two requests at once to one host
        self.assertEqual(state["max_all"], 2)    # but the two hosts did run together

    def test_workers_bound_the_overlap(self):
        lock, state = threading.Lock(), {"now": 0, "max": 0}

        def run():
            with lock:
                state["now"] += 1
                state["max"] = max(state["max"], state["now"])
            time.sleep(0.05)
            with lock:
                state["now"] -= 1
        pa.run_jobs([(f"h{i}", run) for i in range(8)], 3)
        self.assertEqual(state["max"], 3)

    def test_a_stuck_job_is_abandoned_and_its_rows_settle_as_errors(self):
        pa.DEADLINE, real_grace = time.monotonic() + 0.2, pa.GRACE
        pa.GRACE = 0.2
        try:
            started = time.monotonic()
            pa.run_jobs([("slow", lambda: time.sleep(30))], 2)
            self.assertLess(time.monotonic() - started, 5)
        finally:
            pa.DEADLINE, pa.GRACE = None, real_grace
        report = {"groups": [{"id": "g", "items": ["x"], "mirrors": {"m": {"rows": {}}}}]}
        pa.settle(report, {("g", "m")})
        self.assertEqual(report["groups"][0]["mirrors"]["m"]["rows"]["x"]["verdict"], "error")
        self.assertIn("time budget", report["groups"][0]["mirrors"]["m"]["rows"]["x"]["detail"])


class PageState(unittest.TestCase):
    def test_page_shows_last_check_time_and_tolerates_missing_rows(self):
        group = {"id": "npm", "title": "npm", "note": "n", "items": ["x@1", "y@1"], "mirrors": {
            "m": {"url": "https://m.example", "ip": None, "checked_at": "2026-01-01T10:00:00Z",
                  "rows": {"x@1": {"verdict": "ok", "value": "v", "detail": ""}}}}}  # y@1 never checked
        out = pa.page({"generated": "2026-01-01T10:05:00Z", "groups": [group]})
        self.assertIn("آخرین بررسی", out)
        self.assertIn("قدیمی", out)  # 2026-01-01 is long ago


class Page(unittest.TestCase):
    def test_page_renders_and_escapes(self):
        pa.BRAND.update(ours="m", ours_label="<b>us</b>", title="T", name="N", tagline="t", footer_html="<i>f</i>")
        group = {"id": "npm", "title": "npm", "note": "n", "items": ["x@1"], "mirrors": {
            "m": {"url": "https://m.example", "ip": None,
                  "rows": {"x@1": {"verdict": "mismatch", "value": "<script>", "detail": ""}}}}}
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;b&gt;us&lt;/b&gt;", out)
        self.assertIn("ناهمخوان", out)
        # the headline names the mirror, the ecosystem and the item
        head = out[out.index('class="verdict'):out.index('class="nums"')]
        self.assertIn("m.example", head)
        self.assertIn('href="#npm"', head)
        self.assertIn("x@1", head)
        self.assertIn("&lt;b&gt;us&lt;/b&gt;", head)  # marked as ours
        self.assertNotIn("og:image", out)  # no site_url, no preview tags
        pa.BRAND["site_url"] = "https://audit.example.com/"
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertIn('property="og:image" content="https://audit.example.com/og.jpg"', out)
        self.assertIn('name="twitter:card" content="summary_large_image"', out)
        pa.BRAND["site_url"] = ""
        self.assertNotIn('class="src"', out)
        pa.BRAND["source_url"] = "https://github.com/example/pkg-audit"
        out = pa.page({"generated": "2026-01-01T00:00:00Z", "groups": [group]})
        self.assertIn('class="src" href="https://github.com/example/pkg-audit"', out)
        self.assertGreaterEqual(out.count("github.com/example/pkg-audit"), 3)
        pa.BRAND["source_url"] = ""


if __name__ == "__main__":
    unittest.main()
