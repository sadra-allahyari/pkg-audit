#!/usr/bin/env python3
"""Offline tests: no network. Run: python3 tests/test_pkg_audit.py"""
import importlib.util
import json
import sys
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


class Verdicts(unittest.TestCase):
    def test_package_verdicts(self):
        values = {"https://official": "good", "https://ok": "good", "https://bad": "evil"}
        pa.OFFICIAL["npm"] = "https://official"

        def fake(kind, base, item):
            if base == "https://down":
                raise RuntimeError("HTTP 500")
            return values[base]
        real = pa.fetch_value
        pa.fetch_value = fake
        try:
            g = pa.audit_packages("npm", ["x@1.0.0"], [("ok", "https://ok"), ("bad", "https://bad"), ("down", "https://down")])
        finally:
            pa.fetch_value = real
        got = {n: m["rows"]["x@1.0.0"]["verdict"] for n, m in g["mirrors"].items()}
        self.assertEqual(got, {"ok": "ok", "bad": "mismatch", "down": "error"})


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


if __name__ == "__main__":
    unittest.main()
