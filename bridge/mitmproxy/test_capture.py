"""Source-owned tests for the mitmproxy adapter's record projection."""

import importlib.util
import os
import sys
import types
import unittest
from unittest import mock


def load_capture():
    """Load the adapter with fresh mitmproxy stand-ins scoped to its import."""
    fake_mitmproxy = types.ModuleType("mitmproxy")
    fake_mitmproxy.ctx = types.SimpleNamespace()
    fake_mitmproxy.version = types.SimpleNamespace(VERSION="12.2.3")
    fake_io = types.ModuleType("mitmproxy.io")
    fake_io.tnetstring = types.ModuleType("mitmproxy.io.tnetstring")
    stand_ins = {
        "mitmproxy": fake_mitmproxy,
        "mitmproxy.io": fake_io,
        "mitmproxy.io.tnetstring": fake_io.tnetstring,
    }
    spec = importlib.util.spec_from_file_location(
        "rea_mitmproxy_capture", os.path.join(os.path.dirname(__file__), "capture.py")
    )
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, stand_ins):
        spec.loader.exec_module(module)
    return module


capture = load_capture()


def location(value):
    record = capture.project_record({"response": {"headers": [[b"Location", value]]}}, [])
    sidecar = next(
        field for field in record["binary_fields"] if field["pointer"] == "/response/headers/0/1"
    )
    return record["reported"]["response"]["headers"][0][1], sidecar, record["redactions"]


class TransportUserinfoTests(unittest.TestCase):
    def test_backslash_ends_a_special_scheme_authority(self):
        text, sidecar, redactions = location(b"https://example.test\\part@tail")
        self.assertEqual(text, "https://example.test\\part@tail")
        self.assertEqual(sidecar["state"], "retained")
        self.assertIsNotNone(sidecar["content_base64"])
        self.assertEqual(redactions, [])

    def test_userinfo_before_a_backslash_is_still_removed(self):
        text, sidecar, redactions = location(b"https://user:pw@example.test\\path")
        self.assertEqual(text, "https://example.test\\path")
        self.assertEqual(sidecar["state"], "redacted")
        self.assertEqual(
            redactions,
            [{"pointer": "/response/headers/0/1", "reason": "transport-credential"}],
        )

    def test_ordinary_userinfo_is_removed(self):
        text, _sidecar, _redactions = location(b"https://user:pw@example.test/a@b")
        self.assertEqual(text, "https://example.test/a@b")

    def test_special_schemes_skip_leading_slashes_before_userinfo(self):
        for value, expected in [
            (b"https://\\user:pass@host/path", b"https://\\host/path"),
            (b"https:\\\\user:pass@host/path", b"https:\\\\host/path"),
            (b"https:user:pass@host", b"https:host"),
            (b"//\\user:pass@host", b"//\\host"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(capture.without_userinfo(value), expected)
        text, sidecar, redactions = location(b"https://\\user:pass@host/path")
        self.assertEqual(text, "https://\\host/path")
        self.assertEqual(sidecar["state"], "redacted")
        self.assertEqual(len(redactions), 1)

    def test_file_urls_keep_path_text(self):
        self.assertEqual(capture.without_userinfo("file:///a@b"), "file:///a@b")

    def test_non_special_schemes_keep_backslashes_in_the_authority(self):
        self.assertEqual(capture.without_userinfo("foo://a\\b@host/x"), "foo://host/x")
        self.assertEqual(capture.without_userinfo(b"//a\\b@host"), b"//a\\b@host")


if __name__ == "__main__":
    unittest.main()
