"""Source-owned tests for the mitmproxy adapter's record projection."""

import importlib.util
import os
import sys
import types
import unittest


fake_mitmproxy = sys.modules.setdefault("mitmproxy", types.ModuleType("mitmproxy"))
fake_mitmproxy.ctx = types.SimpleNamespace()
fake_mitmproxy.version = types.SimpleNamespace(VERSION="12.2.3")
fake_io = sys.modules.setdefault("mitmproxy.io", types.ModuleType("mitmproxy.io"))
fake_io.tnetstring = sys.modules.setdefault(
    "mitmproxy.io.tnetstring", types.ModuleType("mitmproxy.io.tnetstring")
)
spec = importlib.util.spec_from_file_location(
    "rea_mitmproxy_capture", os.path.join(os.path.dirname(__file__), "capture.py")
)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


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

    def test_non_special_schemes_keep_backslashes_in_the_authority(self):
        self.assertEqual(capture.without_userinfo("foo://a\\b@host/x"), "foo://host/x")
        self.assertEqual(capture.without_userinfo(b"//a\\b@host"), b"//a\\b@host")


if __name__ == "__main__":
    unittest.main()
