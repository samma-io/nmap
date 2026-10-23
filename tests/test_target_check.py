"""Tests for target_check.py and the argv built by the three nmap scripts.

Run from the repository root:

    python3 -m unittest discover -s tests -t .

The scanner scripts import xmltodict; when it is not installed their argv
tests are skipped and only the validator is tested.
"""

import importlib
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(HERE)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

import target_check as tc  # noqa: E402


def _try_import(name):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


portscanner = _try_import("nmap_portscanner")
httprecon = _try_import("nmap_httprecon")
tlscipher = _try_import("nmap_tlscipher")

ACCEPTED = [
    "example.com",
    "scanme.nmap.org",
    "localhost",
    "my-host-1.example.org",
    "1.2.3.4",
    "10.101.2.7",
    "2001:db8::1",
    "::1",
    "a" * 63 + ".example",
]

REJECTED = [
    "",
    "*.example.com",
    "https://example.com",
    "example.com/path",
    "example.com:443",
    "example.com; id",
    "example.com && curl evil",
    "example.com|id",
    "$(id)",
    "`id`",
    "exa mple.com",
    "example.com\n",
    "Example.com",
    "-bad.example.com",
    "example.com.",
    "10.0.0.0/24",
    "10.0.0.1-254",
    "192.168.0-255.1",
    "1.2.3.256",
    "a" * 64 + ".example",
    "x" * 254,
    "exämple.com",
    "'example.com'",
    '"example.com"',
    "2001:db8::zz",
    "1::2::3",
    "[2001:db8::1]",
    None,
]


class ValidateTargetTests(unittest.TestCase):
    def test_accepted(self):
        for target in ACCEPTED:
            with self.subTest(target=target):
                self.assertIsNone(tc.validate_target(target))

    def test_rejected(self):
        for target in REJECTED:
            with self.subTest(target=target):
                with self.assertRaises(tc.InvalidTarget):
                    tc.validate_target(target)


class RequireValidTargetTests(unittest.TestCase):
    def test_returns_the_target(self):
        self.assertEqual(tc.require_valid_target({"TARGET": "scanme.nmap.org"}, die_file=None), "scanme.nmap.org")

    def test_exits_with_status_2(self):
        for environ in ({}, {"TARGET": ""}, {"TARGET": "example.com; id"}, {"TARGET": "*.example.com"}):
            with self.subTest(environ=environ):
                with self.assertRaises(SystemExit) as ctx:
                    tc.require_valid_target(environ, die_file=None)
                self.assertEqual(ctx.exception.code, 2)


@unittest.skipIf(portscanner is None, "nmap_portscanner.py could not be imported (xmltodict missing?)")
class PortScannerCommandTests(unittest.TestCase):
    def test_command(self):
        self.assertEqual(
            portscanner.nmap_command("example.com"),
            ["sudo", "/bin/nmap", "-sS", "-oX", "/out/result.xml", "example.com"],
        )

    def test_target_stays_one_argument(self):
        self.assertIn("example.com; id", portscanner.nmap_command("example.com; id"))


@unittest.skipIf(httprecon is None, "nmap_httprecon.py could not be imported (xmltodict missing?)")
class HttpReconCommandTests(unittest.TestCase):
    def test_command(self):
        self.assertEqual(
            httprecon.nmap_command("example.com"),
            ["sudo", "/bin/nmap", "-sV", "--script", "http-enum", "example.com", "-oX", "/out/result.xml"],
        )


@unittest.skipIf(tlscipher is None, "nmap_tlscipher.py could not be imported (xmltodict missing?)")
class TlsCipherCommandTests(unittest.TestCase):
    def test_command(self):
        self.assertEqual(
            tlscipher.nmap_command("example.com"),
            ["sudo", "/bin/nmap", "-sV", "--script", "ssl-enum-ciphers", "example.com", "-oX", "/out/result.xml"],
        )


if __name__ == "__main__":
    unittest.main()
