"""Tests for nmap_args.py: the argv of the three scanner scripts in the
default mode (sudo, SYN scan) and in unprivileged mode (no sudo, connect
scan).

Run from the repository root:

    python3 -m unittest discover -s tests -t .

The scanner scripts import xmltodict. When it is not installed a stub module
stands in for it here, because these tests only look at the argv the scripts
build and never parse XML.
"""

import os
import sys
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(HERE)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

try:
    import xmltodict  # noqa: F401
except ImportError:
    sys.modules["xmltodict"] = types.ModuleType("xmltodict")

import nmap_args  # noqa: E402
import nmap_httprecon  # noqa: E402
import nmap_portscanner  # noqa: E402
import nmap_tlscipher  # noqa: E402

TARGET = "scanme.nmap.org"
PRIVILEGED = {}
UNPRIVILEGED = {"NMAP_UNPRIVILEGED": "1"}

PORT_DEFAULT = ["sudo", "/bin/nmap", "-sS", "-oX", "/out/result.xml", TARGET]
PORT_UNPRIVILEGED = ["/bin/nmap", "-sT", "-oX", "/out/result.xml", TARGET]
HTTP_DEFAULT = ["sudo", "/bin/nmap", "-sV", "--script", "http-enum", TARGET, "-oX", "/out/result.xml"]
HTTP_UNPRIVILEGED = ["/bin/nmap", "-sV", "--script", "http-enum", TARGET, "-oX", "/out/result.xml"]
TLS_DEFAULT = ["sudo", "/bin/nmap", "-sV", "--script", "ssl-enum-ciphers", TARGET, "-oX", "/out/result.xml"]
TLS_UNPRIVILEGED = ["/bin/nmap", "-sV", "--script", "ssl-enum-ciphers", TARGET, "-oX", "/out/result.xml"]

BUILDERS = [
    (nmap_args.port_scan_command, PORT_DEFAULT, PORT_UNPRIVILEGED),
    (nmap_args.http_recon_command, HTTP_DEFAULT, HTTP_UNPRIVILEGED),
    (nmap_args.tls_cipher_command, TLS_DEFAULT, TLS_UNPRIVILEGED),
]

SCRIPTS = [
    (nmap_portscanner, PORT_DEFAULT, PORT_UNPRIVILEGED),
    (nmap_httprecon, HTTP_DEFAULT, HTTP_UNPRIVILEGED),
    (nmap_tlscipher, TLS_DEFAULT, TLS_UNPRIVILEGED),
]


class ModeTests(unittest.TestCase):
    def test_unset_is_privileged(self):
        self.assertFalse(nmap_args.is_unprivileged({}))

    def test_true_values(self):
        for value in ("1", "true", "True", "TRUE", "yes", "on", " 1 "):
            with self.subTest(value=value):
                self.assertTrue(nmap_args.is_unprivileged({"NMAP_UNPRIVILEGED": value}))

    def test_other_values_are_privileged(self):
        for value in ("", "0", "false", "no", "off", "maybe"):
            with self.subTest(value=value):
                self.assertFalse(nmap_args.is_unprivileged({"NMAP_UNPRIVILEGED": value}))

    def test_reads_os_environ_by_default(self):
        with mock.patch.dict(os.environ, {"NMAP_UNPRIVILEGED": "1"}):
            self.assertTrue(nmap_args.is_unprivileged())
        with mock.patch.dict(os.environ):
            os.environ.pop("NMAP_UNPRIVILEGED", None)
            self.assertFalse(nmap_args.is_unprivileged())


class HelperCommandTests(unittest.TestCase):
    def test_default_mode(self):
        for build, default, _ in BUILDERS:
            with self.subTest(build=build.__name__):
                self.assertEqual(build(TARGET, PRIVILEGED), default)

    def test_unprivileged_mode(self):
        for build, _, unprivileged in BUILDERS:
            with self.subTest(build=build.__name__):
                self.assertEqual(build(TARGET, UNPRIVILEGED), unprivileged)

    def test_unprivileged_mode_never_uses_sudo_or_syn_scan(self):
        for build, _, _ in BUILDERS:
            with self.subTest(build=build.__name__):
                argv = build(TARGET, UNPRIVILEGED)
                self.assertEqual(argv[0], "/bin/nmap")
                self.assertNotIn("sudo", argv)
                self.assertNotIn("-sS", argv)
                self.assertIn(TARGET, argv)

    def test_no_script_needs_pn(self):
        # Without raw sockets nmap pings with connect() to 80 and 443, so host
        # discovery still works and no script has to skip it.
        for build, _, _ in BUILDERS:
            with self.subTest(build=build.__name__):
                self.assertNotIn("-Pn", build(TARGET, UNPRIVILEGED))

    def test_script_scans_are_unchanged(self):
        for build, default, unprivileged in BUILDERS[1:]:
            with self.subTest(build=build.__name__):
                self.assertEqual(default, ["sudo"] + unprivileged)

    def test_target_stays_one_argument(self):
        for environ in (PRIVILEGED, UNPRIVILEGED):
            with self.subTest(environ=environ):
                self.assertIn("example.com; id", nmap_args.port_scan_command("example.com; id", environ))

    def test_raw_socket_only_options_are_refused_unprivileged(self):
        for option in ("-O", "--traceroute", "-PE", "-sU"):
            with self.subTest(option=option):
                self.assertEqual(
                    nmap_args.build_command([option, TARGET], PRIVILEGED),
                    ["sudo", "/bin/nmap", option, TARGET],
                )
                with self.assertRaises(nmap_args.NeedsRawSockets):
                    nmap_args.build_command([option, TARGET], UNPRIVILEGED)


class ScriptCommandTests(unittest.TestCase):
    """The three scripts build their argv through nmap_args from os.environ."""

    def test_default_mode(self):
        for script, default, _ in SCRIPTS:
            with self.subTest(script=script.__name__), mock.patch.dict(os.environ):
                os.environ.pop("NMAP_UNPRIVILEGED", None)
                self.assertEqual(script.nmap_command(TARGET), default)

    def test_unprivileged_mode(self):
        for script, _, unprivileged in SCRIPTS:
            with self.subTest(script=script.__name__), mock.patch.dict(os.environ, {"NMAP_UNPRIVILEGED": "1"}):
                self.assertEqual(script.nmap_command(TARGET), unprivileged)


if __name__ == "__main__":
    unittest.main()
