"""Tests for nmap_args.py: the argv of the three scanner scripts in the
default mode (sudo, SYN scan), in unprivileged mode (no sudo, connect scan)
and in raw-sockets mode (no sudo, SYN scan from the nmap copy that has a
file capability).

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
RAW = {"NMAP_PRIVILEGED": "1"}
RAW_NMAP = "/usr/local/lib/samma/nmap-raw"

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


class RawSocketsModeTests(unittest.TestCase):
    def test_flag_values(self):
        for value in ("1", "true", "yes", "on", " TRUE "):
            with self.subTest(value=value):
                self.assertTrue(nmap_args.is_raw_sockets({"NMAP_PRIVILEGED": value}))
        for value in ("", "0", "false", "no"):
            with self.subTest(value=value):
                self.assertFalse(nmap_args.is_raw_sockets({"NMAP_PRIVILEGED": value}))
        self.assertFalse(nmap_args.is_raw_sockets({}))

    def test_default_flags_from_the_capability_copy_without_sudo(self):
        for build, default, _ in BUILDERS:
            with self.subTest(build=build.__name__):
                argv = build(TARGET, RAW)
                self.assertEqual(argv, [RAW_NMAP] + default[2:])
                self.assertNotIn("sudo", argv)

    def test_port_scan_stays_a_syn_scan(self):
        self.assertIn("-sS", nmap_args.port_scan_command(TARGET, RAW))

    def test_raw_socket_options_allowed(self):
        self.assertEqual(nmap_args.build_command(["-O", TARGET], RAW), [RAW_NMAP, "-O", TARGET])

    def test_unprivileged_wins_over_privileged(self):
        both = {"NMAP_PRIVILEGED": "1", "NMAP_UNPRIVILEGED": "1"}
        self.assertFalse(nmap_args.is_raw_sockets(both))
        self.assertEqual(nmap_args.port_scan_command(TARGET, both), PORT_UNPRIVILEGED)

    def test_other_modes_never_use_the_capability_copy(self):
        for environ in (PRIVILEGED, UNPRIVILEGED):
            for build, _, _ in BUILDERS:
                with self.subTest(environ=environ, build=build.__name__):
                    self.assertNotIn(RAW_NMAP, build(TARGET, environ))

    def test_target_stays_one_argument(self):
        self.assertIn("example.com; id", nmap_args.port_scan_command("example.com; id", RAW))


class RunTests(unittest.TestCase):
    def test_exec_failure_returns_false(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError(2, "No such file or directory")):
            with mock.patch("sys.stderr"):
                self.assertFalse(nmap_args.run([RAW_NMAP, "-sS", TARGET]))

    def test_success_returns_true_and_uses_no_shell(self):
        with mock.patch("subprocess.run") as run:
            self.assertTrue(nmap_args.run(["/bin/nmap", TARGET]))
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/bin/nmap", TARGET])
        self.assertFalse(kwargs.get("shell", False))


class ScriptCommandTests(unittest.TestCase):
    """The three scripts build their argv through nmap_args from os.environ."""

    def test_default_mode(self):
        for script, default, _ in SCRIPTS:
            with self.subTest(script=script.__name__), mock.patch.dict(os.environ):
                os.environ.pop("NMAP_UNPRIVILEGED", None)
                os.environ.pop("NMAP_PRIVILEGED", None)
                self.assertEqual(script.nmap_command(TARGET), default)

    def test_unprivileged_mode(self):
        for script, _, unprivileged in SCRIPTS:
            with self.subTest(script=script.__name__), mock.patch.dict(os.environ, {"NMAP_UNPRIVILEGED": "1"}):
                self.assertEqual(script.nmap_command(TARGET), unprivileged)

    def test_raw_sockets_mode(self):
        for script, default, _ in SCRIPTS:
            with self.subTest(script=script.__name__), mock.patch.dict(os.environ, {"NMAP_PRIVILEGED": "1"}):
                os.environ.pop("NMAP_UNPRIVILEGED", None)
                self.assertEqual(script.nmap_command(TARGET), [RAW_NMAP] + default[2:])


if __name__ == "__main__":
    unittest.main()
