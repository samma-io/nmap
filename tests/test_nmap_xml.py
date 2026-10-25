"""Tests for nmap_xml.py and the records the three scripts build from it.

Run from the repository root:

    python3 -m unittest discover -s tests -t .

The reports below are trimmed nmap -oX output. The parsing tests need
xmltodict (the image has it, and CI installs it) and are skipped without it.
"""

import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(HERE)
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

import nmap_xml  # noqa: E402

try:
    import xmltodict
except ImportError:
    xmltodict = None

if xmltodict is not None:
    import nmap_httprecon  # noqa: E402
    import nmap_portscanner  # noqa: E402
    import nmap_tlscipher  # noqa: E402

HEAD = '<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap" version="7.94">'
RUNSTATS = '<runstats><finished time="1"/><hosts up="{up}" down="{down}" total="1"/></runstats>'
TAIL = "</nmaprun>"


def _port(portid, service=True, script=0):
    body = '<state state="open" reason="syn-ack"/>'
    if service:
        body += '<service name="http" product="nginx" method="probed"/>'
    for i in range(script):
        body += '<script id="s{0}" output="out{0}"/>'.format(i)
    return '<port protocol="tcp" portid="{0}">{1}</port>'.format(portid, body)


def _host(ports, state="up"):
    return (
        '<host><status state="{0}" reason="syn-ack"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><extraports state="closed" count="998"/>{1}</ports></host>'
    ).format(state, "".join(ports))


def report(*hosts, up=1, down=0):
    return HEAD + "".join(hosts) + RUNSTATS.format(up=up, down=down) + TAIL


ONE_PORT = report(_host([_port(80)]))
TWO_PORTS = report(_host([_port(80), _port(8080)]))
DOWN_NOT_LISTED = report(up=0, down=1)
DOWN_LISTED = report('<host><status state="down" reason="no-response"/>'
                     '<address addr="10.0.0.9" addrtype="ipv4"/></host>', up=0, down=1)
UP_NO_PORTS = report('<host><status state="up" reason="syn-ack"/>'
                     '<address addr="10.0.0.5" addrtype="ipv4"/>'
                     '<ports><extraports state="closed" count="1000"/></ports></host>')
TWO_HOSTS = report(_host([_port(22)]), _host([_port(80), _port(443)]), up=2)


class AsListTests(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(nmap_xml.as_list(None), [])
        self.assertEqual(nmap_xml.as_list({"a": 1}), [{"a": 1}])
        self.assertEqual(nmap_xml.as_list([1, 2]), [1, 2])

    def test_garbage_documents(self):
        for doc in (None, {}, {"nmaprun": None}, {"nmaprun": "x"}, "text"):
            with self.subTest(doc=doc):
                self.assertEqual(nmap_xml.ports(doc), [])
                self.assertEqual(nmap_xml.hosts(doc), [])


@unittest.skipIf(xmltodict is None, "xmltodict is not installed")
class PortsTests(unittest.TestCase):
    def ports(self, xml):
        return [(p["@portid"], p["@protocol"]) for p in nmap_xml.ports(xmltodict.parse(xml))]

    def test_single_open_port(self):
        # xmltodict gives a dict here, not a list of one
        self.assertIsInstance(xmltodict.parse(ONE_PORT)["nmaprun"]["host"]["ports"]["port"], dict)
        self.assertEqual(self.ports(ONE_PORT), [("80", "tcp")])

    def test_two_open_ports(self):
        self.assertEqual(self.ports(TWO_PORTS), [("80", "tcp"), ("8080", "tcp")])

    def test_down_host(self):
        self.assertEqual(self.ports(DOWN_NOT_LISTED), [])
        self.assertEqual(self.ports(DOWN_LISTED), [])

    def test_up_without_open_ports(self):
        self.assertEqual(self.ports(UP_NO_PORTS), [])

    def test_several_hosts(self):
        self.assertEqual(self.ports(TWO_HOSTS), [("22", "tcp"), ("80", "tcp"), ("443", "tcp")])


@unittest.skipIf(xmltodict is None, "xmltodict is not installed")
class ReadReportTests(unittest.TestCase):
    def test_missing_file(self):
        with mock.patch("sys.stderr"):
            self.assertIsNone(nmap_xml.read_report(xmltodict.parse, "/nonexistent/result.xml"))

    def test_truncated_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "result.xml")
            with open(path, "w") as handle:
                handle.write(ONE_PORT[:60])
            with mock.patch("sys.stderr"):
                self.assertIsNone(nmap_xml.read_report(xmltodict.parse, path))


@unittest.skipIf(xmltodict is None, "xmltodict is not installed")
class ScriptRecordTests(unittest.TestCase):
    """The records each script logs; their shape is what the bridge reads."""

    def records(self, script, xml):
        logged = []
        with mock.patch.object(script, "logger", side_effect=logged.append), \
                mock.patch.dict(os.environ, {"TARGET": "web"}):
            script.convert_output(xmltodict.parse(xml))
        return logged

    def test_port_scanner_single_port(self):
        self.assertEqual(self.records(nmap_portscanner, ONE_PORT), [
            {"type": "nmap", "scanner": "nmap_port", "target": "web", "port": "80", "protocol": "tcp"},
        ])

    def test_port_scanner_two_ports(self):
        self.assertEqual([r["port"] for r in self.records(nmap_portscanner, TWO_PORTS)], ["80", "8080"])

    def test_all_scripts_down_host(self):
        for script in (nmap_portscanner, nmap_httprecon, nmap_tlscipher):
            for xml in (DOWN_NOT_LISTED, DOWN_LISTED, UP_NO_PORTS):
                with self.subTest(script=script.__name__, xml=xml):
                    self.assertEqual(self.records(script, xml), [])

    def test_http_single_port(self):
        (record,) = self.records(nmap_httprecon, report(_host([_port(80, script=1)])))
        self.assertEqual(record["type"], "nmap")
        self.assertEqual(record["scanner"], "nmap_httpd")
        self.assertEqual(record["target"], "web")
        self.assertEqual(record["result"]["@portid"], "80")
        self.assertIn("hosts", record["runstats"])

    def test_tls_single_port(self):
        self.assertEqual(self.records(nmap_tlscipher, ONE_PORT), [{
            "type": "nmap", "scanner": "nmap_tls", "target": "web",
            "service": {"@name": "http", "@product": "nginx", "@method": "probed"},
        }])


if __name__ == "__main__":
    unittest.main()
