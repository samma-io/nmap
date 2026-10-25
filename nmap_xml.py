"""Read nmap's XML report (as parsed by xmltodict) for the scanner scripts.

xmltodict turns a repeated element into a list but a single element into a
dict, and leaves a missing element out. So the same key can hold a list, a
dict or nothing depending on how many hosts were up and how many ports were
open. Iterating over a dict walks its keys, which is why a host with exactly
one open port used to give no findings, and indexing a missing "host" is why
a down host crashed the TLS script. Everything here returns lists, so the
scripts never see the difference.

No third-party imports: the scripts parse the XML, this module only walks
the result, and the tests can use it without xmltodict.
"""

import sys

from nmap_args import RESULT_FILE, is_raw_sockets


def as_list(value):
    """[] for None, [value] for a single element, the list itself otherwise."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def hosts(doc):
    """Every <host> in the report. A down host is usually not listed at all."""
    if not isinstance(doc, dict):
        return []
    run = doc.get("nmaprun")
    if not isinstance(run, dict):
        return []
    return [host for host in as_list(run.get("host")) if isinstance(host, dict)]


def host_is_up(host):
    """False when nmap lists the host with <status state="down">."""
    status = host.get("status")
    if isinstance(status, dict):
        return status.get("@state", "up") == "up"
    return True


def ports(doc):
    """Every <port> of every host that is up, in report order."""
    found = []
    for host in hosts(doc):
        if not host_is_up(host):
            continue
        for port_list in as_list(host.get("ports")):
            if not isinstance(port_list, dict):
                continue
            for port in as_list(port_list.get("port")):
                if isinstance(port, dict):
                    found.append(port)
    return found


def runstats(doc):
    """The <runstats> element, or None."""
    if isinstance(doc, dict) and isinstance(doc.get("nmaprun"), dict):
        return doc["nmaprun"].get("runstats")
    return None


def error(doc):
    """nmap's own error message when it quit early, else None.

    nmap still writes a well-formed report when it hits a fatal error, with
    <finished exit="error" errormsg="...">. Without this check such a run
    looks like a clean scan of a down host.
    """
    stats = runstats(doc)
    if not isinstance(stats, dict):
        return None
    finished = stats.get("finished")
    if isinstance(finished, dict) and finished.get("@exit") == "error":
        return finished.get("@errormsg") or "nmap exited with an error"
    return None


def read_report(parse, path=RESULT_FILE, environ=None):
    """Parse the report with parse (xmltodict.parse) and return the document.

    Returns None, with a message on stderr, when nmap left no readable
    report: it failed to start, could not resolve the target, or was
    killed. That is a failed scan, unlike a down host, which nmap reports
    normally with no <host> element. A report in which nmap records a fatal
    error counts as no report.
    """
    try:
        with open(path, "r") as handle:
            text = handle.read()
    except OSError as exc:
        print("nmap wrote no report ({0}): {1}".format(path, exc), file=sys.stderr)
        return None
    try:
        doc = parse(text)
    except Exception as exc:  # xmltodict raises expat errors on a cut-off file
        print("nmap report {0} is not valid XML: {1}".format(path, exc), file=sys.stderr)
        return None
    message = error(doc)
    if message is not None:
        print("nmap failed: {0}".format(message), file=sys.stderr)
        if is_raw_sockets(environ):
            # Seen as "dnet: Failed to open device eth0" when nmap-raw runs
            # without its capability, e.g. under no_new_privs.
            print(
                "NMAP_PRIVILEGED=1 needs the NET_RAW capability and privilege "
                "escalation allowed (allowPrivilegeEscalation: true, no "
                "no-new-privileges): the file capability on nmap-raw is not "
                "granted otherwise",
                file=sys.stderr,
            )
        return None
    return doc
