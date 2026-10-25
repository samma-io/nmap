"""Build the nmap argv for the scanner scripts.

nmap_portscanner.py, nmap_httprecon.py and nmap_tlscipher.py get their
command line from here, so the choice between the two modes lives in one
place:

* Default (neither variable set): nmap runs through sudo with the flags each
  script has always used. The port scan is a SYN scan (-sS), which needs raw
  sockets; the image has a sudoers rule for /bin/nmap for that reason. This
  is what a plain `docker run` gets.

* NMAP_PRIVILEGED=1 (or true): raw-sockets mode for a pod that drops every
  capability but adds NET_RAW. sudo cannot work there (it needs setuid root
  and the capabilities to switch ids), so nmap runs as the current user from
  /usr/local/lib/samma/nmap-raw, a copy of /bin/nmap that carries the file
  capability cap_net_raw+eip. The flags are the default ones, SYN scan
  included. nmap reads the same variable itself and then uses raw sockets
  although it is not root. /bin/nmap has no file capability: the kernel
  refuses to run a binary whose effective file capabilities it cannot grant,
  so a capability on /bin/nmap would break the unprivileged mode below.
  File capabilities are only granted when privilege escalation is allowed
  (no_new_privs off, allowPrivilegeEscalation: true in Kubernetes). Under
  no_new_privs nmap-raw still runs, without the capability, and nmap quits
  with "dnet: Failed to open device"; nmap_xml reports that as a failed
  scan.

* NMAP_UNPRIVILEGED=1 (or true): nmap runs as the current user, without sudo,
  and the SYN scan becomes a connect scan (-sT), which needs ordinary sockets
  only. The samma operator sets this when the scanner pod runs with every
  capability dropped. nmap reads the same variable itself (--unprivileged),
  so host discovery also uses connect() to ports 80 and 443 instead of ICMP,
  and no -Pn is needed. Version detection and NSE scripts (-sV, --script)
  work over ordinary sockets and are passed through unchanged.

Flags that need raw sockets and have no substitute (OS detection, traceroute,
ICMP and ARP pings, the scan types other than connect) are refused in
unprivileged mode, so a script that adds one fails at startup with a clear
message instead of nmap quitting behind a discarded stdout. None of the three
scripts uses them.

When both variables are set, NMAP_UNPRIVILEGED wins: it is the mode that
works in every pod.

No third-party imports: the tests import this module without xmltodict.
"""

import os
import subprocess
import sys

NMAP = "/bin/nmap"
# Copy of /bin/nmap with cap_net_raw+eip, made in the Dockerfile.
NMAP_RAW = "/usr/local/lib/samma/nmap-raw"
RESULT_FILE = "/out/result.xml"
ENV_VAR = "NMAP_UNPRIVILEGED"
PRIVILEGED_ENV_VAR = "NMAP_PRIVILEGED"

_TRUE_VALUES = frozenset(["1", "true", "yes", "on"])

# A raw-socket flag and the flag that does the same job without raw sockets.
_CONNECT_EQUIVALENT = {"-sS": "-sT"}

# nmap either quits on these without raw sockets or silently replaces them.
_RAW_SOCKET_ONLY = frozenset([
    "-O", "--traceroute",
    "-PE", "-PP", "-PM", "-PR",
    "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sY", "-sZ", "-sO", "-sI",
])


class NeedsRawSockets(ValueError):
    """An nmap option in the command cannot run in unprivileged mode."""


def _flag(name, environ):
    if environ is None:
        environ = os.environ
    return environ.get(name, "").strip().lower() in _TRUE_VALUES


def is_unprivileged(environ=None):
    """True when NMAP_UNPRIVILEGED is set to 1, true, yes or on."""
    return _flag(ENV_VAR, environ)


def is_raw_sockets(environ=None):
    """True when NMAP_PRIVILEGED is set (and NMAP_UNPRIVILEGED is not)."""
    return _flag(PRIVILEGED_ENV_VAR, environ) and not is_unprivileged(environ)


def build_command(args, environ=None):
    """Return the full argv for the given nmap arguments in the current mode."""
    args = list(args)
    if is_raw_sockets(environ):
        return [NMAP_RAW] + args
    if not is_unprivileged(environ):
        return ["sudo", NMAP] + args
    for arg in args:
        if arg in _RAW_SOCKET_ONLY:
            raise NeedsRawSockets(
                "nmap option {0} needs raw sockets; unset {1} (operator value "
                "scanners.nmapRawSockets: true) to use it".format(arg, ENV_VAR)
            )
    return [NMAP] + [_CONNECT_EQUIVALENT.get(arg, arg) for arg in args]


def run(argv):
    """Run nmap with its stdout discarded. False when it could not start.

    The scripts judge the scan by the report nmap writes (nmap_xml), not by
    this result: an nmap that could not start writes none. A report left
    by an earlier run is removed first so it cannot stand in for this one.
    """
    try:
        os.remove(RESULT_FILE)
    except OSError:
        pass
    try:
        subprocess.run(argv, stdout=subprocess.DEVNULL, check=False)
    except OSError as exc:
        print("could not run {0}: {1}".format(argv[0], exc), file=sys.stderr)
        return False
    return True


def port_scan_command(target, environ=None):
    """nmap_portscanner.py: every open TCP port."""
    return build_command(["-sS", "-oX", RESULT_FILE, target], environ)


def http_recon_command(target, environ=None):
    """nmap_httprecon.py: web server fingerprint and common paths."""
    return build_command(["-sV", "--script", "http-enum", target, "-oX", RESULT_FILE], environ)


def tls_cipher_command(target, environ=None):
    """nmap_tlscipher.py: the TLS ciphers and protocols the target accepts."""
    return build_command(["-sV", "--script", "ssl-enum-ciphers", target, "-oX", RESULT_FILE], environ)
