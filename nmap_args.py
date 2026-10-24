"""Build the nmap argv for the scanner scripts.

nmap_portscanner.py, nmap_httprecon.py and nmap_tlscipher.py get their
command line from here, so the choice between the two modes lives in one
place:

* Default (NMAP_UNPRIVILEGED unset): nmap runs through sudo with the flags
  each script has always used. The port scan is a SYN scan (-sS), which needs
  raw sockets; the image has a sudoers rule for /bin/nmap for that reason.

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

No third-party imports: the tests import this module without xmltodict.
"""

import os

NMAP = "/bin/nmap"
RESULT_FILE = "/out/result.xml"
ENV_VAR = "NMAP_UNPRIVILEGED"

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


def is_unprivileged(environ=None):
    """True when NMAP_UNPRIVILEGED is set to 1, true, yes or on."""
    if environ is None:
        environ = os.environ
    return environ.get(ENV_VAR, "").strip().lower() in _TRUE_VALUES


def build_command(args, environ=None):
    """Return the full argv for the given nmap arguments in the current mode."""
    args = list(args)
    if not is_unprivileged(environ):
        return ["sudo", NMAP] + args
    for arg in args:
        if arg in _RAW_SOCKET_ONLY:
            raise NeedsRawSockets(
                "nmap option {0} needs raw sockets; unset {1} (operator value "
                "scanners.nmapRawSockets: true) to use it".format(arg, ENV_VAR)
            )
    return [NMAP] + [_CONNECT_EQUIVALENT.get(arg, arg) for arg in args]


def port_scan_command(target, environ=None):
    """nmap_portscanner.py: every open TCP port."""
    return build_command(["-sS", "-oX", RESULT_FILE, target], environ)


def http_recon_command(target, environ=None):
    """nmap_httprecon.py: web server fingerprint and common paths."""
    return build_command(["-sV", "--script", "http-enum", target, "-oX", RESULT_FILE], environ)


def tls_cipher_command(target, environ=None):
    """nmap_tlscipher.py: the TLS ciphers and protocols the target accepts."""
    return build_command(["-sV", "--script", "ssl-enum-ciphers", target, "-oX", RESULT_FILE], environ)
