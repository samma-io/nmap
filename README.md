# Samma scanner: Nmap

![Samma-io](assets/samma_logo.png)

[Nmap](https://nmap.org) wrapped as a Samma scanner. It is one of the open-source scanners that the
[Samma operator](https://github.com/samma-io/operator) runs in your Kubernetes cluster, against the
hosts in your annotated Ingresses. Every finding goes to Grafana in that same cluster.

## What it checks

The image has three modes. The operator runs each one as a separate scanner:

| Operator scanner | Script | Nmap command | Finds | Use it for |
|---|---|---|---|---|
| `nmap/port` | `nmap_portscanner.py` (default) | `nmap -sS`, or `nmap -sT` in [unprivileged mode](#unprivileged-mode) | Open TCP ports | A thorough port inventory |
| `nmap/http` | `nmap_httprecon.py` | `nmap -sV --script http-enum` | Web server fingerprint, common paths and applications | Knowing what software you expose |
| `nmap/tls` | `nmap_tlscipher.py` | `nmap -sV --script ssl-enum-ciphers` | Every TLS cipher and protocol accepted, with a grade | Weak cipher and protocol findings |

The lighter [detect](https://github.com/samma-io/detect) scanners (`port-scanner`, `tls-scanner`)
cover the same ground faster. Use Nmap when you want the full picture.

## Run it locally

```sh
docker build -t samma-nmap .

# port scan (default)
docker run --rm -e TARGET=scanme.nmap.org samma-nmap

# http recon or TLS ciphers
docker run --rm -e TARGET=scanme.nmap.org samma-nmap python3 /code/nmap_httprecon.py
docker run --rm -e TARGET=scanme.nmap.org samma-nmap python3 /code/nmap_tlscipher.py
```

Findings are printed to stdout. Only scan hosts you own or have permission to test;
`scanme.nmap.org` exists for this purpose.

## Settings

All settings are environment variables:

| Variable | Default | Description |
|---|---|---|
| `TARGET` | **required** | Host or IP to scan |
| `SAMMA_IO_SCANNER` | `nmap` | Scanner label on every finding |
| `SAMMA_IO_ID` | `1234` | Id added to every finding |
| `SAMMA_IO_TAGS` | `scanner` | Comma-separated tags added to every finding |
| `SAMMA_IO_JSON` | `{}` | Extra JSON added to every finding |
| `TARGET_ID` | — | samma.io target id, so findings show on that target |
| `WRITE_TO_FILE` | `False` | `true` writes findings to `/out/<PARSER>.json` |
| `PARSER` | `nmap` | Output file name |
| `NATS_ENABLED` | `False` | `true` publishes every finding to NATS |
| `NATS_URL` | `nats://localhost:4222` | NATS server |
| `NATS_SUBJECT` | `scans` | NATS subject (the operator uses `samma-io.scan`) |
| `NMAP_UNPRIVILEGED` | unset | `1` runs nmap without `sudo` and with a connect scan, see [Unprivileged mode](#unprivileged-mode) |
| `NMAP_PRIVILEGED` | unset | `1` runs the SYN scan without `sudo`, with only the `NET_RAW` capability, see [Raw-sockets mode](#raw-sockets-mode). `NMAP_UNPRIVILEGED` wins if both are set |

## Unprivileged mode

By default the image runs nmap through `sudo`, because a SYN scan (`-sS`) needs raw sockets. That
works with `docker run`, but not in a hardened Kubernetes pod: a pod that drops every capability
has no raw sockets to give, with or without `sudo`, and a pod that forbids privilege escalation
cannot run `sudo` at all. The port scan fails either way.

Set `NMAP_UNPRIVILEGED=1` and the scripts run `/bin/nmap` directly as the `samma` user, with the
SYN scan replaced by a connect scan (`-sT`). A connect scan uses ordinary sockets and finds the same
open TCP ports; it is a little slower and completes the handshake, so the target logs it. The http
and tls scanners only drop `sudo`: version detection and NSE scripts already work over ordinary
sockets. nmap reads `NMAP_UNPRIVILEGED` itself as well, so host discovery uses `connect()` to ports
80 and 443 instead of ICMP, and nothing needs `-Pn`.

```sh
docker run --rm -e TARGET=scanme.nmap.org -e NMAP_UNPRIVILEGED=1 samma-nmap
```

Leave the variable unset to keep the SYN scan through `sudo`. The
[Samma operator](https://github.com/samma-io/operator) sets it on every nmap container unless its
`scanners.nmapRawSockets` value is `true`, in which case the pod gets the `NET_RAW` capability and
[raw-sockets mode](#raw-sockets-mode) instead.

## Raw-sockets mode

`NMAP_PRIVILEGED=1` keeps the SYN scan in a pod that drops every capability but adds `NET_RAW`.
`sudo` cannot work there, so the scripts run `/usr/local/lib/samma/nmap-raw` as the `samma` user:
a copy of nmap that carries the file capability `cap_net_raw+eip`. nmap reads `NMAP_PRIVILEGED`
itself and uses raw sockets although it is not root.

```sh
docker run --rm -u 1000 --cap-drop ALL --cap-add NET_RAW \
  -e TARGET=scanme.nmap.org -e NMAP_PRIVILEGED=1 samma-nmap
```

Two conditions, both checked by CI:

* The container needs `NET_RAW` in its bounding set (`capabilities.add: [NET_RAW]`).
* Privilege escalation must be allowed (`allowPrivilegeEscalation: true`, no
  `--security-opt no-new-privileges`). A file capability is a privilege gain at exec, which
  `no_new_privs` forbids, and the kernel then refuses to run `nmap-raw` at all. The scripts report
  that on stderr and exit 1 without a `scan: done` record.

`/bin/nmap` itself has no file capability. Because its capability bit is "effective", the kernel
would refuse to run it in any pod without `NET_RAW`, which would break the default and unprivileged
modes.

## Results

Each script logs one record per port nmap reports (`nmap_port`, `nmap_httpd` or `nmap_tls`), then
`scanner_stop` and `scan: done`. A host that is down, or up with no open ports, gives no findings
and exits 0. If nmap leaves no readable report (it could not start, or was killed) the script
exits 1 without `scan: done`.

The image creates `samma` with uid and gid 1000, the `runAsUser` the operator sets, and removes the
stock `ubuntu` user that recent Ubuntu base images ship at that id. Without that, `samma` would get
uid 1001 and a pod running as 1000 would be the `ubuntu` user, which the sudoers rule does not
cover.

## In Kubernetes

Don't deploy this image by hand. Install the [Samma operator](https://github.com/samma-io/operator)
and pick a profile that includes Nmap (`web`, `network`, `classic`, `default` or `all`) on an
Ingress:

```yaml
metadata:
  annotations:
    samma-io.alpha.kubernetes.io/enable: "true"
    samma-io.alpha.kubernetes.io/profile: "network"
```

The operator runs the scan once straight away and then weekly. When you delete the Ingress, the
scanners are removed. Findings flow through NATS and TimescaleDB to Grafana. The
[Samma guide](https://github.com/samma-io/guide) covers the whole setup.
