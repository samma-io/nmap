# Samma scanner: Nmap

![Samma-io](assets/samma_logo.png)

[Nmap](https://nmap.org) wrapped as a Samma scanner. It is one of the open-source scanners that the
[Samma operator](https://github.com/samma-io/operator) runs in your Kubernetes cluster, against the
hosts in your annotated Ingresses. Every finding goes to Grafana in that same cluster.

## What it checks

The image has three modes. The operator runs each one as a separate scanner:

| Operator scanner | Script | Nmap command | Finds | Use it for |
|---|---|---|---|---|
| `nmap/port` | `nmap_portscanner.py` (default) | `nmap -sS` | Open TCP ports (SYN scan) | A thorough port inventory |
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
