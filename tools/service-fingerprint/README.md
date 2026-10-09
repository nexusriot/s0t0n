# service-fingerprint

Protocol-aware TCP service fingerprinter (Rust). Successor to `bannerscan`:
instead of a single blind read it sends a **protocol-specific probe** (HTTP
`HEAD`, SMTP `EHLO`, …) and labels the service. Accepts a single IP, CIDR, or
`a.b.c.d-e` range with exclusions, and can emit NDJSON.

> Authorized use only.

## Usage

```bash
./service-fingerprint -t 10.0.0.5 -r 1-1024
./service-fingerprint -t 10.0.0.0/28 -r 22-443 -x 10.0.0.1 --json
```

## Build

```bash
cargo build --release
```
