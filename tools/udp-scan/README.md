# udp-scan

UDP service scanner (Rust). Sends **protocol-specific payloads** (DNS, NTP,
SNMP, mDNS, SSDP, NetBIOS, IKE) and marks a port open on any UDP response;
silence is reported as `open|filtered` (UDP returns no RST). Built on the shared
`scanengine` (bounded concurrency + rate limiting).

> Authorized use only.

## Usage

```bash
./udp-scan -t 10.0.0.0/24                 # all known UDP probes
./udp-scan -t 10.0.0.5 -p 53,161 --json   # specific ports, NDJSON
./udp-scan -t 10.0.0.0/24 --rate 500      # cap at 500 probes/sec
```

## Build

```bash
cargo build --release
```
