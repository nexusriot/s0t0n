# synscan

Half-open (**SYN**) TCP scanner (Rust / `pnet`). Sends a lone SYN and
classifies the reply: SYN/ACK = open, RST = closed, nothing = filtered. Faster
and quieter than a full connect scan — feed the open ports into
`service-fingerprint`.

> Needs raw-socket privileges (`sudo` / `CAP_NET_RAW`). Authorized use only.

## Usage

```bash
sudo ./synscan -t 10.0.0.0/24 -r 1-1024            # CIDR + port range
sudo ./synscan -t 10.0.0.10-50 -r 22,80 -x 10.0.0.1 --json
```

`-t` accepts a CIDR, `a.b.c.d-e` range, or single IP; `-x` excludes targets;
`--json` emits NDJSON.

## Build

```bash
cargo build --release
```
