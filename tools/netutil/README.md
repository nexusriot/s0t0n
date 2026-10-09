# netutil

Shared Rust library (and `cidr-expand` binary) with the networking helpers the
other s0t0n tools reuse, so each scanner doesn't re-implement host enumeration.

**Provides**
- `Cidr` — IPv4 CIDR parsing, `.hosts()` / `.addresses()` / `.broadcast()`
- `Cidr6` — IPv6 CIDR parsing with bounded host iteration
- `expand_v4` / `exclude_v4` — target specs: CIDR, `a.b.c.d-e` ranges, single
  IPs, with exclusion lists
- `jsonl` — dependency-free NDJSON record builder for the tools' `--json` output

## Usage (cidr-expand)

```bash
cargo run --bin cidr-expand -- 192.168.1.0/29        # usable hosts
cargo run --bin cidr-expand -- 10.0.0.0/30 --all     # incl. network/broadcast
```

## Build / test

```bash
cargo build --release
cargo test            # CIDR math, IPv6, ranges, exclusions, NDJSON
```
