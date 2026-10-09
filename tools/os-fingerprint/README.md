# os-fingerprint

Coarse remote-OS guesser (Rust). Sends an ICMP echo and infers the OS family
from the reply's **IP TTL** (hosts start the TTL at well-known values — 64
Linux/Unix, 128 Windows, 255 network gear — and routers decrement it). A
heuristic, not a replacement for `nmap -O`.

> Needs raw-socket privileges (`sudo` / `CAP_NET_RAW`). Authorized use only.

## Usage

```bash
sudo ./os-fingerprint 10.0.0.5
```

## Build / test

```bash
cargo build --release
cargo test            # TTL classification table
```
