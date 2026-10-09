# bannerscan

Simple async TCP **connect-scan + banner grab** (Rust / Tokio). Connects across
a port range with bounded concurrency and reads up to 1 KiB from each open port.
Kept as the minimal reference implementation; `service-fingerprint` is the
protocol-aware successor.

> Authorized use only.

## Usage

```bash
./bannerscan -i 10.0.0.5 -r 1-1024
```

## Build

```bash
cargo build --release
```
