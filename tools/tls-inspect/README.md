# tls-inspect

Dump a server's **TLS certificate chain** (Rust, library + binary). Connects
without validating (so self-signed / expired / mismatched certs are still
shown) and prints each cert's subject, issuer, SANs, validity and serial, plus
the negotiated protocol, cipher and ALPN.

The library (`tls_inspect::inspect`) is reused by `cert-expiry-watch`.

> Authorized use only.

## Usage

```bash
./tls-inspect example.com
./tls-inspect 10.0.0.5 --port 8443 --sni internal.lan
```

## Build

```bash
cargo build --release
```
