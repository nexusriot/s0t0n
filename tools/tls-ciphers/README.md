# tls-ciphers

Enumerate the **TLS protocol versions and cipher suites a server accepts**
(Rust, raw sockets — no TLS library). Sends one ClientHello per candidate and
reads the ServerHello, then flags weak/legacy suites (CBC, SHA-1, RC4, 3DES,
static-RSA / no-PFS). The TLS analogue of `ssh-audit-lite`.

> Authorized use only.

## Usage

```bash
./tls-ciphers example.com
./tls-ciphers 10.0.0.5 8443
```

## Build

```bash
cargo build --release
```
