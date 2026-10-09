# cert-expiry-watch

Monitor **TLS certificate expiry** across a host list (Rust). Checks each host's
leaf certificate and **exits non-zero** if any is expired or expires within
`--days` — cron-friendly. Built on the `tls-inspect` library.

> Authorized use only.

## Usage

```bash
./cert-expiry-watch example-hosts.txt --days 30
```

Host list: one `host` or `host:port` per line (`#` comments ignored). See
[example-hosts.txt](example-hosts.txt).

## Build

```bash
cargo build --release
```
