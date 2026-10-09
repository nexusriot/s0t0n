# jarm

Active **TLS-server fingerprinting** via the JARM algorithm (Rust). Sends 10
deliberately varied TLS ClientHellos and hashes the server's responses into a
62-character fingerprint for clustering / identification.

Independent reimplementation of the public JARM algorithm (`salesforce/jarm`);
output is **byte-identical** to the reference scanner (validated against
Cloudflare / Google / GitHub).

> Authorized use only.

## Usage

```bash
./jarm example.com 443
```

## Build

```bash
cargo build --release
```
