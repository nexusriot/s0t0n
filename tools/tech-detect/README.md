# tech-detect

Fingerprint **server technology** from HTTP response headers, cookies, body
markers and the favicon mmh3 hash (Go) — e.g. "nginx + WordPress + Cloudflare".

> Authorized use only.

## Usage

```bash
go build -o tech-detect .
./tech-detect https://example.com
```
