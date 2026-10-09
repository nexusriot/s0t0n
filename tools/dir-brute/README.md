# dir-brute

Wordlist-based **web content discovery** (Go). Reports status, size and redirect
target for each path, skipping 404s. The active complement to
`cert-transparency` / `dns-recon brute`.

> Authorized use only.

## Usage

```bash
go build -o dir-brute .
./dir-brute https://host/ [wordlist]     # defaults to bundled wordlist.txt
```

Ships a small [wordlist.txt](wordlist.txt).
