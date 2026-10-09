# http-probe

Fetch a list of URLs and record **status, final URL, title, Server + security
headers, redirect chain and a shodan-style favicon mmh3 hash** (Go). A clearnet
sibling of `onion-batch`.

> Authorized use only.

## Usage

```bash
go build -o http-probe .
./http-probe example-urls.txt        # one URL (or bare host) per line
```

See [example-urls.txt](example-urls.txt).
