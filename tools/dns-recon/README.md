# dns-recon

Lightweight **DNS reconnaissance** (Python). Four subcommands:

| Subcommand | What it does |
|------------|--------------|
| `reverse <CIDR>`      | reverse-DNS (PTR) sweep of an IPv4 range |
| `brute <domain> [wl]` | wordlist subdomain brute, with **wildcard detection** |
| `records <domain>`    | A/AAAA/MX/NS/SOA/TXT/CAA + SPF/DMARC enumeration |
| `axfr <domain>`       | attempt a zone transfer against each authoritative NS |

`reverse` and `brute` use only the stdlib; `records` and `axfr` need
`dnspython`.

> Authorized use only.

## Usage

```bash
pip install -r requirements.txt
python3 dns_recon.py reverse 192.168.1.0/24
python3 dns_recon.py brute   example.com
python3 dns_recon.py records example.com
python3 dns_recon.py axfr    example.com
```

Ships a small [wordlist.txt](wordlist.txt).
