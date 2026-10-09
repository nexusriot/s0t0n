# cert-transparency

Passive **subdomain discovery** from Certificate Transparency logs via crt.sh
(Python, stdlib). The complement to active `dns-recon brute` — it finds names
that were ever issued a certificate, with no DNS queries to the target.

> Authorized use only.

## Usage

```bash
python3 ct_subdomains.py example.com              # list names
python3 ct_subdomains.py example.com --resolve    # also resolve A/AAAA
```
