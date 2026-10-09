#!/usr/bin/env python3
"""cert-transparency — passive subdomain discovery from Certificate
Transparency logs via crt.sh. The complement to active `dns-recon brute`:
it finds names that were ever issued a certificate, no DNS queries to the
target. Stdlib only. Authorized use only.

Usage:
  ct_subdomains.py <domain> [--resolve]

  --resolve  also resolve each discovered name (A/AAAA) and show live ones
"""
import concurrent.futures
import json
import socket
import ssl
import sys
import urllib.request


def fetch_names(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "s0t0n-ct/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.load(resp)
    except Exception as e:  # noqa: BLE001
        print(f"crt.sh query failed: {e}", file=sys.stderr)
        sys.exit(1)

    names: set[str] = set()
    for entry in data:
        for field in ("common_name", "name_value"):
            val = entry.get(field, "")
            for name in str(val).splitlines():
                name = name.strip().lstrip("*.").lower()
                if " " in name or "@" in name:
                    continue
                if name == domain or name.endswith("." + domain):
                    names.add(name)
    return names


def resolve(name: str):
    try:
        infos = socket.getaddrinfo(name, None)
        return name, sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return name, None


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    domain = sys.argv[1].strip().lower()
    do_resolve = "--resolve" in sys.argv[2:]

    print(f"Querying crt.sh for *.{domain} ...\n")
    names = sorted(fetch_names(domain))
    if not names:
        print("No certificates found.")
        return

    if not do_resolve:
        for n in names:
            print(n)
        print(f"\n{len(names)} unique name(s) from CT logs.")
        return

    live = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for name, ips in ex.map(resolve, names):
            if ips:
                live += 1
                print(f"{name:45}  {', '.join(ips)}")
            else:
                print(f"{name:45}  (no A/AAAA)")
    print(f"\n{len(names)} name(s), {live} resolvable.")


if __name__ == "__main__":
    main()
