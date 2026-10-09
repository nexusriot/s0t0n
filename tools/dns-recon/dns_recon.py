#!/usr/bin/env python3
"""dns-recon — lightweight DNS reconnaissance for the s0t0n toolkit.

Subcommands:
  reverse <CIDR>            reverse-DNS (PTR) sweep of an IPv4 range
  brute   <domain> [list]   wordlist subdomain brute (with wildcard detection)
  records <domain>          A/AAAA/MX/NS/SOA/TXT/CAA + SPF/DMARC enumeration
  axfr    <domain>          attempt a zone transfer against each authoritative NS

`records` and `axfr` need dnspython; `reverse` and `brute` fall back to stdlib.
Authorized use only: query domains / ranges you own or are permitted to test.
"""
import concurrent.futures
import ipaddress
import os
import socket
import sys

try:
    import dns.resolver
    import dns.query
    import dns.zone
    _HAVE_DNSPYTHON = True
except ImportError:
    _HAVE_DNSPYTHON = False


def reverse_sweep(cidr: str) -> None:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    print(f"Reverse-resolving {len(hosts)} address(es) in {cidr} ...\n")

    def lookup(ip):
        try:
            name, _, _ = socket.gethostbyaddr(str(ip))
            return str(ip), name
        except (socket.herror, socket.gaierror):
            return None

    found = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for res in ex.map(lookup, hosts):
            if res:
                found += 1
                print(f"{res[0]:16}  {res[1]}")
    print(f"\n{found} PTR record(s).")


def _resolve(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except socket.gaierror:
        return None


def brute(domain: str, wordlist: str | None) -> None:
    path = wordlist or os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")
    try:
        with open(path) as fh:
            names = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError as e:
        print(f"cannot read wordlist {path}: {e}", file=sys.stderr)
        sys.exit(1)

    # Wildcard detection: if a random label resolves, the zone is a wildcard.
    import random, string
    rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    wildcard_ips = _resolve(f"{rnd}.{domain}")
    if wildcard_ips:
        print(f"[!] Wildcard DNS detected ({', '.join(wildcard_ips)}); "
              f"matching answers are suppressed.\n")

    print(f"Brute-forcing {len(names)} subdomains of {domain} ...\n")
    targets = [f"{n}.{domain}" for n in names]
    found = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for host, ips in zip(targets, ex.map(_resolve, targets)):
            if ips and ips != wildcard_ips:
                found += 1
                print(f"{host:40}  {', '.join(ips)}")
    print(f"\n{found} resolvable subdomain(s).")


def axfr(domain: str) -> None:
    if not _HAVE_DNSPYTHON:
        print("axfr requires dnspython: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)

    try:
        ns_records = dns.resolver.resolve(domain, "NS")
    except Exception as e:  # noqa: BLE001
        print(f"could not list name servers for {domain}: {e}", file=sys.stderr)
        sys.exit(1)

    any_ok = False
    for ns in ns_records:
        nshost = str(ns.target).rstrip(".")
        try:
            nsip = socket.gethostbyname(nshost)
        except socket.gaierror:
            print(f"[-] {nshost}: cannot resolve NS")
            continue
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nsip, domain, timeout=5))
        except Exception as e:  # noqa: BLE001
            print(f"[-] {nshost} ({nsip}): refused ({e})")
            continue
        any_ok = True
        print(f"[+] {nshost} ({nsip}): ZONE TRANSFER ALLOWED")
        for name, node in zone.nodes.items():
            print(f"    {name}")
            for rds in node.rdatasets:
                print(f"        {rds}")
    if not any_ok:
        print("\nNo name server allowed AXFR (expected for well-configured zones).")


def records(domain: str) -> None:
    if not _HAVE_DNSPYTHON:
        print("records requires dnspython: pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)
    print(f"DNS records for {domain}\n")
    for rtype in ("A", "AAAA", "NS", "MX", "SOA", "TXT", "CAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
        except Exception:  # noqa: BLE001
            continue
        for r in answers:
            print(f"  {rtype:5} {r.to_text()}")

    # SPF (from TXT) and DMARC (_dmarc subdomain).
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            txt = r.to_text().strip('"')
            if txt.lower().startswith("v=spf1"):
                print(f"  SPF   {txt}")
    except Exception:  # noqa: BLE001
        pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            print(f"  DMARC {r.to_text().strip(chr(34))}")
    except Exception:  # noqa: BLE001
        print("  DMARC (none)")


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    cmd, arg = sys.argv[1], sys.argv[2]
    if cmd == "reverse":
        reverse_sweep(arg)
    elif cmd == "brute":
        brute(arg, sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == "records":
        records(arg)
    elif cmd == "axfr":
        axfr(arg)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
