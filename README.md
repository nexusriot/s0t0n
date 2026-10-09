# s0t0n

A polyglot collection of **network reconnaissance, fingerprinting, and
defensive-analysis tools** — built as hands-on exercises in Rust, Go, and
Python. Each tool is a self-contained, minimal implementation of a classic
primitive, favouring clarity over feature-completeness, and the newer ones
speak a shared NDJSON (`--json`) format so they chain together.

> ⚠️ **Authorized use only.** These actively probe networks (ARP/ICMP/SYN/UDP
> sweeps, banner/TLS/SSH fingerprinting, DNS & web enumeration, Tor fetches, LAN
> discovery) and inspect traffic. Run them only against hosts and networks you
> own or have explicit written permission to test, and comply with local law.

## Shared libraries

- **`netutil`** (Rust) — IPv4 **and** IPv6 CIDR parsing, `a.b.c.d-e` range
  syntax, exclusion lists, and a dependency-free NDJSON builder. Ships a
  `cidr-expand` binary and unit tests.
- **`scanengine`** (Rust) — async scan engine: bounded concurrency, global
  token-bucket rate limiting, retries. Used by `udp-scan` and `ipv6-sweep`.

NDJSON tools pipe through `jq` and into `report`, e.g.
`synscan -t 10.0.0.0/24 -r 1-1024 --json | jq -r 'select(.state=="open").ip'`.

## Tools by category

### Host discovery
| Tool | Lang | One-liner |
|------|------|-----------|
| **icmp-sweep** | Go | ICMP echo sweep of a CIDR (`sudo ./icmp-sweep 192.168.1.0/24`) |
| **go-arpscan** | Go | ARP sweep, sequential + worker-pool (build one `.go` at a time) |
| **net-neighbors** | Go | unified ARP (on-link) + ICMP (routed) discovery |
| **ipv6-sweep** | Rust | TCP-connect liveness sweep over an IPv6 CIDR (uses `scanengine`) |
| **py-arpscan** | Python | scapy ARP broadcast sweep |
| **arp-watch** | Go | passive ARP monitor, alerts on new MAC / IP↔MAC change |
| **tcp-ping** | Go | TCP connect latency/jitter over time (no root) |

### Port & service scanning
| Tool | Lang | One-liner |
|------|------|-----------|
| **synscan** | Rust | half-open SYN scan, CIDR/range/exclusions, `--json` (root) |
| **udp-scan** | Rust | UDP service probes (DNS/NTP/SNMP/mDNS/SSDP/NetBIOS/IKE), `--json` |
| **service-fingerprint** | Rust | protocol-aware banner probes, `--json`, ranges/exclusions |
| **bannerscan** | Rust | simple async connect-scan + banner read |
| **os-fingerprint** | Rust | ICMP TTL → OS family guess (root) |
| **port-knock** | Go | send a knock sequence then probe a port |
| **mini-honeypot** | Go | open ports and log who connects (defensive) |

### TLS / crypto
| Tool | Lang | One-liner |
|------|------|-----------|
| **tls-inspect** | Rust | dump a TLS certificate chain (lib + bin) |
| **tls-ciphers** | Rust | enumerate accepted TLS versions + cipher suites, flag weak |
| **cert-expiry-watch** | Rust | alert/exit-nonzero on soon-to-expire certs (cron) |
| **jarm** | Rust | active JARM TLS-server fingerprint (byte-exact vs reference) |
| **ja3** | Go | JA3/JA3S client+server fingerprints from a pcap |
| **ssh-audit-lite** | Go | SSH KEXINIT algorithms + weak-algo flags |

### DNS / OSINT / web
| Tool | Lang | One-liner |
|------|------|-----------|
| **dns-recon** | Python | reverse / brute+wildcard / records / AXFR |
| **cert-transparency** | Python | subdomains from crt.sh CT logs |
| **whois-asn** | Go | IP → ASN / prefix / org (Team Cymru) |
| **http-probe** | Go | URL list → status/title/headers/favicon-mmh3 |
| **tech-detect** | Go | fingerprint server tech (headers/cookies/body/favicon) |
| **dir-brute** | Go | wordlist web content discovery |
| **onion-batch** | Rust | batch .onion uptime/title checker over Tor |

### Other-protocol recon
| Tool | Lang | One-liner |
|------|------|-----------|
| **snmp-check** | Go | SNMP v1/v2c community brute → sysDescr |
| **smb-enum** | Go | SMB2 NEGOTIATE: dialect + signing posture |

### Traffic analysis
| Tool | Lang | One-liner |
|------|------|-----------|
| **pcap-summary** | Go | talkers / protocols / DNS / plaintext-cred hints from a pcap |
| **dns-sniff** | Go | passive DNS logger from a pcap |

### Orchestration & reporting
| Tool | Lang | One-liner |
|------|------|-----------|
| **s0t0n-run** | Python | pipeline driver: service-fingerprint → tls-inspect + jarm → NDJSON |
| **report** | Python | aggregate NDJSON into a host-centric HTML/Markdown report |

## Selected usage

```bash
# Build the Rust scanners (each independent)
for d in netutil scanengine synscan udp-scan ipv6-sweep service-fingerprint \
         os-fingerprint tls-inspect tls-ciphers cert-expiry-watch jarm; do
  (cd tools/$d && cargo build --release)
done

# Port + service + TLS pipeline, rendered to HTML
sudo tools/synscan/target/release/synscan -t 10.0.0.0/24 -r 1-1024 --json > ports.ndjson
python3 tools/s0t0n-run/s0t0n_run.py 10.0.0.5 --range 1-1024 | python3 tools/report/report.py -o report.html

# TLS posture of a host
tools/tls-ciphers/target/release/tls-ciphers example.com
tools/jarm/target/release/jarm example.com 443

# UDP services + IPv6 sweep
tools/udp-scan/target/release/udp-scan -t 10.0.0.0/24 --json
tools/ipv6-sweep/target/release/ipv6-sweep 2001:db8::/120 -p 22,80,443

# Web-layer recon
(cd tools/tech-detect && go build . && ./tech-detect https://example.com)
(cd tools/dir-brute  && go build . && ./dir-brute https://example.com)

# Traffic analysis / fingerprints from a capture
(cd tools/pcap-summary && go build . && ./pcap-summary capture.pcap)
(cd tools/ja3          && go build . && ./ja3 capture.pcap)
(cd tools/dns-sniff    && go build . && ./dns-sniff capture.pcap)

# DNS / OSINT
python3 tools/dns-recon/dns_recon.py records example.com
python3 tools/cert-transparency/ct_subdomains.py example.com --resolve
(cd tools/whois-asn && go build . && ./whois-asn 8.8.8.8)
```

## Requirements

- **Rust** (stable, 2021) — netutil, scanengine, synscan, udp-scan, ipv6-sweep,
  bannerscan, service-fingerprint, os-fingerprint, tls-inspect, tls-ciphers,
  cert-expiry-watch, jarm, onion_checker, onion-batch
- **Go** 1.22+ — icmp-sweep, go-arpscan, net-neighbors, arp-watch, tcp-ping,
  port-knock, mini-honeypot, ssh-audit-lite, ja3, whois-asn, http-probe,
  tech-detect, dir-brute, snmp-check, smb-enum, pcap-summary, dns-sniff
- **Python** 3.12 (+ `scapy`/`dnspython`) — py-arpscan, dns-recon,
  cert-transparency, s0t0n-run, report
- Root / `CAP_NET_RAW` for ARP, ICMP, SYN, OS-fingerprint, arp-watch

## Verification notes

- **jarm** output is byte-identical to the reference `salesforce/jarm` scanner
  (validated against Cloudflare / Google / GitHub).
- **ja3** output matches the canonical JA3 string + MD5 on a crafted ClientHello.
- **netutil** (8 tests) and **scanengine** (3 tests) ship `cargo test` suites.
- Raw-socket tools (synscan, icmp-sweep, net-neighbors, os-fingerprint,
  arp-watch) build cleanly but must run as root to exercise the network path.

## Known issues / TODO

- `go-arpscan` keeps two `main()` in one package; build one file at a time.
- `synscan`/`service-fingerprint`/`udp-scan` are IPv4-only (netutil has IPv6).
- `s0t0n-run` routes through `service-fingerprint` (IP targets); TLS cert/JARM
  enrichment needs a real SNI hostname, so feed hostnames to `tls-*`/`jarm` directly.
- `onion_checker`/`onion-batch` hard-code HTTP/1.1 and ignore TLS for `https` onions.
- `os-fingerprint` is a coarse TTL heuristic, not a replacement for `nmap -O`.

## License

Personal / educational. No warranty.
