# ja3

Compute **JA3 (client) and JA3S (server)** TLS fingerprints from a pcap (Go, no
libpcap). The passive, client-side sibling of the active `jarm` tool; reads
pcaps like `pcap-summary`.

> Authorized use only.

## Usage

```bash
go build -o ja3 .
./ja3 capture.pcap
```
