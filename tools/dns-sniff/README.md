# dns-sniff

Passive **DNS logger** from a pcap (Go, no libpcap) — who queried what, and the
answers returned. Defensive counterpart to `dns-recon`.

> Authorized use only.

## Usage

```bash
go build -o dns-sniff .
./dns-sniff capture.pcap
```
