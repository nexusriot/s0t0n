# arp-watch

Passive **ARP monitor** (Go, pure-Go AF_PACKET). Listens for ARP traffic on an
interface and alerts on newly seen hosts and on IP↔MAC changes (possible ARP
spoofing). The defensive counterpart to `go-arpscan`.

> Needs raw sockets (`sudo` / `CAP_NET_RAW`). Authorized use only.

## Usage

```bash
go build -o arp-watch .
sudo ./arp-watch eth0
```
