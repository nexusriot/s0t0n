# net-neighbors

Unified host discovery (Go). For targets on the interface's own subnet it uses
**ARP** (fast, reliable on a LAN); for off-link targets it falls back to
**ICMP** echo. Prints one table with the method used per host.

> Needs raw sockets (`sudo` / `CAP_NET_RAW`). Authorized use only.

## Usage

```bash
go build -o net-neighbors .
sudo ./net-neighbors eth0 192.168.1.0/24
```
