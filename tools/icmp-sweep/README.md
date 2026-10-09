# icmp-sweep

ICMP echo (**ping**) sweep of a CIDR (Go). Sends echo requests to every host in
the range and reports responders with RTT. Unlike ARP scanning it works across
routers/subnets.

> Needs raw sockets (`sudo` / `CAP_NET_RAW`). Authorized use only.

## Usage

```bash
go build -o icmp-sweep .
sudo ./icmp-sweep 192.168.1.0/24
```
