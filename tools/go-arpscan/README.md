# go-arpscan

ARP sweep of a CIDR (Go, `mdlayher/arp`). Resolves MAC addresses for every host
by sending ARP requests on a chosen interface. Two variants:

- `arpscanV1.go` — simple sequential scan (30 ms pacing)
- `arpscan.go` — worker-pool version (20 goroutines, each its own ARP socket)

> Both files declare `func main()` in the same package, so **build one at a
> time**. Needs `sudo` / `CAP_NET_RAW`. Authorized use only.

## Usage

```bash
go build -o arpscan arpscan.go        # or arpscanV1.go
sudo ./arpscan eth0 192.168.1.0/24
```
