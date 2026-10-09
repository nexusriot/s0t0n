# mdns-ssdp-discover

Passive-ish **LAN service discovery** (Go). Sends an SSDP `M-SEARCH` (UPnP) and
an mDNS/DNS-SD `PTR` query, then prints the responders and advertised services.
No special privileges required.

> Authorized use only.

## Usage

```bash
go build -o mdns-ssdp-discover .
./mdns-ssdp-discover
```
