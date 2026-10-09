# pcap-summary

Read a **.pcap** file (no libpcap / cgo) and summarize top talkers, L4 protocol
mix, DNS queries and plaintext-credential hints (Go). A defensive/analysis
counterpart to the recon tools.

> Authorized use only.

## Usage

```bash
go build -o pcap-summary .
./pcap-summary capture.pcap
```
