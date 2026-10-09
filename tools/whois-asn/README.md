# whois-asn

Map IPv4 addresses to **ASN / prefix / org** using Team Cymru's DNS interface
(Go, stdlib). Annotates scan results with the owning network.

> Authorized use only.

## Usage

```bash
go build -o whois-asn .
./whois-asn 8.8.8.8 1.1.1.1
cat ips.txt | ./whois-asn            # or pipe one IP per line
```
