# snmp-check

Try a list of **SNMP community strings** (v1/v2c) against a host and, on
success, read `sysDescr.0` (Go, hand-crafted SNMP GET). High-signal recon for
misconfigured devices.

> Authorized use only.

## Usage

```bash
go build -o snmp-check .
./snmp-check 10.0.0.5                     # defaults: public,private
./snmp-check 10.0.0.5 public,private,community
```
