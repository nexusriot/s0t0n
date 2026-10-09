# tcp-ping

Measure **TCP connect latency** to a `host:port` over time (Go, no root). A
userland alternative to `icmp-sweep` where ICMP is filtered; reports
min/avg/max/jitter.

> Authorized use only.

## Usage

```bash
go build -o tcp-ping .
./tcp-ping example.com 443 10 500      # host port [count] [interval-ms]
```
