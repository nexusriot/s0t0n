# mini-honeypot

Open several TCP ports and **log the source and first bytes** of anyone who
connects (Go). Catches scanners on your own network; the active counterpart to
`arp-watch`.

> Run on your own host. Authorized use only.

## Usage

```bash
go build -o mini-honeypot .
./mini-honeypot 23,2323,8080
```
