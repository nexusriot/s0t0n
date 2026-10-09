# ipv6-sweep

IPv6 liveness sweep (Rust). Iterates an IPv6 CIDR (via `netutil::Cidr6`) and
**TCP-connects** to a small port list to find live hosts — the practical
alternative to ICMPv6 neighbor probing (which needs raw sockets). Built on the
shared `scanengine`.

> The prefix must be `/104` or longer to bound the range. Authorized use only.

## Usage

```bash
./ipv6-sweep 2001:db8::/120 -p 22,80,443
./ipv6-sweep fe80::/120 --concurrency 256 --rate 200
```

## Build

```bash
cargo build --release
```
