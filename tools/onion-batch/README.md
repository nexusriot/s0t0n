# onion-batch

Batch **.onion uptime/title checker** over Tor (Rust / `arti`). Reads a file of
URLs, fetches each over a single bootstrapped Tor client with bounded
concurrency, and prints a status / latency / `<title>` table. The list-driven
sibling of the `onion_checker` PoC.

> Authorized use only. First run is slow (Tor bootstrap).

## Usage

```bash
./onion-batch example-urls.txt        # one URL per line, '#' comments ignored
```

## Build

```bash
cargo build --release
```
