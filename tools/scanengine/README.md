# scanengine

Shared Rust async scan engine used by the newer scanners (`udp-scan`,
`ipv6-sweep`). Runs many async probes with **bounded concurrency**, an optional
**global token-bucket rate limit**, and **retries**, preserving input order.

**API**
- `Config { concurrency, rate_per_sec, retries }`
- `run(items, cfg, |item| async { ... }) -> Vec<Option<T>>`
- `RateLimiter` — standalone token-bucket limiter

## Build / test

```bash
cargo build --release
cargo test            # ordering, retries, rate limiting
```

This is a library crate; depend on it with a path dependency:
`scanengine = { path = "../scanengine" }`.
