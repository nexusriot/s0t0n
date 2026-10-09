# s0t0n-run

Pipeline driver (Python) that **chains the s0t0n tools** over a target and emits
one combined NDJSON stream (pipe into `report`).

Pipeline: `service-fingerprint --json` → for TLS ports also `tls-inspect` and
`jarm`. Binaries are auto-located under `../<tool>/target/{release,debug}/`;
build them first or pass `--bin-dir`.

> `target` is anything `service-fingerprint` accepts (IP / CIDR / `a.b.c.d-e`).
> Authorized use only.

## Usage

```bash
python3 s0t0n_run.py 10.0.0.0/24 --range 1-1024 | python3 ../report/report.py -o report.html
```
