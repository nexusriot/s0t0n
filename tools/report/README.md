# report

Aggregate the s0t0n tools' **NDJSON output into a host-centric report**
(Python, stdlib) — HTML by default, Markdown with `--md`. Reads NDJSON from
files or stdin.

> Authorized use only.

## Usage

```bash
cat results.ndjson | python3 report.py -o out.html
python3 ../s0t0n-run/s0t0n_run.py 10.0.0.0/24 | python3 report.py --md -o out.md
```
