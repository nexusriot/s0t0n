#!/usr/bin/env python3
"""report — aggregate the s0t0n tools' NDJSON into a host-centric HTML (or
Markdown) report. Reads NDJSON from files or stdin. Authorized use only.

Usage:
  cat results.ndjson | report.py -o out.html
  s0t0n_run.py 10.0.0.0/24 | report.py --md -o out.md
"""
import argparse
import html
import json
import sys
from collections import defaultdict


def load(streams) -> list[dict]:
    rows = []
    for st in streams:
        for line in st:
            line = line.strip()
            if line.startswith("{"):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def group(rows):
    hosts = defaultdict(list)
    for r in rows:
        hosts[r.get("ip", "?")].append(r)
    return dict(sorted(hosts.items()))


def render_md(hosts) -> str:
    out = ["# s0t0n scan report\n"]
    for ip, recs in hosts.items():
        out.append(f"## {ip}\n")
        out.append("| port | service | details |")
        out.append("|------|---------|---------|")
        for r in sorted(recs, key=lambda x: int(x.get("port", 0))):
            details = []
            for k in ("banner", "tls_version", "tls_cipher", "cert_subject", "jarm", "state"):
                if r.get(k):
                    details.append(f"{k}={r[k]}")
            out.append(f"| {r.get('port','')} | {r.get('service','')} | {'; '.join(details)} |")
        out.append("")
    return "\n".join(out)


def render_html(hosts) -> str:
    rows_total = sum(len(v) for v in hosts.values())
    parts = ["""<!doctype html><html><head><meta charset="utf-8">
<title>s0t0n scan report</title><style>
body{font-family:system-ui,sans-serif;margin:2rem;background:#0b0f14;color:#d6deeb}
h1{color:#7fd1ff}h2{color:#addb67;border-bottom:1px solid #223;padding-bottom:.2rem;margin-top:2rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #223;padding:.35rem .6rem;text-align:left;font-size:.9rem;vertical-align:top}
th{background:#111826;color:#7fd1ff}code{color:#f78c6c}
.weak{color:#ff6b6b}
</style></head><body>"""]
    parts.append(f"<h1>s0t0n scan report</h1><p>{len(hosts)} host(s), {rows_total} record(s)</p>")
    for ip, recs in hosts.items():
        parts.append(f"<h2>{html.escape(ip)}</h2>")
        parts.append("<table><tr><th>Port</th><th>Service</th><th>Details</th></tr>")
        for r in sorted(recs, key=lambda x: int(x.get("port", 0))):
            details = []
            for k in ("banner", "tls_version", "tls_cipher", "cert_subject", "jarm", "state"):
                if r.get(k):
                    details.append(f"<code>{html.escape(k)}</code>={html.escape(str(r[k]))}")
            parts.append(f"<tr><td>{html.escape(str(r.get('port','')))}</td>"
                         f"<td>{html.escape(str(r.get('service','')))}</td>"
                         f"<td>{'<br>'.join(details)}</td></tr>")
        parts.append("</table>")
    parts.append("</body></html>")
    return "\n".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", help="NDJSON files (default: stdin)")
    ap.add_argument("-o", "--out", help="output file (default: stdout)")
    ap.add_argument("--md", action="store_true", help="Markdown instead of HTML")
    args = ap.parse_args()

    streams = [open(f) for f in args.files] if args.files else [sys.stdin]
    rows = load(streams)
    hosts = group(rows)
    text = render_md(hosts) if args.md else render_html(hosts)

    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
        print(f"wrote {args.out} ({len(hosts)} host(s), {len(rows)} record(s))", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
