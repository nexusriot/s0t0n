#!/usr/bin/env python3
"""s0t0n-run — pipeline driver that chains the s0t0n tools over a target and
emits one combined NDJSON stream (pipe into `report`). Authorized use only.

Pipeline: service-fingerprint (--json) -> for TLS ports also tls-inspect + jarm.

Usage:
  s0t0n_run.py <target> [--range 1-1024] [--bin-dir DIR]

`target` is anything service-fingerprint accepts (IP, CIDR, a.b.c.d-e range).
Binaries are auto-located under ../<tool>/target/{release,debug}/; build them
first (cargo build --release) or pass --bin-dir.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

TLS_PORTS = {443, 8443, 993, 995, 465, 5671, 6697}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # tools/


def locate(name: str, bin_dir: str | None) -> str | None:
    if bin_dir:
        cand = os.path.join(bin_dir, name)
        if os.path.exists(cand):
            return cand
    for profile in ("release", "debug"):
        cand = os.path.join(ROOT, name, "target", profile, name)
        if os.path.exists(cand):
            return cand
    return shutil.which(name)


def emit(obj: dict) -> None:
    print(json.dumps(obj), flush=True)


def run_service_fp(binary: str, target: str, prange: str) -> list[dict]:
    out = subprocess.run(
        [binary, "-t", target, "-r", prange, "--json"],
        capture_output=True, text=True, timeout=600,
    )
    rows = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def run_tls_inspect(binary: str, host: str, port: int) -> dict:
    out = subprocess.run([binary, host, "--port", str(port)],
                         capture_output=True, text=True, timeout=30)
    info = {}
    for line in out.stdout.splitlines():
        if line.startswith("Protocol :"):
            info["tls_version"] = line.split(":", 1)[1].strip()
        elif line.startswith("Cipher   :"):
            info["tls_cipher"] = line.split(":", 1)[1].strip()
        elif "subject :" in line and "subject" not in info:
            info["cert_subject"] = line.split("subject :", 1)[1].strip()
    return info


def run_jarm(binary: str, host: str, port: int) -> str:
    out = subprocess.run([binary, host, str(port)],
                         capture_output=True, text=True, timeout=120)
    m = re.search(r"\t([0-9a-f]{62})", out.stdout)
    return m.group(1) if m else ""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--range", default="1-1024")
    ap.add_argument("--bin-dir")
    args = ap.parse_args()

    sfp = locate("service-fingerprint", args.bin_dir)
    if not sfp:
        print("service-fingerprint binary not found; build it first "
              "(cd tools/service-fingerprint && cargo build --release)", file=sys.stderr)
        sys.exit(1)
    tls_bin = locate("tls-inspect", args.bin_dir)
    jarm_bin = locate("jarm", args.bin_dir)

    services = run_service_fp(sfp, args.target, args.range)
    print(f"# {len(services)} open service(s) found", file=sys.stderr)

    for svc in services:
        rec = {"ip": svc.get("ip"), "port": svc.get("port"),
               "service": svc.get("service"), "banner": svc.get("banner", "")}
        port = int(svc.get("port", 0))
        if port in TLS_PORTS:
            if tls_bin:
                rec.update(run_tls_inspect(tls_bin, rec["ip"], port))
            if jarm_bin:
                j = run_jarm(jarm_bin, rec["ip"], port)
                if j:
                    rec["jarm"] = j
        emit(rec)


if __name__ == "__main__":
    main()
