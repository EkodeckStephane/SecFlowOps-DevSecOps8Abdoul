#!/usr/bin/env python3
"""Replay vulnerable and human-patched Vul4J states and record validation evidence.

This driver delegates build/PoV validation to Vul4J's reproducible environment.
It records process provenance and does not infer scanner effectiveness from PoV
outcomes. SecFlowOps scanner evidence is added separately from PoV validation.
"""
from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import time
from pathlib import Path


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 3600) -> dict:
    started = time.time()
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "elapsed_s": round(time.time() - started, 3),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def docker_vul4j(image: str, vul_id: str, host_out: Path, timeout: int) -> dict:
    host_out.mkdir(parents=True, exist_ok=True)
    shell = (
        "set -euo pipefail; "
        f"vul4j reproduce --id {shlex.quote(vul_id)} 2>&1 | tee /out/reproduce.log; "
        "cp -f /root/vul4j_data/reproduction.txt /out/reproduction_full.txt 2>/dev/null || true"
    )
    result = run([
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "-v", f"{host_out.resolve()}:/out", image,
        "bash", "-lc", shell,
    ], timeout=timeout)
    (host_out / "docker_stdout.log").write_text(result["stdout"], encoding="utf-8", errors="replace")
    (host_out / "docker_stderr.log").write_text(result["stderr"], encoding="utf-8", errors="replace")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--output-dir", default="SecFlowOps/results/emse/vul4j")
    ap.add_argument("--image", default="tuhhsoftsec/vul4j:latest")
    ap.add_argument("--ids", nargs="*", help="Optional VUL4J IDs; otherwise all candidate rows")
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    with open(args.manifest, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    selected = [r for r in rows if r.get("candidate_status") == "candidate"]
    if args.ids:
        wanted = set(args.ids)
        selected = [r for r in selected if r.get("vul_id") in wanted]

    root = Path(args.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    summary = []
    for row in selected:
        vul_id = row["vul_id"]
        case_dir = root / vul_id
        result = docker_vul4j(args.image, vul_id, case_dir, args.timeout)
        log_path = case_dir / "reproduce.log"
        log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else result["stdout"]
        record = {
            "trajectory_id": row["trajectory_id"],
            "vul_id": vul_id,
            "repo_slug": row["repo_slug"],
            "cve_id": row["cve_id"],
            "cwe_id": row.get("cwe_id", ""),
            "human_patch_url": row["human_patch_url"],
            "reproduce_returncode": result["returncode"],
            "reproduce_elapsed_s": result["elapsed_s"],
            "vulnerable_state_seen": "Applying version: vulnerable" in log_text,
            "human_patch_state_seen": "Applying version: human_patch" in log_text,
            "reproduction_pass": "Vulnerabilities: PASS" in log_text,
            "spotbugs_pass_or_skip": ("Spotbugs: PASS" in log_text or "Spotbugs: SKIP" in log_text),
        }
        (case_dir / "run_record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        summary.append(record)
        print(json.dumps(record, sort_keys=True))

    out_csv = root / "trajectory_validation.csv"
    fields = list(summary[0].keys()) if summary else ["trajectory_id"]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summary)
    failures = [r for r in summary if not r.get("reproduction_pass")]
    print(f"validated={len(summary)-len(failures)} failed={len(failures)} total={len(summary)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
