#!/usr/bin/env python3
"""Build the EMSE real-world security-fix candidate corpus from Vul4J.

The script deliberately treats the vulnerability/fix pair as the independent
material. It does not count repeated executions as additional cases.
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import sys
import urllib.request
from collections import Counter
from pathlib import Path

DEFAULT_SOURCE = "https://raw.githubusercontent.com/tuhh-softsec/vul4j/main/dataset/vul4j_dataset.csv"
OUT_FIELDS = [
    "trajectory_id", "source_dataset", "vul_id", "cve_id", "cwe_id", "cwe_name",
    "repo_slug", "ecosystem", "human_patch_url", "fix_commit", "build_system",
    "java_level", "failing_tests", "compile_cmd", "test_all_cmd", "test_cmd",
    "candidate_status", "exclusion_reason"
]


def fetch_text(source: str) -> str:
    if re.match(r"^https?://", source):
        req = urllib.request.Request(source, headers={"User-Agent": "SecFlowOps-EMSE/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8-sig")
    return Path(source).read_text(encoding="utf-8-sig")


def commit_from_url(url: str) -> str:
    m = re.search(r"/commit/([0-9a-fA-F]{7,40})", url or "")
    return m.group(1) if m else ""


def build_rows(text: str, limit: int | None = None) -> list[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(text))
    rows: list[dict[str, str]] = []
    for src in reader:
        vul_id = (src.get("vul_id") or "").strip()
        if not re.fullmatch(r"VUL4J-(?:[1-9]|[1-7][0-9])", vul_id):
            continue
        human_patch = (src.get("human_patch") or "").strip()
        row = {
            "trajectory_id": f"vul4j::{vul_id}",
            "source_dataset": "Vul4J",
            "vul_id": vul_id,
            "cve_id": (src.get("cve_id") or "").strip(),
            "cwe_id": (src.get("cwe_id") or "").strip(),
            "cwe_name": (src.get("cwe_name") or "").strip(),
            "repo_slug": (src.get("repo_slug") or "").strip(),
            "ecosystem": "java",
            "human_patch_url": human_patch,
            "fix_commit": commit_from_url(human_patch),
            "build_system": (src.get("build_system") or "").strip(),
            "java_level": (src.get("compliance_level") or "").strip(),
            "failing_tests": (src.get("failing_tests") or "").strip(),
            "compile_cmd": (src.get("compile_cmd") or "").strip(),
            "test_all_cmd": (src.get("test_all_cmd") or "").strip(),
            "test_cmd": (src.get("test_cmd") or "").strip(),
            "candidate_status": "candidate",
            "exclusion_reason": "",
        }
        missing = [k for k in ("vul_id", "repo_slug", "human_patch_url", "fix_commit") if not row[k]]
        if missing:
            row["candidate_status"] = "excluded_metadata"
            row["exclusion_reason"] = "missing:" + ",".join(missing)
        rows.append(row)
        if limit is not None and len(rows) >= limit:
            break
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=DEFAULT_SOURCE, help="Vul4J CSV URL or local CSV path")
    ap.add_argument("--output", default="SecFlowOps/data/emse/candidate_security_fixes.csv")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--min-cases", type=int, default=30)
    ap.add_argument("--min-projects", type=int, default=15)
    args = ap.parse_args()

    rows = build_rows(fetch_text(args.source), args.limit)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    retained = [r for r in rows if r["candidate_status"] == "candidate"]
    projects = {r["repo_slug"] for r in retained}
    cwes = Counter(r["cwe_id"] for r in retained if r["cwe_id"])
    print(f"candidate_rows={len(rows)} retained={len(retained)} projects={len(projects)} cwes={len(cwes)}")
    if len(retained) < args.min_cases or len(projects) < args.min_projects:
        print("EMSE corpus gate: FAIL", file=sys.stderr)
        return 2
    print("EMSE corpus gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
