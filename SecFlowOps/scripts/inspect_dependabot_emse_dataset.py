#!/usr/bin/env python3
"""Inspect the public replication data of Mohayeji et al. (EMSE 2025).

This script is intentionally diagnostic. It records schemas and sample values
before any selection rule is frozen, preventing us from inferring fix semantics
from a column name or a human/bot label alone.
"""
from __future__ import annotations

import csv
import io
import json
import urllib.request

BASE = "https://raw.githubusercontent.com/piwvh/dependabot-emse/master/data/csv/"
FILES = [
    "security_updates_commits.csv",
    "fixes_commits_times.csv",
    "pr_vulnerabilities.csv",
    "security_advisories_modified.csv",
    "stage_2_second_rater_true.csv",
]


def read_prefix(name: str, max_rows: int = 3):
    req = urllib.request.Request(BASE + name, headers={"User-Agent": "SecFlowOps-EMSE/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        wrapper = io.TextIOWrapper(resp, encoding="utf-8-sig", newline="")
        reader = csv.DictReader(wrapper)
        rows = []
        for row in reader:
            rows.append(row)
            if len(rows) >= max_rows:
                break
        return reader.fieldnames or [], rows


def main() -> int:
    report = {}
    for name in FILES:
        fields, rows = read_prefix(name)
        report[name] = {"fields": fields, "sample": rows}
        print("DATASET", name)
        print("FIELDS", json.dumps(fields))
        print("SAMPLE", json.dumps(rows, ensure_ascii=False)[:6000])
    with open("dependabot_emse_schema.json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
