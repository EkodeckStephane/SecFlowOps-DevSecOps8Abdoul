#!/usr/bin/env python3
"""Resolve actual pre/post commit pairs for merged Dependabot security updates.

The replication dataset provides the merged commit. We query GitHub's commit
graph and use the first parent of that merged commit as the actual immediately
preceding repository state. Resolution is a provenance/screening step; it does
not imply that the project builds or that the update fixes every advisory.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

FIELDS = [
    "trajectory_id", "repo_slug", "pr_number", "package", "from_version", "to_version",
    "ghsa_ids", "max_severity", "pre_oid", "post_oid", "parent_count",
    "recorded_parent_oid", "pr_final_oid", "changed_files", "ecosystem",
    "resolution_status", "exclusion_reason"
]


def api_json(url: str, token: str | None):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "SecFlowOps-EMSE/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def select_diverse(rows: list[dict[str, str]], limit: int) -> list[dict[str, str]]:
    by_repo: dict[str, list[dict[str, str]]] = {}
    for r in rows:
        by_repo.setdefault(r["repo_slug"], []).append(r)
    chosen = [vals[0] for _, vals in sorted(by_repo.items())]
    if len(chosen) >= limit:
        return chosen[:limit]
    used = {r["trajectory_id"] for r in chosen}
    for r in rows:
        if r["trajectory_id"] not in used:
            chosen.append(r); used.add(r["trajectory_id"])
            if len(chosen) >= limit:
                break
    return chosen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--min-resolved", type=int, default=30)
    ap.add_argument("--min-projects", type=int, default=20)
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN")

    with open(args.input, newline="", encoding="utf-8") as fh:
        candidates = [r for r in csv.DictReader(fh) if r.get("candidate_status") == "candidate"]
    selected = select_diverse(candidates, args.limit)
    out_rows = []
    for idx, r in enumerate(selected):
        status, reason, pre_oid, parent_count = "resolved", "", "", 0
        try:
            commit = api_json(
                f"https://api.github.com/repos/{r['repo_slug']}/commits/{r['merged_oid']}", token
            )
            parents = commit.get("parents") or []
            parent_count = len(parents)
            if not parents:
                status, reason = "excluded", "merged_commit_has_no_parent"
            else:
                pre_oid = parents[0]["sha"]
        except urllib.error.HTTPError as exc:
            status, reason = "excluded", f"github_http_{exc.code}"
        except Exception as exc:  # diagnostic screen; reason is retained
            status, reason = "excluded", f"github_error_{type(exc).__name__}"
        out_rows.append({
            "trajectory_id": r["trajectory_id"], "repo_slug": r["repo_slug"],
            "pr_number": r["pr_number"], "package": r["package"],
            "from_version": r["from_version"], "to_version": r["to_version"],
            "ghsa_ids": r["ghsa_ids"], "max_severity": r["max_severity"],
            "pre_oid": pre_oid, "post_oid": r["merged_oid"], "parent_count": parent_count,
            "recorded_parent_oid": r["recorded_parent_oid"], "pr_final_oid": r["pr_final_oid"],
            "changed_files": r["changed_files"], "ecosystem": r["ecosystem"],
            "resolution_status": status, "exclusion_reason": reason,
        })
        if idx and idx % 25 == 0: time.sleep(0.2)

    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS); writer.writeheader(); writer.writerows(out_rows)
    resolved = [r for r in out_rows if r["resolution_status"] == "resolved"]
    projects = {r["repo_slug"] for r in resolved}
    print({"selected": len(selected), "resolved": len(resolved), "projects": len(projects)})
    if len(resolved) < args.min_resolved or len(projects) < args.min_projects:
        print("EMSE npm commit-resolution gate: FAIL")
        return 2
    print("EMSE npm commit-resolution gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
