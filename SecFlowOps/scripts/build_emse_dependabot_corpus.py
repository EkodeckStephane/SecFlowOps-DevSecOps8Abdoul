#!/usr/bin/env python3
"""Build a reproducible npm security-update candidate corpus from the
replication package of Mohayeji et al., Empirical Software Engineering (2025).

Only merged PRs with an explicit merge commit and linked vulnerability record
are retained as candidates. The actual pre-fix parent is resolved separately
from GitHub's commit graph before execution; `parent_oid` is retained as the
replication dataset's recorded base state for provenance.
"""
from __future__ import annotations

import argparse
import ast
import csv
import io
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/piwvh/dependabot-emse/master/data/csv/"
COMMITS = BASE + "security_updates_commits.csv"
VULNS = BASE + "pr_vulnerabilities.csv"
OUT_FIELDS = [
    "trajectory_id", "source_dataset", "repo_slug", "pr_number", "pr_url",
    "package", "from_version", "to_version", "ghsa_ids", "severities",
    "max_severity", "recorded_parent_oid", "pr_commit_oid", "pr_final_oid",
    "merged_oid", "rebased", "changed_files", "ecosystem",
    "candidate_status", "exclusion_reason"
]


def open_csv(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "SecFlowOps-EMSE/1.0"})
    resp = urllib.request.urlopen(req, timeout=180)
    wrapper = io.TextIOWrapper(resp, encoding="utf-8-sig", newline="")
    return resp, wrapper, csv.DictReader(wrapper)


def safe_list(value: str) -> list[str]:
    if not value:
        return []
    try:
        parsed = ast.literal_eval(value)
        return [str(x) for x in parsed] if isinstance(parsed, (list, tuple)) else [str(parsed)]
    except (ValueError, SyntaxError):
        return [value]


def load_vulnerabilities() -> dict[tuple[str, str], dict[str, str]]:
    resp, wrapper, reader = open_csv(VULNS)
    try:
        return {(r["repository"].strip(), r["number"].strip()): r for r in reader}
    finally:
        wrapper.close(); resp.close()


def is_manifest_update(files: list[str]) -> bool:
    names = {Path(f).name.lower() for f in files}
    return bool(names & {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="SecFlowOps/data/emse/dependabot_security_updates.csv")
    ap.add_argument("--min-cases", type=int, default=50)
    ap.add_argument("--min-projects", type=int, default=20)
    args = ap.parse_args()

    vulns = load_vulnerabilities()
    resp, wrapper, reader = open_csv(COMMITS)
    rows = []
    seen = set()
    try:
        for src in reader:
            repo = (src.get("repository") or "").strip()
            num = (src.get("number") or "").strip()
            key = (repo, num)
            if key in seen:
                continue
            seen.add(key)
            vuln = vulns.get(key)
            files = safe_list(src.get("files") or "")
            ghsa = safe_list((vuln or {}).get("vulnerabilities") or "")
            severities = safe_list((vuln or {}).get("severities") or "")
            reasons = []
            if (src.get("state") or "").upper() != "MERGED": reasons.append("not_merged")
            if not (src.get("merged_oid") or "").strip(): reasons.append("missing_merged_oid")
            if vuln is None: reasons.append("missing_vulnerability_record")
            if not ghsa: reasons.append("missing_ghsa")
            if not is_manifest_update(files): reasons.append("no_manifest_or_lockfile_change")
            status = "candidate" if not reasons else "excluded"
            row = {
                "trajectory_id": f"dependabot::{repo}#{num}",
                "source_dataset": "Mohayeji-et-al-EMSE-2025",
                "repo_slug": repo,
                "pr_number": num,
                "pr_url": (src.get("url") or "").strip(),
                "package": ((vuln or {}).get("package") or "").strip(),
                "from_version": ((vuln or {}).get("from") or "").strip(),
                "to_version": ((vuln or {}).get("to") or "").strip(),
                "ghsa_ids": ";".join(ghsa),
                "severities": ";".join(severities),
                "max_severity": ((vuln or {}).get("maximal_severity") or "").strip(),
                "recorded_parent_oid": (src.get("parent_oid") or "").strip(),
                "pr_commit_oid": (src.get("commit_oid") or "").strip(),
                "pr_final_oid": (src.get("final_oid") or "").strip(),
                "merged_oid": (src.get("merged_oid") or "").strip(),
                "rebased": (src.get("rebased") or "").strip(),
                "changed_files": ";".join(files),
                "ecosystem": "npm/javascript",
                "candidate_status": status,
                "exclusion_reason": ";".join(reasons),
            }
            rows.append(row)
    finally:
        wrapper.close(); resp.close()

    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=OUT_FIELDS)
        writer.writeheader(); writer.writerows(rows)
    kept = [r for r in rows if r["candidate_status"] == "candidate"]
    projects = {r["repo_slug"] for r in kept}
    print({"all_unique_prs": len(rows), "candidates": len(kept), "projects": len(projects)})
    if len(kept) < args.min_cases or len(projects) < args.min_projects:
        print("EMSE Dependabot corpus gate: FAIL")
        return 2
    print("EMSE Dependabot corpus gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
