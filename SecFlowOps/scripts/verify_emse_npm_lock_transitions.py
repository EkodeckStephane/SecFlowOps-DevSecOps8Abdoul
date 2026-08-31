#!/usr/bin/env python3
"""Verify package-version transitions in npm lockfiles for EMSE trajectories.

The security-update replication package supplies the target package and from/to
versions. For cases with package-lock.json or npm-shrinkwrap.json, this script
reads the lockfile at the resolved pre-fix and post-fix commits and verifies
that the recorded target transition is actually represented in repository
state. This is historical dependency evidence and is kept separate from live
scanner/advisory output.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

FIELDS = [
    "trajectory_id", "repo_slug", "pr_number", "package", "from_version", "to_version",
    "ghsa_ids", "max_severity", "pre_oid", "post_oid", "lockfile_path",
    "pre_versions", "post_versions", "from_present_pre", "to_present_post",
    "transition_verified", "verification_status", "exclusion_reason"
]


def raw_text(repo: str, ref: str, path: str, token: str | None) -> str:
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    url = f"https://raw.githubusercontent.com/{repo}/{ref}/{encoded_path}"
    headers = {"User-Agent": "SecFlowOps-EMSE/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8-sig")


def candidate_lockfiles(changed: str) -> list[str]:
    result = []
    for path in (changed or "").split(";"):
        name = Path(path).name.lower()
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            result.append(path)
    return result


def collect_versions(lock: dict, package: str) -> set[str]:
    versions: set[str] = set()
    packages = lock.get("packages")
    if isinstance(packages, dict):
        suffix = f"node_modules/{package}"
        for key, meta in packages.items():
            if key == suffix or key.endswith("/" + suffix):
                if isinstance(meta, dict) and meta.get("version"):
                    versions.add(str(meta["version"]))
    def walk(node):
        if isinstance(node, dict):
            deps = node.get("dependencies")
            if isinstance(deps, dict):
                meta = deps.get(package)
                if isinstance(meta, dict) and meta.get("version"):
                    versions.add(str(meta["version"]))
                for child in deps.values():
                    walk(child)
    walk(lock)
    return versions


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--min-verified", type=int, default=20)
    ap.add_argument("--min-projects", type=int, default=15)
    args = ap.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    with open(args.input, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r.get("resolution_status") == "resolved"]

    out_rows = []
    for r in rows:
        locks = candidate_lockfiles(r.get("changed_files", ""))
        if not locks:
            out_rows.append({
                **{k: r.get(k, "") for k in FIELDS if k in r},
                "lockfile_path": "", "pre_versions": "", "post_versions": "",
                "from_present_pre": False, "to_present_post": False,
                "transition_verified": False, "verification_status": "excluded",
                "exclusion_reason": "no_npm_lockfile_in_changed_files",
            })
            continue
        verified_record = None
        last_reason = ""
        for lock_path in locks:
            try:
                pre = json.loads(raw_text(r["repo_slug"], r["pre_oid"], lock_path, token))
                post = json.loads(raw_text(r["repo_slug"], r["post_oid"], lock_path, token))
                pre_versions = collect_versions(pre, r["package"])
                post_versions = collect_versions(post, r["package"])
                from_pre = r["from_version"] in pre_versions
                to_post = r["to_version"] in post_versions
                verified = from_pre and to_post
                verified_record = {
                    **{k: r.get(k, "") for k in FIELDS if k in r},
                    "lockfile_path": lock_path,
                    "pre_versions": ";".join(sorted(pre_versions)),
                    "post_versions": ";".join(sorted(post_versions)),
                    "from_present_pre": from_pre,
                    "to_present_post": to_post,
                    "transition_verified": verified,
                    "verification_status": "verified" if verified else "mismatch",
                    "exclusion_reason": "" if verified else "recorded_from_to_not_observed_in_lockfile",
                }
                if verified:
                    break
            except urllib.error.HTTPError as exc:
                last_reason = f"lockfile_http_{exc.code}"
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                last_reason = f"lockfile_parse_{type(exc).__name__}"
        out_rows.append(verified_record or {
            **{k: r.get(k, "") for k in FIELDS if k in r},
            "lockfile_path": locks[0], "pre_versions": "", "post_versions": "",
            "from_present_pre": False, "to_present_post": False,
            "transition_verified": False, "verification_status": "excluded",
            "exclusion_reason": last_reason or "lockfile_unavailable",
        })

    out = Path(args.output); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader(); writer.writerows(out_rows)
    verified = [r for r in out_rows if str(r.get("transition_verified")) == "True" or r.get("transition_verified") is True]
    projects = {r["repo_slug"] for r in verified}
    print({"resolved_pairs": len(rows), "lock_transition_verified": len(verified), "projects": len(projects)})
    if len(verified) < args.min_verified or len(projects) < args.min_projects:
        print("EMSE npm lock-transition gate: FAIL")
        return 2
    print("EMSE npm lock-transition gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
