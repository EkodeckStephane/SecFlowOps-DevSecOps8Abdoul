from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.normalize_findings import normalize_run
from scripts.run_matrix import copy_workspace, git_commit_or_local, run_scanners
from secflowops.normalizer.common import read_jsonl, write_json


def utc_run_id(config: str, repo: str, repetition: int) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{stamp}_{config}_{repo}_r{repetition}"


def run_npm_audit_fix(workspace: Path, log_path: Path) -> dict[str, Any]:
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    package_lock = workspace / "package-lock.json"
    package_json = workspace / "package.json"
    if not npm or not package_lock.exists() or not package_json.exists():
        return {
            "attempted": False,
            "changed": False,
            "returncode": None,
            "elapsed_seconds": 0.0,
            "reason": "npm_or_package_files_unavailable",
        }

    before = package_lock.read_text(encoding="utf-8", errors="replace")
    env = os.environ.copy()
    env.setdefault("npm_config_cache", str(workspace / ".npm-cache"))
    started = time.perf_counter()
    proc = subprocess.run(
        [npm, "audit", "fix", "--package-lock-only", "--omit=dev"],
        cwd=workspace,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=900,
        env=env,
    )
    elapsed = time.perf_counter() - started
    after = package_lock.read_text(encoding="utf-8", errors="replace")
    with log_path.open("a", encoding="utf-8") as log:
        log.write("$ npm audit fix --package-lock-only --omit=dev\n")
        log.write(proc.stdout or "")
        log.write(proc.stderr or "")
        log.write(f"\n[returncode={proc.returncode} elapsed={elapsed:.3f}s]\n")
    return {
        "attempted": True,
        "changed": before != after,
        "returncode": proc.returncode,
        "elapsed_seconds": elapsed,
        "stdout_tail": (proc.stdout or "")[-4000:],
        "stderr_tail": (proc.stderr or "")[-4000:],
        "note": "Non-zero return codes are expected when residual advisories remain.",
    }


def count_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(findings),
        "critical": sum(1 for f in findings if str(f.get("severity")).lower() == "critical"),
        "high": sum(1 for f in findings if str(f.get("severity")).lower() == "high"),
        "secret": sum(1 for f in findings if f.get("category") == "secret"),
        "sca": sum(1 for f in findings if f.get("category") == "sca"),
        "iac": sum(1 for f in findings if f.get("category") == "iac"),
    }


def run_one(repo: str, repetition: int, campaign_id: str) -> dict[str, Any]:
    config = "B1_NpmAuditOnly"
    run_id = utc_run_id(config, repo, repetition)
    raw_dir = ROOT / "data" / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    workspace = raw_dir / "workspace"
    log_path = raw_dir / "workflow_log.txt"
    source_repo = ROOT / "repos" / repo
    copy_workspace(source_repo, workspace)
    commit = git_commit_or_local(source_repo if (source_repo / ".git").exists() else None)

    started = time.perf_counter()
    initial_scan, initial_failures = run_scanners(workspace, raw_dir, log_path)
    initial_path = ROOT / "data" / "normalized" / f"findings_{run_id}.jsonl"
    normalize_run(raw_dir, initial_path, repo=repo, commit=commit, run_id=run_id)

    npm_result = run_npm_audit_fix(workspace, log_path)

    post_dir = raw_dir / "post_npm_audit"
    post_dir.mkdir(parents=True, exist_ok=True)
    post_scan, post_failures = run_scanners(workspace, post_dir, log_path)
    residual_path = ROOT / "data" / "normalized" / f"findings_{run_id}_residual.jsonl"
    normalize_run(post_dir, residual_path, repo=repo, commit=commit, run_id=run_id)

    initial = read_jsonl(initial_path)
    residual = read_jsonl(residual_path)
    initial_counts = count_findings(initial)
    residual_counts = count_findings(residual)
    elapsed = time.perf_counter() - started

    metadata = {
        "run_id": run_id,
        "configuration": config,
        "repo": repo,
        "scenario": "npm_audit_only_baseline",
        "repetition": repetition,
        "campaign_id": campaign_id,
        "commit": commit,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pipeline_time_seconds": elapsed,
        "pipeline_success": True,
        "tool_failures": [*initial_failures, *[f"post:{f}" for f in post_failures]],
        "normalized_findings": str(initial_path),
        "residual_findings": str(residual_path),
        "steps": {
            "scanners_initial": initial_scan,
            "npm_audit_fix": npm_result,
            "scanners_post_remediation": post_scan,
        },
    }
    write_json(raw_dir / "metadata.json", metadata)
    write_json(raw_dir / "npm_audit_only_result.json", {
        "run_id": run_id,
        "campaign_id": campaign_id,
        "initial": initial_counts,
        "residual": residual_counts,
        "resolved_total": initial_counts["total"] - residual_counts["total"],
        "resolved_critical": initial_counts["critical"] - residual_counts["critical"],
        "resolved_high": initial_counts["high"] - residual_counts["high"],
        "resolved_secret": initial_counts["secret"] - residual_counts["secret"],
        "npm_audit_fix": npm_result,
        "pipeline_time_seconds": elapsed,
    })
    return {
        "run_id": run_id,
        "campaign_id": campaign_id,
        "configuration": config,
        "repo": repo,
        "repetition": repetition,
        "pipeline_time_seconds": elapsed,
        "npm_audit_seconds": npm_result["elapsed_seconds"],
        "npm_returncode": npm_result["returncode"],
        "npm_changed_lockfile": npm_result["changed"],
        "initial_total": initial_counts["total"],
        "initial_critical": initial_counts["critical"],
        "initial_high": initial_counts["high"],
        "initial_secret": initial_counts["secret"],
        "residual_total": residual_counts["total"],
        "residual_critical": residual_counts["critical"],
        "residual_high": residual_counts["high"],
        "residual_secret": residual_counts["secret"],
        "resolved_total": initial_counts["total"] - residual_counts["total"],
        "resolved_critical": initial_counts["critical"] - residual_counts["critical"],
        "resolved_high": initial_counts["high"] - residual_counts["high"],
        "resolved_secret": initial_counts["secret"] - residual_counts["secret"],
        "tool_failure_count": len(metadata["tool_failures"]),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    metrics = [
        "pipeline_time_seconds",
        "npm_audit_seconds",
        "initial_total",
        "initial_critical",
        "initial_high",
        "initial_secret",
        "residual_total",
        "residual_critical",
        "residual_high",
        "residual_secret",
        "resolved_total",
        "resolved_critical",
        "resolved_high",
        "resolved_secret",
        "tool_failure_count",
    ]
    out = {"configuration": "B1_NpmAuditOnly", "repo": rows[0]["repo"], "n_runs": len(rows)}
    for metric in metrics:
        values = [float(row[metric] or 0.0) for row in rows]
        out[f"mean_{metric}"] = sum(values) / len(values)
    return [out]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="external_nodegoat")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--campaign-id", default="npm_audit_only_manual")
    args = parser.parse_args()

    rows = [run_one(args.repo, rep, args.campaign_id) for rep in range(1, args.repetitions + 1)]
    write_csv(ROOT / "data" / "processed" / "npm_audit_only_runs.csv", rows)
    write_csv(ROOT / "tables" / "npm_audit_only_baseline.csv", summarize(rows))
    print(json.dumps({"runs": len(rows), "output": str(ROOT / "tables" / "npm_audit_only_baseline.csv")}, indent=2))


if __name__ == "__main__":
    main()
