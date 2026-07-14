from __future__ import annotations

import argparse
import csv
import shlex
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

from scripts.run_matrix import run_one


DEFAULT_PLAN = ROOT / "experiments" / "extended_external_build_test_plan.csv"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def split_command(command: str) -> list[str]:
    if sys.platform.startswith("win"):
        return shlex.split(command, posix=False)
    return shlex.split(command)


def copy_workspace(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".venv",
            "venv",
            "node_modules",
            "dist",
            "build",
        ),
    )


def run_command(command: str, cwd: Path, timeout: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            split_command(command),
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - started
        return {
            "command": command,
            "returncode": proc.returncode,
            "elapsed_seconds": elapsed,
            "stdout_tail": (proc.stdout or "")[-2000:],
            "stderr_tail": (proc.stderr or "")[-2000:],
        }
    except Exception as exc:  # noqa: BLE001 - preserve execution failure
        elapsed = time.perf_counter() - started
        return {
            "command": command,
            "returncode": 999,
            "elapsed_seconds": elapsed,
            "stdout_tail": "",
            "stderr_tail": str(exc),
        }


def choose_command(row: dict[str, str], *, fallback: bool) -> tuple[str, str]:
    if fallback:
        return row["fallback_check_command"], "fallback_check"
    return row["native_test_command"], "native_test"


def baseline_check(repo_id: str, command: str, mode: str, campaign_id: str, timeout: int) -> dict[str, Any]:
    source = ROOT / "repos" / repo_id
    workspace = ROOT / "data" / "regression_workspaces" / campaign_id / f"{repo_id}_baseline"
    copy_workspace(source, workspace)
    result = run_command(command, workspace, timeout)
    return {
        "campaign_id": campaign_id,
        "repo": repo_id,
        "phase": "before_remediation",
        "test_mode": mode,
        "run_id": "",
        "remediated_count": "",
        "started_at": utc_now(),
        **result,
    }


def post_remediation_check(repo_id: str, command: str, mode: str, campaign_id: str, timeout: int) -> dict[str, Any]:
    metadata = run_one(
        "C4_AgentsOnly",
        repo=repo_id,
        scenario="external_regression_validation",
        repetition=1,
        campaign_id=campaign_id,
        build_mode="skip",
        enable_zap=False,
    )
    raw_dir = ROOT / "data" / "raw" / metadata["run_id"]
    workspace = raw_dir / "workspace"
    result = run_command(command, workspace, timeout)
    remediation_count = metadata.get("steps", {}).get("remediation", {}).get("remediated_count", 0)
    return {
        "campaign_id": campaign_id,
        "repo": repo_id,
        "phase": "after_secflowops_remediation_workspace",
        "test_mode": mode,
        "run_id": metadata["run_id"],
        "remediated_count": remediation_count,
        "started_at": utc_now(),
        **result,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--campaign-id", default=f"regression_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    parser.add_argument("--repos", nargs="*", default=None)
    parser.add_argument("--fallback", action="store_true", help="Use fallback syntax/build checks instead of native tests.")
    parser.add_argument("--post-remediation", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--output-label", default="extended_external")
    args = parser.parse_args()

    plan_rows = read_csv(Path(args.plan))
    if args.repos:
        selected = [row for row in plan_rows if row["repo_id"] in set(args.repos)]
    else:
        selected = plan_rows
    rows: list[dict[str, Any]] = []
    for row in selected:
        command, mode = choose_command(row, fallback=args.fallback)
        rows.append(baseline_check(row["repo_id"], command, mode, args.campaign_id, args.timeout))
        if args.post_remediation:
            rows.append(post_remediation_check(row["repo_id"], command, mode, args.campaign_id, args.timeout))

    output = ROOT / "data" / "processed" / f"application_regression_checks_{args.output_label}.csv"
    write_csv(output, rows)
    print(f"wrote {len(rows)} regression check rows to {output}")


if __name__ == "__main__":
    main()
