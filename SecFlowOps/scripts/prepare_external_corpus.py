from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOS = ROOT / "repos"


EXTERNAL_REPOS = [
    {
        "repo_id": "external_requests",
        "url": "https://github.com/psf/requests.git",
        "origin_type": "external_oss_library",
        "stack": "python;pip",
        "notes": "Popular Python HTTP library.",
    },
    {
        "repo_id": "external_flask",
        "url": "https://github.com/pallets/flask.git",
        "origin_type": "external_oss_framework",
        "stack": "python;pip",
        "notes": "Popular Python web framework.",
    },
    {
        "repo_id": "external_express",
        "url": "https://github.com/expressjs/express.git",
        "origin_type": "external_oss_framework",
        "stack": "javascript;npm",
        "notes": "Popular Node.js web framework.",
    },
    {
        "repo_id": "external_nodegoat",
        "url": "https://github.com/OWASP/NodeGoat.git",
        "origin_type": "external_security_benchmark",
        "stack": "javascript;npm;docker",
        "notes": "OWASP intentionally vulnerable Node.js benchmark.",
    },
    {
        "repo_id": "external_dvna",
        "url": "https://github.com/appsecco/dvna.git",
        "origin_type": "external_security_benchmark",
        "stack": "javascript;npm;docker",
        "notes": "Damn Vulnerable NodeJS Application benchmark.",
    },
]


def run_git(args: list[str], *, cwd: Path | None = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
    )


def ensure_repo(entry: dict[str, str], *, refresh: bool) -> Path:
    target = REPOS / entry["repo_id"]
    if target.exists() and refresh:
        resolved_repos = REPOS.resolve()
        resolved_target = target.resolve()
        if resolved_repos not in resolved_target.parents or not target.name.startswith("external_"):
            raise RuntimeError(f"Refusing to delete unexpected path: {target}")
        shutil.rmtree(target)
    if not target.exists():
        last_error = ""
        for attempt in range(1, 4):
            proc = run_git(["clone", "--depth", "1", entry["url"], str(target)], timeout=900)
            if proc.returncode == 0:
                break
            last_error = proc.stderr
            if target.exists():
                shutil.rmtree(target)
            time.sleep(5 * attempt)
        else:
            raise RuntimeError(f"git clone failed for {entry['repo_id']}: {last_error}")
    return target


def git_value(repo: Path, args: list[str]) -> str:
    proc = run_git(args, cwd=repo, timeout=120)
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def count_files_and_loc(repo: Path) -> tuple[int, int]:
    files = [
        path for path in repo.rglob("*")
        if path.is_file() and ".git" not in path.parts
    ]
    loc = 0
    for path in files:
        try:
            loc += len(path.read_text(encoding="utf-8").splitlines())
        except UnicodeDecodeError:
            pass
    return len(files), loc


def write_manifest(rows: list[dict[str, str]]) -> None:
    path = ROOT / "experiments" / "external_corpus_manifest.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "repo_id",
        "url",
        "origin_type",
        "stack",
        "commit",
        "branch",
        "captured_at_utc",
        "file_count",
        "loc",
        "ground_truth_status",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_design_matrix(repo_ids: list[str], repetitions: int) -> None:
    path = ROOT / "experiments" / "external_design_matrix.csv"
    configs = [
        "C1_NonBlockingScanning",
        "C2_AutoScanning",
        "C3_PolicyOnly",
        "C4_AgentsOnly",
        "C5_SecFlowOps",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["configuration", "repo_id", "scenario", "planned_repetitions", "primary_metrics"])
        for repo_id in repo_ids:
            for config in configs:
                writer.writerow([
                    config,
                    repo_id,
                    "external_open_source",
                    repetitions,
                    "pipeline_time_seconds;scanner_time_seconds;finding_count_initial;residual_critical;residual_high;residual_secret;policy_allow",
                ])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()

    rows = []
    repo_ids = []
    captured_at = datetime.now(timezone.utc).isoformat()
    for entry in EXTERNAL_REPOS:
        repo = ensure_repo(entry, refresh=args.refresh)
        commit = git_value(repo, ["rev-parse", "HEAD"])
        branch = git_value(repo, ["branch", "--show-current"])
        file_count, loc = count_files_and_loc(repo)
        repo_ids.append(entry["repo_id"])
        rows.append({
            "repo_id": entry["repo_id"],
            "url": entry["url"],
            "origin_type": entry["origin_type"],
            "stack": entry["stack"],
            "commit": commit,
            "branch": branch,
            "captured_at_utc": captured_at,
            "file_count": str(file_count),
            "loc": str(loc),
            "ground_truth_status": "no_complete_external_ground_truth",
            "notes": entry["notes"],
        })

    write_manifest(rows)
    write_design_matrix(repo_ids, args.repetitions)
    print(f"prepared {len(repo_ids)} external repositories")
    print(" ".join(repo_ids))


if __name__ == "__main__":
    main()
