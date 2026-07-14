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


EXTENDED_EXTERNAL_REPOS = [
    {
        "repo_id": "external_requests",
        "url": "https://github.com/psf/requests.git",
        "origin_type": "external_oss_library",
        "stack": "python;pip",
        "native_test_command": "python -m pytest -q",
        "fallback_check_command": "python -m compileall src tests",
        "notes": "Popular Python HTTP library; existing SecFlowOps external corpus member.",
    },
    {
        "repo_id": "external_flask",
        "url": "https://github.com/pallets/flask.git",
        "origin_type": "external_oss_framework",
        "stack": "python;pip",
        "native_test_command": "python -m pytest -q",
        "fallback_check_command": "python -m compileall src tests",
        "notes": "Popular Python web framework; existing SecFlowOps external corpus member.",
    },
    {
        "repo_id": "external_click",
        "url": "https://github.com/pallets/click.git",
        "origin_type": "external_oss_library",
        "stack": "python;pip",
        "native_test_command": "python -m pytest -q",
        "fallback_check_command": "python -m compileall src tests",
        "notes": "Python command-line framework from the Pallets ecosystem.",
    },
    {
        "repo_id": "external_itsdangerous",
        "url": "https://github.com/pallets/itsdangerous.git",
        "origin_type": "external_oss_library",
        "stack": "python;pip",
        "native_test_command": "python -m pytest -q",
        "fallback_check_command": "python -m compileall src tests",
        "notes": "Python signing helper from the Pallets ecosystem.",
    },
    {
        "repo_id": "external_express",
        "url": "https://github.com/expressjs/express.git",
        "origin_type": "external_oss_framework",
        "stack": "javascript;npm",
        "native_test_command": "npm.cmd test",
        "fallback_check_command": "node -c index.js",
        "notes": "Popular Node.js web framework; existing SecFlowOps external corpus member.",
    },
    {
        "repo_id": "external_body_parser",
        "url": "https://github.com/expressjs/body-parser.git",
        "origin_type": "external_oss_middleware",
        "stack": "javascript;npm",
        "native_test_command": "npm.cmd test",
        "fallback_check_command": "node -c index.js",
        "notes": "Express middleware package.",
    },
    {
        "repo_id": "external_morgan",
        "url": "https://github.com/expressjs/morgan.git",
        "origin_type": "external_oss_middleware",
        "stack": "javascript;npm",
        "native_test_command": "npm.cmd test",
        "fallback_check_command": "node -c index.js",
        "notes": "Express HTTP request logger middleware.",
    },
    {
        "repo_id": "external_nodegoat",
        "url": "https://github.com/OWASP/NodeGoat.git",
        "origin_type": "external_security_benchmark",
        "stack": "javascript;npm;docker",
        "native_test_command": "npm.cmd test",
        "fallback_check_command": "node -c server.js",
        "notes": "OWASP intentionally vulnerable Node.js benchmark; existing SecFlowOps external corpus member.",
    },
    {
        "repo_id": "external_dvna",
        "url": "https://github.com/appsecco/dvna.git",
        "origin_type": "external_security_benchmark",
        "stack": "javascript;npm;docker",
        "native_test_command": "npm.cmd test",
        "fallback_check_command": "node -c server.js",
        "notes": "Damn Vulnerable NodeJS Application benchmark; existing SecFlowOps external corpus member.",
    },
    {
        "repo_id": "external_gorilla_mux",
        "url": "https://github.com/gorilla/mux.git",
        "origin_type": "external_oss_library",
        "stack": "go",
        "native_test_command": "go test ./...",
        "fallback_check_command": "go test ./...",
        "notes": "Go HTTP router library.",
    },
    {
        "repo_id": "external_gorilla_websocket",
        "url": "https://github.com/gorilla/websocket.git",
        "origin_type": "external_oss_library",
        "stack": "go",
        "native_test_command": "go test ./...",
        "fallback_check_command": "go test ./...",
        "notes": "Go WebSocket library.",
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


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="Optional first-N subset for pilot runs.")
    args = parser.parse_args()

    selected = EXTENDED_EXTERNAL_REPOS[: args.limit] if args.limit else EXTENDED_EXTERNAL_REPOS
    captured_at = datetime.now(timezone.utc).isoformat()
    manifest_rows: list[dict[str, str]] = []
    build_rows: list[dict[str, str]] = []
    for entry in selected:
        repo = ensure_repo(entry, refresh=args.refresh)
        commit = git_value(repo, ["rev-parse", "HEAD"])
        branch = git_value(repo, ["branch", "--show-current"])
        file_count, loc = count_files_and_loc(repo)
        manifest_rows.append({
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
        build_rows.append({
            "repo_id": entry["repo_id"],
            "stack": entry["stack"],
            "native_test_command": entry["native_test_command"],
            "fallback_check_command": entry["fallback_check_command"],
            "requires_project_dependencies": "true",
            "planned_use": "native_before_after_when_executable;fallback_records_environment_limit",
        })

    write_csv(ROOT / "experiments" / "extended_external_corpus_manifest.csv", manifest_rows)
    write_csv(ROOT / "experiments" / "extended_external_build_test_plan.csv", build_rows)
    print(f"prepared {len(manifest_rows)} extended external repositories")
    print(" ".join(row["repo_id"] for row in manifest_rows))


if __name__ == "__main__":
    main()
