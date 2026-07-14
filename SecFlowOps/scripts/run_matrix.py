from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import socket
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
from secflowops.agents.remediator_agent import remediate
from secflowops.normalizer.common import read_jsonl, write_json
from secflowops.policy_gate.evaluate_policy import evaluate_policy_file


CONFIGS = [
    "C0_BuildOnly",
    "C1_NonBlockingScanning",
    "C2_AutoScanning",
    "C3_PolicyOnly",
    "C4_AgentsOnly",
    "C5_SecFlowOps",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def scanner_environment() -> dict[str, str]:
    env = os.environ.copy()
    semgrep_home = ROOT / "artifact" / "semgrep_home"
    semgrep_cache = ROOT / "artifact" / "semgrep_cache"
    trivy_cache = ROOT / "artifact" / "trivy_cache"
    semgrep_home.mkdir(parents=True, exist_ok=True)
    semgrep_cache.mkdir(parents=True, exist_ok=True)
    trivy_cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("XDG_CONFIG_HOME", str(semgrep_home))
    env.setdefault("XDG_CACHE_HOME", str(semgrep_cache))
    env.setdefault("SEMGREP_LOG_FILE", str(semgrep_home / "semgrep.log"))
    env.setdefault("SEMGREP_SETTINGS_FILE", str(semgrep_home / "settings.yml"))
    env.setdefault("SEMGREP_VERSION_CACHE_PATH", str(semgrep_cache / "semgrep_version"))
    env.setdefault("TRIVY_CACHE_DIR", str(trivy_cache))
    return env


def resolve_tool(name: str) -> str | None:
    if name == "java":
        for candidate in [
            Path(r"C:\Program Files\Java\jdk-24\bin\java.exe"),
            Path(r"C:\Program Files\Eclipse Adoptium\jre-17.0.19.10-hotspot\bin\java.exe"),
        ]:
            if candidate.exists():
                return str(candidate)
    exe = shutil.which(name)
    if exe:
        return exe
    local_names = {
        "gitleaks": ROOT / "tools" / "gitleaks" / "gitleaks.exe",
    }
    local_exe = local_names.get(name)
    if local_exe and local_exe.exists():
        return str(local_exe)
    return None


def resolve_zap_jar() -> Path | None:
    jar = ROOT / "tools" / "zap" / "ZAP_2.17.0" / "zap-2.17.0.jar"
    return jar if jar.exists() else None


def run_command(
    cmd: list[str],
    *,
    cwd: Path,
    log_path: Path,
    timeout: int = 600,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    line = f"$ {' '.join(cmd)}\n"
    with log_path.open("a", encoding="utf-8") as log:
        log.write(line)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        elapsed = time.perf_counter() - started
        with log_path.open("a", encoding="utf-8") as log:
            log.write(proc.stdout or "")
            log.write(proc.stderr or "")
            log.write(f"\n[returncode={proc.returncode} elapsed={elapsed:.3f}s]\n")
        return {
            "command": cmd,
            "returncode": proc.returncode,
            "elapsed_seconds": elapsed,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except Exception as exc:  # noqa: BLE001 - preserve run failure
        elapsed = time.perf_counter() - started
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"[exception after {elapsed:.3f}s] {exc}\n")
        return {
            "command": cmd,
            "returncode": 999,
            "elapsed_seconds": elapsed,
            "stdout": "",
            "stderr": str(exc),
        }


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


def git_commit_or_local(path: Path | None = None) -> str:
    cwd = path or ROOT.parent
    try:
        proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=cwd, text=True, capture_output=True)
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:
        pass
    return "local"


def build_command_for_workspace(workspace: Path, mode: str) -> tuple[list[str], str]:
    if mode == "skip":
        return ["python", "-c", "print('build skipped by experiment configuration')"], "skipped_by_experiment_configuration"
    if mode == "python_unittest":
        return ["python", "-m", "unittest", "discover", "-s", "tests"], "python_unittest_forced"
    tests_dir = workspace / "tests"
    if tests_dir.exists() and any(tests_dir.rglob("test*.py")):
        return ["python", "-m", "unittest", "discover", "-s", "tests"], "python_unittest"
    return ["python", "-c", "print('no local build command configured')"], "skipped_no_local_test_command"


def port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_zap_scan(workspace: Path, raw_dir: Path, scanner_dir: Path, log_path: Path) -> dict[str, Any]:
    java = resolve_tool("java")
    zap_jar = resolve_zap_jar()
    if not java or not zap_jar:
        return {
            "command": ["zap"],
            "returncode": 999,
            "elapsed_seconds": 0.0,
            "stderr": "java_or_zap_unavailable",
        }
    app = workspace / "app.py"
    if not app.exists():
        return {
            "command": ["zap"],
            "returncode": 998,
            "elapsed_seconds": 0.0,
            "stderr": "no local app.py target for DAST",
        }
    target_port = find_free_port()
    proxy_port = find_free_port()
    app_text = app.read_text(encoding="utf-8")
    patched_text = app_text.replace('("127.0.0.1", 8080)', f'("127.0.0.1", {target_port})')
    if patched_text != app_text:
        app.write_text(patched_text, encoding="utf-8")

    server_log = raw_dir / "zap_target_server.log"
    server_out = server_log.open("w", encoding="utf-8")
    server = subprocess.Popen(
        [sys.executable, "app.py"],
        cwd=workspace,
        stdout=server_out,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.perf_counter() + 10
        while time.perf_counter() < deadline:
            if not port_available(target_port):
                break
            time.sleep(0.2)
        if port_available(target_port):
            return {
                "command": ["zap"],
                "returncode": 996,
                "elapsed_seconds": 0.0,
                "stderr": f"target server did not listen on {target_port}",
            }
        zap_home = raw_dir / "zap_home"
        zap_home.mkdir(parents=True, exist_ok=True)
        zap_out = scanner_dir / "zap.json"
        cmd = [
            java,
            "-jar",
            str(zap_jar),
            "-cmd",
            "-silent",
            "-dir",
            str(zap_home),
            "-port",
            str(proxy_port),
            "-quickurl",
            f"http://127.0.0.1:{target_port}/search?q=secflowops",
            "-quickout",
            str(zap_out),
            "-quickprogress",
        ]
        return run_command(
            cmd,
            cwd=ROOT,
            log_path=log_path,
            timeout=300,
            env=scanner_environment(),
        )
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        server_out.close()


def run_scanners(
    workspace: Path,
    raw_dir: Path,
    log_path: Path,
    *,
    enable_zap: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    scanner_dir = raw_dir / "scanner_outputs"
    scanner_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {}
    failures: list[str] = []

    trivy = resolve_tool("trivy")
    if trivy:
        trivy_out = scanner_dir / "trivy_fs.json"
        cmd = [
            trivy,
            "fs",
            "--skip-version-check",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-check-update",
            "--skip-vex-repo-update",
            "--cache-dir",
            str(ROOT / "artifact" / "trivy_cache"),
            "--scanners",
            "vuln,secret,misconfig",
            "--format",
            "json",
            "--output",
            str(trivy_out),
            str(workspace),
        ]
        result = run_command(cmd, cwd=ROOT.parent, log_path=log_path, timeout=900, env=scanner_environment())
        results["trivy"] = {k: result[k] for k in ("command", "returncode", "elapsed_seconds", "stderr")}
        if result["returncode"] != 0:
            failures.append("trivy")
    else:
        failures.append("trivy:not_available")

    semgrep = resolve_tool("semgrep")
    if semgrep:
        semgrep_out = scanner_dir / "semgrep.json"
        cmd = [
            semgrep,
            "scan",
            "--metrics=off",
            "--disable-version-check",
            "--config",
            str(ROOT / "scanners" / "semgrep" / "secflowops.yml"),
            "--json",
            "--output",
            str(semgrep_out),
            str(workspace),
        ]
        result = run_command(cmd, cwd=ROOT.parent, log_path=log_path, timeout=600, env=scanner_environment())
        results["semgrep"] = {k: result[k] for k in ("command", "returncode", "elapsed_seconds", "stderr")}
        if result["returncode"] not in (0, 1):
            failures.append("semgrep")
    else:
        failures.append("semgrep:not_available")

    gitleaks = resolve_tool("gitleaks")
    if gitleaks:
        gitleaks_out = scanner_dir / "gitleaks.json"
        cmd = [
            gitleaks,
            "detect",
            "--source",
            str(workspace),
            "--config",
            str(ROOT / "scanners" / "gitleaks" / "gitleaks.toml"),
            "--report-format",
            "json",
            "--report-path",
            str(gitleaks_out),
            "--no-git",
        ]
        result = run_command(cmd, cwd=ROOT.parent, log_path=log_path, timeout=600)
        results["gitleaks"] = {k: result[k] for k in ("command", "returncode", "elapsed_seconds", "stderr")}
        if result["returncode"] not in (0, 1):
            failures.append("gitleaks")
    else:
        failures.append("gitleaks:not_available")

    if enable_zap:
        result = run_zap_scan(workspace, raw_dir, scanner_dir, log_path)
        results["zap"] = {k: result[k] for k in ("command", "returncode", "elapsed_seconds", "stderr")}
        if result["returncode"] not in (0, 1, 2):
            failures.append("zap")

    return results, failures


def estimate_coverage(findings_path: Path, *, repo: str) -> float:
    findings = read_jsonl(findings_path)
    matched = {f.get("ground_truth_id") for f in findings if f.get("ground_truth_id")}
    gt_path = ROOT / "repos" / "ground_truth" / "ground_truth_findings.csv"
    with gt_path.open("r", encoding="utf-8", newline="") as f:
        rows = [
            r for r in csv.DictReader(f)
            if r.get("expected_detection", "").lower() == "true"
            and (not r.get("repo") or r.get("repo") == repo)
        ]
    return len(matched) / len(rows) if rows else 0.0


def run_one(
    config: str,
    *,
    repo: str,
    scenario: str,
    repetition: int,
    campaign_id: str | None = None,
    build_mode: str = "auto",
    enable_zap: bool = False,
) -> dict[str, Any]:
    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}_{config}_{repo}_r{repetition}"
    raw_dir = ROOT / "data" / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)
    log_path = raw_dir / "workflow_log.txt"
    workspace = raw_dir / "workspace"
    source_repo = ROOT / "repos" / repo
    copy_workspace(source_repo, workspace)
    if scenario == "auto":
        scenario_file = workspace / "secflowops_scenario.json"
        if scenario_file.exists():
            scenario_data = json.loads(scenario_file.read_text(encoding="utf-8"))
            scenario = scenario_data.get("scenario") or scenario
    source_commit = git_commit_or_local(source_repo if (source_repo / ".git").exists() else None)

    metadata: dict[str, Any] = {
        "run_id": run_id,
        "configuration": config,
        "repo": repo,
        "scenario": scenario,
        "repetition": repetition,
        "campaign_id": campaign_id,
        "commit": source_commit,
        "started_at": utc_now(),
        "host_os": os.name,
        "steps": {},
        "tool_failures": [],
    }

    start = time.perf_counter()
    build_command, resolved_build_mode = build_command_for_workspace(workspace, build_mode)
    build_result = run_command(build_command, cwd=workspace, log_path=log_path)
    metadata["steps"]["build_test"] = {k: build_result[k] for k in ("command", "returncode", "elapsed_seconds", "stderr")}
    metadata["steps"]["build_test"]["mode"] = resolved_build_mode

    normalized_path = ROOT / "data" / "normalized" / f"findings_{run_id}.jsonl"
    residual_path = normalized_path
    remediation_log = raw_dir / "remediation_log.json"
    write_json(remediation_log, {"mode": "not_applicable", "events": [], "remediated_count": 0})

    if config != "C0_BuildOnly":
        scan_results, failures = run_scanners(workspace, raw_dir, log_path, enable_zap=enable_zap)
        metadata["steps"]["scanners_initial"] = scan_results
        metadata["tool_failures"].extend(failures)
        normalize_run(raw_dir, normalized_path, repo=repo, commit=metadata["commit"], run_id=run_id)
    else:
        normalized_path.parent.mkdir(parents=True, exist_ok=True)
        normalized_path.write_text("", encoding="utf-8")

    if config in ("C4_AgentsOnly", "C5_SecFlowOps"):
        remediation_started = time.perf_counter()
        remediation_result = remediate(workspace, normalized_path, remediation_log)
        remediation_elapsed = time.perf_counter() - remediation_started
        metadata["steps"]["remediation"] = {
            "elapsed_seconds": remediation_elapsed,
            "remediated_count": remediation_result.get("remediated_count", 0),
            "tests_returncode": remediation_result.get("tests", {}).get("returncode"),
        }
        # Rescan the patched workspace to produce residual findings.
        post_dir = raw_dir / "post_remediation"
        post_dir.mkdir(parents=True, exist_ok=True)
        post_scan_results, post_failures = run_scanners(workspace, post_dir, log_path, enable_zap=enable_zap)
        metadata["steps"]["scanners_post_remediation"] = post_scan_results
        metadata["tool_failures"].extend([f"post:{f}" for f in post_failures])
        residual_path = ROOT / "data" / "normalized" / f"findings_{run_id}_residual.jsonl"
        normalize_run(post_dir, residual_path, repo=repo, commit=metadata["commit"], run_id=run_id)

    policy_decision_path = raw_dir / "policy_decision.json"
    policy_required = config in ("C3_PolicyOnly", "C5_SecFlowOps")
    if policy_required:
        coverage = estimate_coverage(normalized_path, repo=repo)
        policy_started = time.perf_counter()
        decision = evaluate_policy_file(
            residual_path,
            policy_decision_path,
            coverage=coverage,
            tool_failures=metadata["tool_failures"],
            rego_path=ROOT / "policies" / "rego" / "secflowops.rego",
        )
        metadata["steps"]["policy_gate"] = {
            "elapsed_seconds": time.perf_counter() - policy_started,
            "engine": decision.get("engine"),
            "allow": decision.get("allow"),
            "coverage": coverage,
        }
    else:
        decision = {"engine": "not_applicable", "allow": True, "deny": [], "warn": [], "summary": {}}
        write_json(policy_decision_path, decision)

    elapsed = time.perf_counter() - start
    metadata["finished_at"] = utc_now()
    metadata["pipeline_time_seconds"] = elapsed
    metadata["pipeline_success"] = build_result["returncode"] == 0 and bool(decision.get("allow", True))
    metadata["normalized_findings"] = str(normalized_path)
    metadata["residual_findings"] = str(residual_path)
    metadata["policy_decision"] = str(policy_decision_path)
    metadata["remediation_log"] = str(remediation_log)
    write_json(raw_dir / "metadata.json", metadata)
    write_json(raw_dir / "artifacts_manifest.json", {
        "metadata": str(raw_dir / "metadata.json"),
        "workflow_log": str(log_path),
        "normalized_findings": str(normalized_path),
        "residual_findings": str(residual_path),
        "policy_decision": str(policy_decision_path),
        "remediation_log": str(remediation_log),
    })
    append_manifest(run_id, config, repo, scenario, repetition, metadata["pipeline_success"], raw_dir / "metadata.json")
    return metadata


def append_manifest(run_id: str, config: str, repo: str, scenario: str, repetition: int, success: bool, metadata_path: Path) -> None:
    manifest = ROOT / "experiments" / "raw_logs_manifest.csv"
    with manifest.open("a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([run_id, config, repo, scenario, repetition, "success" if success else "failed", metadata_path, "local"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--repo", default="sample_api")
    parser.add_argument("--repos", nargs="*", default=None)
    parser.add_argument("--scenario", default="controlled_multi_layer")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--configs", nargs="*", default=CONFIGS)
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--build-mode", choices=["auto", "skip", "python_unittest"], default="auto")
    parser.add_argument("--enable-zap", action="store_true", help="Run local OWASP ZAP quick DAST scans against app.py targets.")
    args = parser.parse_args()

    rows = []
    repos = args.repos if args.repos else [args.repo]
    for rep in range(1, args.repetitions + 1):
        for repo in repos:
            for config in args.configs:
                print(f"[RUN] {config} repo={repo} rep={rep}")
                rows.append(run_one(
                    config,
                    repo=repo,
                    scenario=args.scenario,
                    repetition=rep,
                    campaign_id=args.campaign_id,
                    build_mode=args.build_mode,
                    enable_zap=args.enable_zap,
                ))

    print(json.dumps({
        "runs": len(rows),
        "successes": sum(1 for row in rows if row["pipeline_success"]),
        "raw_dir": str(ROOT / "data" / "raw"),
    }, indent=2))


if __name__ == "__main__":
    main()
