from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from secflowops.normalizer.common import read_jsonl, write_json


DEFAULT_POLICY = {
    "critical_tolerance": 0,
    "high_threshold": 3,
    "cvss_ceiling": 9.0,
    "block_on_secret": True,
    "min_coverage": 0.80,
}


def _max_cvss(findings: list[dict[str, Any]]) -> float:
    values = [float(f.get("cvss") or 0.0) for f in findings if not f.get("remediated")]
    return max(values) if values else 0.0


def fallback_decision(
    findings: list[dict[str, Any]],
    *,
    coverage: float,
    tool_failures: list[str],
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    policy = {**DEFAULT_POLICY, **(policy or {})}
    residual = [f for f in findings if not f.get("remediated")]
    critical_count = sum(1 for f in residual if str(f.get("severity")).lower() == "critical")
    high_count = sum(1 for f in residual if str(f.get("severity")).lower() == "high")
    secret_count = sum(1 for f in residual if f.get("category") == "secret")
    max_cvss = _max_cvss(findings)
    deny = []
    warn = []

    if critical_count > int(policy["critical_tolerance"]):
        deny.append(f"residual critical findings: {critical_count} > tolerance {policy['critical_tolerance']}")
    if high_count > int(policy["high_threshold"]):
        deny.append(f"residual high findings: {high_count} > threshold {policy['high_threshold']}")
    if max_cvss > float(policy["cvss_ceiling"]):
        deny.append(f"max residual CVSS {max_cvss:.1f} > ceiling {float(policy['cvss_ceiling']):.1f}")
    if policy.get("block_on_secret", True) and secret_count > 0:
        deny.append(f"residual secret findings: {secret_count}")
    if coverage < float(policy["min_coverage"]):
        warn.append(f"coverage {coverage:.3f} < threshold {float(policy['min_coverage']):.3f}")
    for failure in tool_failures:
        warn.append(f"tool failure: {failure}")

    return {
        "engine": "python_fallback",
        "allow": len(deny) == 0,
        "deny": deny,
        "warn": warn,
        "summary": {
            "critical_count": critical_count,
            "high_count": high_count,
            "secret_count": secret_count,
            "max_cvss": max_cvss,
            "residual_count": len(residual),
        },
        "policy": policy,
    }


def evaluate_with_opa(
    findings: list[dict[str, Any]],
    *,
    coverage: float,
    tool_failures: list[str],
    rego_path: Path,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    opa = shutil.which("opa")
    if not opa:
        local_opa = rego_path.parents[2] / "tools" / "opa.exe"
        if local_opa.exists():
            opa = str(local_opa)
    if not opa:
        return None

    payload = {
        "findings": findings,
        "coverage": coverage,
        "tool_failures": tool_failures,
        "policy": {**DEFAULT_POLICY, **(policy or {})},
    }
    with tempfile.TemporaryDirectory() as tmp:
        input_path = Path(tmp) / "input.json"
        input_path.write_text(json.dumps(payload), encoding="utf-8")
        cmd = [
            opa,
            "eval",
            "--format",
            "json",
            "--data",
            str(rego_path),
            "--input",
            str(input_path),
            "data.secflowops.decision",
        ]
        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.returncode != 0:
            return {
                "engine": "opa",
                "allow": False,
                "deny": [f"opa eval failed: {proc.stderr.strip()}"],
                "warn": [],
                "summary": {},
                "policy": payload["policy"],
            }
        data = json.loads(proc.stdout)
        result = data["result"][0]["expressions"][0]["value"]
        result["engine"] = "opa"
        result["policy"] = payload["policy"]
        return result


def evaluate_policy_file(
    findings_path: Path,
    output_path: Path,
    *,
    coverage: float,
    tool_failures: list[str] | None = None,
    rego_path: Path | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings = read_jsonl(findings_path)
    root = Path(__file__).resolve().parents[2]
    rego_path = rego_path or root / "policies" / "rego" / "secflowops.rego"
    tool_failures = tool_failures or []
    decision = evaluate_with_opa(
        findings,
        coverage=coverage,
        tool_failures=tool_failures,
        rego_path=rego_path,
        policy=policy,
    )
    if decision is None:
        decision = fallback_decision(findings, coverage=coverage, tool_failures=tool_failures, policy=policy)
    write_json(output_path, decision)
    return decision


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--coverage", type=float, default=0.0)
    args = parser.parse_args()
    evaluate_policy_file(Path(args.findings), Path(args.output), coverage=args.coverage)


if __name__ == "__main__":
    main()
