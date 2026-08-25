from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secflowops.normalizer.common import load_ground_truth, read_jsonl
from secflowops.policy_gate.evaluate_policy import fallback_decision


CANONICAL_CONFIG = {
    "C0_BuildOnly": "BuildOnly",
    "C1_ScanOnly": "ScanOnly",
    "C2_PolicyOnly": "PolicyOnly",
    "C3_RemediationOnly": "RemediationOnly",
    "C4_SecFlowOps": "SecFlowOps",
    "C1_NonBlockingScanning": "ScanOnly",
    "C3_PolicyOnly": "PolicyOnly",
    "C4_AgentsOnly": "RemediationOnly",
    "C5_SecFlowOps": "SecFlowOps",
}
EXCLUDED_CONFIGS = {"C2_AutoScanning"}


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_div(num: float, den: float) -> float | None:
    return num / den if den else None


def scanner_time(metadata: dict[str, Any]) -> float:
    total = 0.0
    for step_name, step in metadata.get("steps", {}).items():
        if "scanners" not in step_name or not isinstance(step, dict):
            continue
        for result in step.values():
            if isinstance(result, dict):
                total += float(result.get("elapsed_seconds") or 0.0)
    return total


def active_tools(metadata: dict[str, Any]) -> set[str]:
    explicit = metadata.get("enabled_tools") or []
    if explicit:
        return {str(x).lower() for x in explicit}
    tools: set[str] = set()
    for step_name, step in metadata.get("steps", {}).items():
        if "scanners" not in step_name or not isinstance(step, dict):
            continue
        tools.update(str(k).lower() for k in step.keys())
    return tools


def ground_truth_for_run(
    ground_truth: list[dict[str, str]], repo: str, tools: set[str]
) -> list[dict[str, str]]:
    rows = [
        row for row in ground_truth
        if (not row.get("repo") or row.get("repo") == repo)
        and row.get("expected_detection", "").lower() == "true"
    ]
    eligible: list[dict[str, str]] = []
    for row in rows:
        expected = {
            t.strip().lower()
            for t in (row.get("tool_expected") or "").replace(",", "|").split("|")
            if t.strip()
        }
        if not expected or expected.intersection(tools):
            eligible.append(row)
    return eligible


def _returncode_ok(value: Any) -> bool:
    if value is None:
        return True
    try:
        return int(value) in (0, 1, 2)
    except (TypeError, ValueError):
        return False


def execution_success(metadata: dict[str, Any]) -> bool:
    if "execution_success" in metadata:
        return bool(metadata["execution_success"])
    build = metadata.get("steps", {}).get("build_test", {})
    if not _returncode_ok(build.get("returncode")):
        return False
    if metadata.get("tool_failures"):
        return False
    for name, step in metadata.get("steps", {}).items():
        if not name.startswith("scanners_") or not isinstance(step, dict):
            continue
        for result in step.values():
            if isinstance(result, dict) and not _returncode_ok(result.get("returncode")):
                return False
    return True


def validation_fields(remediation: dict[str, Any]) -> tuple[bool, str]:
    validation = remediation.get("validation") or remediation.get("tests") or {}
    if "validation_executed" in validation:
        return bool(validation.get("validation_executed")), str(validation.get("validation_status") or "unknown")
    mode = str(validation.get("mode") or "")
    if mode.startswith("skipped") or validation.get("returncode") is None:
        return False, "not_tested"
    return True, "passed" if validation.get("returncode") == 0 else "failed"


def compute_run_metrics(raw_dir: Path, ground_truth: list[dict[str, str]]) -> dict[str, Any] | None:
    metadata = read_json(raw_dir / "metadata.json")
    raw_config = str(metadata.get("configuration"))
    if raw_config in EXCLUDED_CONFIGS:
        return None
    config = CANONICAL_CONFIG.get(raw_config)
    if not config:
        return None

    decision = read_json(raw_dir / "policy_decision.json")
    remediation = read_json(raw_dir / "remediation_log.json")
    initial = read_jsonl(Path(metadata["normalized_findings"]))
    residual = read_jsonl(Path(metadata["residual_findings"]))
    tools = active_tools(metadata)

    eligible_gt = ground_truth_for_run(ground_truth, metadata["repo"], tools)
    eligible_gt_ids = {row.get("finding_id") for row in eligible_gt if row.get("finding_id")}
    initial_gt_ids = {
        f.get("ground_truth_id") for f in initial
        if f.get("ground_truth_id") and f.get("ground_truth_id") in eligible_gt_ids
    }
    residual_gt_ids = {
        f.get("ground_truth_id") for f in residual
        if f.get("ground_truth_id") and f.get("ground_truth_id") in eligible_gt_ids
    }
    gt_recall = safe_div(len(initial_gt_ids), len(eligible_gt_ids))
    gt_removal_rate = safe_div(len(initial_gt_ids - residual_gt_ids), len(initial_gt_ids))

    remediated = [f for f in initial if f.get("remediated")]
    mttr_values: list[float] = []
    for finding in remediated:
        detected_at = parse_time((finding.get("timestamps") or {}).get("detected_at"))
        patched_at = parse_time((finding.get("timestamps") or {}).get("patch_validated_at"))
        if detected_at and patched_at:
            mttr_values.append((patched_at - detected_at).total_seconds())

    pipeline_started = parse_time(metadata.get("started_at"))
    mttd_values: list[float] = []
    for finding in initial:
        detected_at = parse_time((finding.get("timestamps") or {}).get("detected_at"))
        if pipeline_started and detected_at:
            mttd_values.append((detected_at - pipeline_started).total_seconds())

    validation_executed, validation_status = validation_fields(remediation)
    policy_applicable = config in {"PolicyOnly", "SecFlowOps"}
    allow = decision.get("allow") if policy_applicable else None
    release_decision = "ALLOW" if allow is True else "DENY" if allow is False else "NOT_APPLICABLE"

    return {
        "run_id": metadata["run_id"],
        "configuration": config,
        "raw_configuration": raw_config,
        "repo": metadata["repo"],
        "scenario": metadata["scenario"],
        "repetition": metadata["repetition"],
        "campaign_id": metadata.get("campaign_id"),
        "execution_success": execution_success(metadata),
        "release_decision": release_decision,
        "release_allowed": "" if allow is None else bool(allow),
        "pipeline_time_seconds": float(metadata.get("pipeline_time_seconds") or 0.0),
        "scanner_time_seconds": scanner_time(metadata),
        "tool_failure_count": len(metadata.get("tool_failures", [])),
        "finding_count_initial": len(initial),
        "finding_count_residual": len(residual),
        "finding_reduction_fraction": safe_div(max(len(initial) - len(residual), 0), len(initial)),
        "residual_critical": sum(1 for f in residual if str(f.get("severity")).lower() == "critical"),
        "residual_high": sum(1 for f in residual if str(f.get("severity")).lower() == "high"),
        "residual_secret": sum(1 for f in residual if f.get("category") == "secret"),
        "policy_engine": decision.get("engine"),
        "policy_deny_count": len(decision.get("deny", [])),
        "ground_truth_scope_size": len(eligible_gt_ids),
        "ground_truth_detected": len(initial_gt_ids),
        "ground_truth_recall": "" if gt_recall is None else gt_recall,
        "residual_ground_truth_count": "" if not eligible_gt_ids else len(residual_gt_ids),
        "ground_truth_removal_rate": "" if gt_removal_rate is None else gt_removal_rate,
        "remediated_count": int(remediation.get("remediated_count") or 0),
        "validation_executed": validation_executed,
        "validation_status": validation_status,
        "mttd_seconds": statistics.mean(mttd_values) if mttd_values else "",
        "validated_mttr_seconds": statistics.mean(mttr_values) if mttr_values else "",
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
    by_config: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_config.setdefault(row["configuration"], []).append(row)
    summary: list[dict[str, Any]] = []
    for config, values in sorted(by_config.items()):
        release_rows = [v for v in values if v["release_decision"] != "NOT_APPLICABLE"]
        recall_values = [float(v["ground_truth_recall"]) for v in values if v["ground_truth_recall"] != ""]
        summary.append({
            "configuration": config,
            "n_executions": len(values),
            "execution_completion_rate": sum(bool(v["execution_success"]) for v in values) / len(values),
            "release_allow_rate": "" if not release_rows else sum(v["release_decision"] == "ALLOW" for v in release_rows) / len(release_rows),
            "mean_pipeline_time_seconds": statistics.mean(float(v["pipeline_time_seconds"]) for v in values),
            "median_pipeline_time_seconds": statistics.median(float(v["pipeline_time_seconds"]) for v in values),
            "mean_findings_initial": statistics.mean(float(v["finding_count_initial"]) for v in values),
            "mean_findings_residual": statistics.mean(float(v["finding_count_residual"]) for v in values),
            "mean_ground_truth_recall": "" if not recall_values else statistics.mean(recall_values),
        })
    return summary


def policy_sensitivity_rows(raw_dirs: list[Path]) -> list[dict[str, Any]]:
    grid = []
    for high_threshold in [0, 1, 3, 5, 10]:
        for cvss_ceiling in [7.0, 9.0, 10.0]:
            for block_on_secret in [True, False]:
                grid.append({
                    "critical_tolerance": 0,
                    "high_threshold": high_threshold,
                    "cvss_ceiling": cvss_ceiling,
                    "block_on_secret": block_on_secret,
                })

    out: list[dict[str, Any]] = []
    for policy in grid:
        decisions: list[bool] = []
        residual_counts: list[int] = []
        for raw_dir in raw_dirs:
            metadata = read_json(raw_dir / "metadata.json")
            raw_config = str(metadata.get("configuration"))
            if raw_config in EXCLUDED_CONFIGS:
                continue
            config = CANONICAL_CONFIG.get(raw_config)
            if config not in {"PolicyOnly", "SecFlowOps"}:
                continue
            findings = read_jsonl(Path(metadata.get("residual_findings", "")))
            decision = fallback_decision(
                findings,
                tool_failures=metadata.get("tool_failures", []),
                policy=policy,
            )
            decisions.append(bool(decision.get("allow")))
            residual_counts.append(int((decision.get("summary") or {}).get("residual_count", 0)))
        out.append({
            **policy,
            "n_policy_executions": len(decisions),
            "allow_rate": "" if not decisions else sum(decisions) / len(decisions),
            "mean_residual_count": "" if not residual_counts else statistics.mean(residual_counts),
        })
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-run-id", default=None)
    parser.add_argument("--max-run-id", default=None)
    parser.add_argument("--campaign-id-filter", default=None)
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    ground_truth = load_ground_truth(ROOT / "repos" / "ground_truth" / "ground_truth_findings.csv")
    rows: list[dict[str, Any]] = []
    raw_dirs: list[Path] = []
    for raw_dir in sorted((ROOT / "data" / "raw").glob("*")):
        if args.min_run_id and raw_dir.name < args.min_run_id:
            continue
        if args.max_run_id and raw_dir.name > args.max_run_id:
            continue
        required = [raw_dir / "metadata.json", raw_dir / "policy_decision.json", raw_dir / "remediation_log.json"]
        if not all(path.exists() for path in required):
            continue
        metadata = read_json(raw_dir / "metadata.json")
        if args.campaign_id_filter and metadata.get("campaign_id") != args.campaign_id_filter:
            continue
        if str(metadata.get("configuration")) in EXCLUDED_CONFIGS:
            continue
        row = compute_run_metrics(raw_dir, ground_truth)
        if row is not None:
            rows.append(row)
            raw_dirs.append(raw_dir)

    suffix = f"_{args.label}" if args.label else ""
    write_csv(ROOT / "data" / "processed" / f"run_metrics{suffix}.csv", rows)
    write_csv(ROOT / "tables" / f"summary_metrics{suffix}.csv", summarize(rows))
    write_csv(ROOT / "tables" / f"policy_threshold_robustness{suffix}.csv", policy_sensitivity_rows(raw_dirs))
    print(f"processed {len(rows)} final-protocol executions")


if __name__ == "__main__":
    main()
