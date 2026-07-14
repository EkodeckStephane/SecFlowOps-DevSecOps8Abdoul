from __future__ import annotations

import csv
import argparse
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


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def scanner_time(metadata: dict[str, Any]) -> float:
    total = 0.0
    for step_name, step in metadata.get("steps", {}).items():
        if "scanners" not in step_name:
            continue
        for result in step.values():
            total += float(result.get("elapsed_seconds") or 0.0)
    return total


def ground_truth_for_repo(ground_truth: list[dict[str, str]], repo: str) -> list[dict[str, str]]:
    return [row for row in ground_truth if not row.get("repo") or row.get("repo") == repo]


def compute_run_metrics(raw_dir: Path, ground_truth: list[dict[str, str]]) -> dict[str, Any]:
    metadata = read_json(raw_dir / "metadata.json")
    decision = read_json(raw_dir / "policy_decision.json")
    remediation = read_json(raw_dir / "remediation_log.json")
    initial = read_jsonl(Path(metadata["normalized_findings"]))
    residual = read_jsonl(Path(metadata["residual_findings"]))
    findings_for_quality = initial if initial else residual
    residual_active = [f for f in residual if not f.get("remediated")]

    repo_ground_truth = ground_truth_for_repo(ground_truth, metadata["repo"])
    expected_gt = [row for row in repo_ground_truth if row.get("expected_detection", "").lower() == "true"]
    detected_gt_ids = {f.get("ground_truth_id") for f in findings_for_quality if f.get("ground_truth_id")}
    tp = len(detected_gt_ids)
    fp = sum(1 for f in findings_for_quality if f.get("is_false_positive") is True)
    unknown = sum(1 for f in findings_for_quality if f.get("ground_truth_id") is None)
    fn = max(len(expected_gt) - tp, 0)
    precision = safe_div(tp, tp + fp + unknown)
    recall = safe_div(tp, len(expected_gt))

    remediated = [f for f in initial if f.get("remediated")]
    mttr_values = []
    for finding in remediated:
        detected_at = parse_time(finding.get("timestamps", {}).get("detected_at"))
        patched_at = parse_time(finding.get("timestamps", {}).get("patch_validated_at"))
        if detected_at and patched_at:
            mttr_values.append((patched_at - detected_at).total_seconds())

    pipeline_started = parse_time(metadata.get("started_at"))
    mttd_values = []
    for finding in findings_for_quality:
        detected_at = parse_time(finding.get("timestamps", {}).get("detected_at"))
        if pipeline_started and detected_at:
            mttd_values.append((detected_at - pipeline_started).total_seconds())

    return {
        "run_id": metadata["run_id"],
        "configuration": metadata["configuration"],
        "repo": metadata["repo"],
        "scenario": metadata["scenario"],
        "repetition": metadata["repetition"],
        "campaign_id": metadata.get("campaign_id"),
        "pipeline_success": metadata["pipeline_success"],
        "pipeline_time_seconds": metadata["pipeline_time_seconds"],
        "scanner_time_seconds": scanner_time(metadata),
        "tool_failure_count": len(metadata.get("tool_failures", [])),
        "finding_count_initial": len(initial),
        "finding_count_residual": len(residual),
        "residual_critical": sum(1 for f in residual_active if str(f.get("severity")).lower() == "critical"),
        "residual_high": sum(1 for f in residual_active if str(f.get("severity")).lower() == "high"),
        "residual_secret": sum(1 for f in residual_active if f.get("category") == "secret"),
        "policy_engine": decision.get("engine"),
        "policy_allow": decision.get("allow"),
        "policy_deny_count": len(decision.get("deny", [])),
        "tp_ground_truth": tp,
        "fp_unknown_or_false": fp + unknown,
        "fn_ground_truth": fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": safe_div(fp + unknown, tp + fp + unknown),
        "false_negative_rate": safe_div(fn, fn + tp),
        "coverage": recall,
        "auto_remediation_rate": safe_div(remediation.get("remediated_count", 0), max(len(initial), 1)),
        "patch_success_rate": 1.0 if remediation.get("tests", {}).get("returncode") == 0 and remediation.get("remediated_count", 0) else 0.0,
        "human_escalation_rate": safe_div(
            sum(1 for e in remediation.get("events", []) if e.get("human_review_required")),
            max(len(remediation.get("events", [])), 1),
        ),
        "mttd_seconds": statistics.mean(mttd_values) if mttd_values else 0.0,
        "mttr_seconds": statistics.mean(mttr_values) if mttr_values else 0.0,
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


def compute_finding_metrics(raw_dirs: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_dir in raw_dirs:
        metadata_path = raw_dir / "metadata.json"
        if not metadata_path.exists():
            continue
        metadata = read_json(metadata_path)
        stages = [
            ("initial", Path(metadata.get("normalized_findings", ""))),
            ("residual", Path(metadata.get("residual_findings", ""))),
        ]
        for stage, path in stages:
            for finding in read_jsonl(path):
                rows.append({
                    "run_id": metadata["run_id"],
                    "campaign_id": metadata.get("campaign_id"),
                    "configuration": metadata["configuration"],
                    "repo": metadata["repo"],
                    "scenario": metadata["scenario"],
                    "repetition": metadata["repetition"],
                    "stage": stage,
                    "finding_id": finding.get("finding_id"),
                    "fingerprint": finding.get("fingerprint"),
                    "tool": finding.get("tool"),
                    "category": finding.get("category"),
                    "severity": finding.get("severity"),
                    "cvss": finding.get("cvss"),
                    "file": finding.get("file"),
                    "cwe": finding.get("cwe"),
                    "cve": finding.get("cve"),
                    "ground_truth_id": finding.get("ground_truth_id"),
                    "is_ground_truth": finding.get("is_ground_truth"),
                    "is_false_positive": finding.get("is_false_positive"),
                    "remediated": finding.get("remediated"),
                    "remediation_method": finding.get("remediation_method"),
                })
    return rows


def compute_remediation_metrics(raw_dirs: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_dir in raw_dirs:
        metadata_path = raw_dir / "metadata.json"
        remediation_path = raw_dir / "remediation_log.json"
        if not metadata_path.exists() or not remediation_path.exists():
            continue
        metadata = read_json(metadata_path)
        remediation = read_json(remediation_path)
        events = remediation.get("events") or []
        if not events:
            rows.append({
                "run_id": metadata["run_id"],
                "campaign_id": metadata.get("campaign_id"),
                "configuration": metadata["configuration"],
                "repo": metadata["repo"],
                "scenario": metadata["scenario"],
                "repetition": metadata["repetition"],
                "finding_id": "",
                "ground_truth_id": "",
                "method": remediation.get("mode"),
                "branch_created": remediation.get("branch_created"),
                "pr_created": remediation.get("pr_created"),
                "tests_returncode": (remediation.get("tests") or {}).get("returncode"),
                "human_review_required": "",
                "status": "no_remediation_event",
                "time_to_patch_pr_seconds": 0.0,
                "time_to_green_patch_seconds": 0.0,
            })
            continue
        for event in events:
            rows.append({
                "run_id": metadata["run_id"],
                "campaign_id": metadata.get("campaign_id"),
                "configuration": metadata["configuration"],
                "repo": metadata["repo"],
                "scenario": metadata["scenario"],
                "repetition": metadata["repetition"],
                "finding_id": event.get("finding_id"),
                "ground_truth_id": event.get("ground_truth_id"),
                "method": event.get("method"),
                "branch_created": remediation.get("branch_created"),
                "pr_created": remediation.get("pr_created"),
                "tests_returncode": (remediation.get("tests") or {}).get("returncode"),
                "human_review_required": event.get("human_review_required"),
                "status": event.get("status"),
                "time_to_patch_pr_seconds": 0.0 if not remediation.get("pr_created") else "",
                "time_to_green_patch_seconds": 0.0 if (remediation.get("tests") or {}).get("returncode") == 0 else "",
            })
    return rows


def ablation_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(row["repo"], row["scenario"], row["repetition"], row["configuration"]): row for row in rows}
    comparisons = [
        ("C2_vs_C1_normalization", "C2_AutoScanning", "C1_NonBlockingScanning"),
        ("C3_vs_C2_policy_only", "C3_PolicyOnly", "C2_AutoScanning"),
        ("C4_vs_C2_agents_only", "C4_AgentsOnly", "C2_AutoScanning"),
        ("C5_vs_C4_policy_after_agents", "C5_SecFlowOps", "C4_AgentsOnly"),
        ("C5_vs_C3_agents_before_policy", "C5_SecFlowOps", "C3_PolicyOnly"),
        ("C5_vs_C0_full_over_build", "C5_SecFlowOps", "C0_BuildOnly"),
    ]
    out = []
    for name, lhs, rhs in comparisons:
        paired = []
        for repo, scenario, repetition, config in list(by_key):
            if config != lhs:
                continue
            left = by_key.get((repo, scenario, repetition, lhs))
            right = by_key.get((repo, scenario, repetition, rhs))
            if left and right:
                paired.append((left, right))
        for metric in [
            "pipeline_time_seconds",
            "finding_count_residual",
            "recall",
            "precision",
            "auto_remediation_rate",
            "pipeline_success",
        ]:
            deltas = []
            for left, right in paired:
                lval = float(left[metric]) if metric != "pipeline_success" else float(bool(left[metric]))
                rval = float(right[metric]) if metric != "pipeline_success" else float(bool(right[metric]))
                deltas.append(lval - rval)
            out.append({
                "comparison": name,
                "lhs": lhs,
                "rhs": rhs,
                "metric": metric,
                "n_pairs": len(deltas),
                "mean_delta": statistics.mean(deltas) if deltas else 0.0,
                "median_delta": statistics.median(deltas) if deltas else 0.0,
                "min_delta": min(deltas) if deltas else 0.0,
                "max_delta": max(deltas) if deltas else 0.0,
            })
    return out


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
                    "min_coverage": 0.80,
                })
    out = []
    for policy in grid:
        decisions = []
        residual_counts = []
        for raw_dir in raw_dirs:
            metadata_path = raw_dir / "metadata.json"
            if not metadata_path.exists():
                continue
            metadata = read_json(metadata_path)
            if metadata.get("configuration") not in {"C3_PolicyOnly", "C5_SecFlowOps"}:
                continue
            findings = read_jsonl(Path(metadata.get("residual_findings", "")))
            decision = fallback_decision(
                findings,
                coverage=1.0,
                tool_failures=metadata.get("tool_failures", []),
                policy=policy,
            )
            decisions.append(bool(decision.get("allow")))
            residual_counts.append((decision.get("summary") or {}).get("residual_count", 0))
        out.append({
            **policy,
            "n_policy_runs": len(decisions),
            "allow_rate": safe_div(sum(1 for d in decisions if d), len(decisions)),
            "deny_rate": safe_div(sum(1 for d in decisions if not d), len(decisions)),
            "mean_residual_count": statistics.mean(residual_counts) if residual_counts else 0.0,
        })
    return out


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_config: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_config.setdefault(row["configuration"], []).append(row)
    summary = []
    for config, values in sorted(by_config.items()):
        summary.append({
            "configuration": config,
            "n_runs": len(values),
            "pipeline_success_rate": safe_div(sum(1 for v in values if v["pipeline_success"]), len(values)),
            "mean_pipeline_time_seconds": statistics.mean(float(v["pipeline_time_seconds"]) for v in values),
            "mean_scanner_time_seconds": statistics.mean(float(v["scanner_time_seconds"]) for v in values),
            "mean_findings_initial": statistics.mean(float(v["finding_count_initial"]) for v in values),
            "mean_findings_residual": statistics.mean(float(v["finding_count_residual"]) for v in values),
            "mean_recall": statistics.mean(float(v["recall"]) for v in values),
            "mean_precision": statistics.mean(float(v["precision"]) for v in values),
            "mean_auto_remediation_rate": statistics.mean(float(v["auto_remediation_rate"]) for v in values),
            "mean_mttr_seconds": statistics.mean(float(v["mttr_seconds"]) for v in values),
            "mean_mttd_seconds": statistics.mean(float(v["mttd_seconds"]) for v in values),
        })
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-run-id", default=None, help="Ignore raw runs whose directory name is lexically older.")
    parser.add_argument("--max-run-id", default=None, help="Ignore raw runs whose directory name is lexically newer.")
    parser.add_argument("--campaign-id-filter", default=None, help="Only include runs with this exact campaign_id.")
    parser.add_argument("--label", default="", help="Optional output label, e.g. external writes *_external.csv.")
    args = parser.parse_args()

    ground_truth = load_ground_truth(ROOT / "repos" / "ground_truth" / "ground_truth_findings.csv")
    rows = []
    raw_dirs = []
    for raw_dir in sorted((ROOT / "data" / "raw").glob("*")):
        if args.min_run_id and raw_dir.name < args.min_run_id:
            continue
        if args.max_run_id and raw_dir.name > args.max_run_id:
            continue
        required = [
            raw_dir / "metadata.json",
            raw_dir / "policy_decision.json",
            raw_dir / "remediation_log.json",
        ]
        if all(path.exists() for path in required):
            if args.campaign_id_filter:
                metadata = read_json(raw_dir / "metadata.json")
                if metadata.get("campaign_id") != args.campaign_id_filter:
                    continue
            raw_dirs.append(raw_dir)
            rows.append(compute_run_metrics(raw_dir, ground_truth))

    suffix = f"_{args.label}" if args.label else ""
    write_csv(ROOT / "data" / "processed" / f"run_metrics{suffix}.csv", rows)
    write_csv(ROOT / "data" / "processed" / f"finding_metrics{suffix}.csv", compute_finding_metrics(raw_dirs))
    write_csv(ROOT / "data" / "processed" / f"remediation_metrics{suffix}.csv", compute_remediation_metrics(raw_dirs))
    write_csv(ROOT / "tables" / f"summary_metrics{suffix}.csv", summarize(rows))
    write_csv(ROOT / "tables" / f"ablation_results{suffix}.csv", ablation_rows(rows))
    write_csv(ROOT / "tables" / f"policy_sensitivity{suffix}.csv", policy_sensitivity_rows(raw_dirs))
    print(f"computed metrics for {len(rows)} runs")


if __name__ == "__main__":
    main()
