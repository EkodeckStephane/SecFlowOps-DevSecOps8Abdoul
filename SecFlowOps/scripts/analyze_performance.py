from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def as_float(value: Any) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def scanner_component(steps: dict[str, Any], phase: str, tool: str) -> float:
    step = steps.get(phase, {})
    return as_float((step.get(tool) or {}).get("elapsed_seconds"))


def load_corpus() -> dict[str, dict[str, str]]:
    rows = read_csv(ROOT / "experiments" / "corpus_manifest.csv")
    rows.extend(read_csv(ROOT / "experiments" / "external_corpus_manifest.csv"))
    rows.extend(read_csv(ROOT / "experiments" / "injected_external_corpus_manifest.csv"))
    rows.extend(read_csv(ROOT / "experiments" / "full_protocol_corpus_manifest.csv"))
    return {row["repo_id"]: row for row in rows}


def component_rows(min_run_id: str | None, max_run_id: str | None) -> list[dict[str, Any]]:
    corpus = load_corpus()
    rows = []
    for raw_dir in sorted((ROOT / "data" / "raw").glob("*")):
        if min_run_id and raw_dir.name < min_run_id:
            continue
        if max_run_id and raw_dir.name > max_run_id:
            continue
        metadata_path = raw_dir / "metadata.json"
        if not metadata_path.exists():
            continue
        metadata = read_json(metadata_path)
        steps = metadata.get("steps", {})
        repo = metadata["repo"]
        corpus_row = corpus.get(repo, {})
        initial_scanner_time = sum(scanner_component(steps, "scanners_initial", tool) for tool in ["trivy", "semgrep", "gitleaks"])
        post_scanner_time = sum(scanner_component(steps, "scanners_post_remediation", tool) for tool in ["trivy", "semgrep", "gitleaks"])
        rows.append({
            "run_id": metadata["run_id"],
            "campaign_id": metadata.get("campaign_id"),
            "configuration": metadata["configuration"],
            "repo": repo,
            "size_class": corpus_row.get("size_class", "unknown"),
            "origin_type": corpus_row.get("origin_type", corpus_row.get("origin", "unknown")),
            "stack": corpus_row.get("stack", ""),
            "file_count": corpus_row.get("file_count", ""),
            "loc": corpus_row.get("loc", ""),
            "repetition": metadata["repetition"],
            "pipeline_success": metadata["pipeline_success"],
            "pipeline_time_seconds": as_float(metadata.get("pipeline_time_seconds")),
            "build_time_seconds": as_float((steps.get("build_test") or {}).get("elapsed_seconds")),
            "initial_trivy_seconds": scanner_component(steps, "scanners_initial", "trivy"),
            "initial_semgrep_seconds": scanner_component(steps, "scanners_initial", "semgrep"),
            "initial_gitleaks_seconds": scanner_component(steps, "scanners_initial", "gitleaks"),
            "post_trivy_seconds": scanner_component(steps, "scanners_post_remediation", "trivy"),
            "post_semgrep_seconds": scanner_component(steps, "scanners_post_remediation", "semgrep"),
            "post_gitleaks_seconds": scanner_component(steps, "scanners_post_remediation", "gitleaks"),
            "initial_scanner_time_seconds": initial_scanner_time,
            "post_scanner_time_seconds": post_scanner_time,
            "total_scanner_time_seconds": initial_scanner_time + post_scanner_time,
            "remediation_time_seconds": as_float((steps.get("remediation") or {}).get("elapsed_seconds")),
            "policy_time_seconds": as_float((steps.get("policy_gate") or {}).get("elapsed_seconds")),
        })
    return rows


def component_rows_for_campaign(campaign_id: str) -> list[dict[str, Any]]:
    rows = component_rows(None, None)
    return [row for row in rows if row.get("campaign_id") == campaign_id]


def summarize(rows: list[dict[str, Any]], keys: list[str], metrics: list[str]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(tuple(row[key] for key in keys), []).append(row)
    out = []
    for group_key, values in sorted(grouped.items()):
        item = {key: value for key, value in zip(keys, group_key)}
        item["n_runs"] = len(values)
        for metric in metrics:
            vals = [as_float(row[metric]) for row in values]
            item[f"mean_{metric}"] = statistics.mean(vals) if vals else 0.0
            item[f"median_{metric}"] = statistics.median(vals) if vals else 0.0
            item[f"stdev_{metric}"] = statistics.stdev(vals) if len(vals) > 1 else 0.0
        out.append(item)
    return out


def paired_overheads(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(row["repo"], row["repetition"], row["configuration"]): row for row in rows}
    comparisons = [
        ("C5_vs_C0_total", "C5_SecFlowOps", "C0_BuildOnly", "pipeline_time_seconds"),
        ("C5_vs_C1_incremental", "C5_SecFlowOps", "C1_NonBlockingScanning", "pipeline_time_seconds"),
        ("C3_vs_C1_policy_gate", "C3_PolicyOnly", "C1_NonBlockingScanning", "pipeline_time_seconds"),
        ("C4_vs_C1_agent_rescan", "C4_AgentsOnly", "C1_NonBlockingScanning", "pipeline_time_seconds"),
        ("C5_vs_C4_policy_increment", "C5_SecFlowOps", "C4_AgentsOnly", "pipeline_time_seconds"),
    ]
    out = []
    repos = sorted({row["repo"] for row in rows})
    reps = sorted({row["repetition"] for row in rows})
    for name, lhs, rhs, metric in comparisons:
        values = []
        for repo in repos:
            for rep in reps:
                left = by_key.get((repo, rep, lhs))
                right = by_key.get((repo, rep, rhs))
                if left and right:
                    values.append(as_float(left[metric]) - as_float(right[metric]))
        out.append({
            "comparison": name,
            "metric": metric,
            "n_pairs": len(values),
            "mean_delta_seconds": statistics.mean(values) if values else 0.0,
            "median_delta_seconds": statistics.median(values) if values else 0.0,
            "stdev_delta_seconds": statistics.stdev(values) if len(values) > 1 else 0.0,
            "min_delta_seconds": min(values) if values else 0.0,
            "max_delta_seconds": max(values) if values else 0.0,
        })
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-run-id", default=None)
    parser.add_argument("--max-run-id", default=None)
    parser.add_argument("--campaign-id-filter", default=None)
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    rows = component_rows_for_campaign(args.campaign_id_filter) if args.campaign_id_filter else component_rows(args.min_run_id, args.max_run_id)
    metrics = [
        "pipeline_time_seconds",
        "build_time_seconds",
        "initial_scanner_time_seconds",
        "post_scanner_time_seconds",
        "total_scanner_time_seconds",
        "remediation_time_seconds",
        "policy_time_seconds",
    ]
    suffix = f"_{args.label}" if args.label else ""
    write_csv(ROOT / "data" / "processed" / f"performance_components{suffix}.csv", rows)
    write_csv(ROOT / "tables" / f"performance_by_config{suffix}.csv", summarize(rows, ["configuration"], metrics))
    write_csv(ROOT / "tables" / f"performance_by_size{suffix}.csv", summarize(rows, ["configuration", "size_class"], metrics))
    write_csv(ROOT / "tables" / f"performance_overheads{suffix}.csv", paired_overheads(rows))
    print(f"analyzed performance for {len(rows)} runs")


if __name__ == "__main__":
    main()
