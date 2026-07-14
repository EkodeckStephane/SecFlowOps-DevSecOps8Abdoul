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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def finding_key_from_finding(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("repo"),
        finding.get("tool"),
        finding.get("category"),
        finding.get("cve"),
        finding.get("cwe"),
        finding.get("file"),
        str(finding.get("line_start") or ""),
        finding.get("message"),
    )


def finding_key_from_label(row: dict[str, str]) -> tuple[Any, ...]:
    return (
        row.get("repo"),
        row.get("tool"),
        row.get("category"),
        row.get("cve") or None,
        row.get("cwe") or None,
        row.get("file"),
        row.get("line_start") or "",
        row.get("message"),
    )


def safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def load_labels(path: Path) -> dict[tuple[Any, ...], dict[str, str]]:
    return {finding_key_from_label(row): row for row in read_csv(path)}


def matched_counts(findings: list[dict[str, Any]], labels: dict[tuple[Any, ...], dict[str, str]]) -> dict[str, int]:
    total = len(findings)
    reviewed = 0
    true_positive = 0
    false_positive = 0
    reviewed_critical = 0
    reviewed_high = 0
    reviewed_secret = 0
    for finding in findings:
        label = labels.get(finding_key_from_finding(finding))
        if not label:
            continue
        reviewed += 1
        if label.get("true_positive", "").lower() == "true":
            true_positive += 1
            severity = str(label.get("confirmed_severity") or finding.get("severity") or "").lower()
            if severity == "critical":
                reviewed_critical += 1
            if severity == "high":
                reviewed_high += 1
            if finding.get("category") == "secret":
                reviewed_secret += 1
        elif label.get("true_positive", "").lower() == "false":
            false_positive += 1
    return {
        "total": total,
        "reviewed": reviewed,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "precision_denominator": true_positive + false_positive,
        "unknown": total - reviewed,
        "reviewed_critical": reviewed_critical,
        "reviewed_high": reviewed_high,
        "reviewed_secret": reviewed_secret,
    }


def run_rows(
    labels: dict[tuple[Any, ...], dict[str, str]],
    *,
    min_run_id: str | None,
    max_run_id: str | None,
    campaign_id: str | None,
) -> list[dict[str, Any]]:
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
        if campaign_id and metadata.get("campaign_id") != campaign_id:
            continue
        if not str(metadata.get("repo", "")).startswith("external_"):
            continue
        initial = read_jsonl(Path(metadata["normalized_findings"]))
        residual = read_jsonl(Path(metadata["residual_findings"]))
        initial_counts = matched_counts(initial, labels)
        residual_counts = matched_counts(residual, labels)
        resolved_tp = max(initial_counts["true_positive"] - residual_counts["true_positive"], 0)
        initial_precision = (
            safe_div(initial_counts["true_positive"], initial_counts["precision_denominator"])
            if initial_counts["precision_denominator"]
            else ""
        )
        residual_precision = (
            safe_div(residual_counts["true_positive"], residual_counts["precision_denominator"])
            if residual_counts["precision_denominator"]
            else ""
        )
        rows.append({
            "run_id": metadata["run_id"],
            "campaign_id": metadata.get("campaign_id"),
            "configuration": metadata["configuration"],
            "repo": metadata["repo"],
            "repetition": metadata["repetition"],
            "pipeline_success": metadata["pipeline_success"],
            "initial_findings_total": initial_counts["total"],
            "initial_findings_reviewed": initial_counts["reviewed"],
            "initial_reviewed_true_positive": initial_counts["true_positive"],
            "initial_reviewed_false_positive": initial_counts["false_positive"],
            "initial_unreviewed_findings": initial_counts["unknown"],
            "residual_findings_total": residual_counts["total"],
            "residual_findings_reviewed": residual_counts["reviewed"],
            "residual_reviewed_true_positive": residual_counts["true_positive"],
            "residual_reviewed_false_positive": residual_counts["false_positive"],
            "residual_unreviewed_findings": residual_counts["unknown"],
            "resolved_reviewed_true_positive": resolved_tp,
            "reviewed_resolution_rate": safe_div(resolved_tp, initial_counts["true_positive"]),
            "initial_adjudicated_precision": initial_precision,
            "residual_adjudicated_precision": residual_precision,
            "residual_reviewed_critical": residual_counts["reviewed_critical"],
            "residual_reviewed_high": residual_counts["reviewed_high"],
            "residual_reviewed_secret": residual_counts["reviewed_secret"],
            "external_recall_assessable": "false",
        })
    return rows


def summarize(rows: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(tuple(row[key] for key in keys), []).append(row)
    out = []
    metrics = [
        "initial_reviewed_true_positive",
        "residual_reviewed_true_positive",
        "resolved_reviewed_true_positive",
        "reviewed_resolution_rate",
        "initial_adjudicated_precision",
        "residual_adjudicated_precision",
        "residual_reviewed_critical",
        "residual_reviewed_high",
        "residual_reviewed_secret",
    ]
    for group, values in sorted(grouped.items()):
        item: dict[str, Any] = {key: value for key, value in zip(keys, group)}
        item["n_runs"] = len(values)
        for metric in metrics:
            vals = [float(row[metric]) for row in values if row[metric] != ""]
            item[f"mean_{metric}"] = statistics.mean(vals) if vals else 0.0
            item[f"median_{metric}"] = statistics.median(vals) if vals else 0.0
            if metric.endswith("adjudicated_precision"):
                item[f"n_{metric}_runs"] = len(vals)
        out.append(item)
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", default=str(ROOT / "data" / "manual_labels" / "external_adjudication_reviewed.csv"))
    parser.add_argument("--min-run-id", default=None)
    parser.add_argument("--max-run-id", default=None)
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--label", default="external_adjudicated")
    args = parser.parse_args()

    labels = load_labels(Path(args.labels))
    rows = run_rows(labels, min_run_id=args.min_run_id, max_run_id=args.max_run_id, campaign_id=args.campaign_id)
    suffix = f"_{args.label}" if args.label else ""
    write_csv(ROOT / "data" / "processed" / f"run_metrics{suffix}.csv", rows)
    write_csv(ROOT / "tables" / f"summary_metrics{suffix}.csv", summarize(rows, ["configuration"]))
    write_csv(ROOT / "tables" / f"summary_metrics{suffix}_by_repo.csv", summarize(rows, ["configuration", "repo"]))
    print(f"computed adjudicated metrics for {len(rows)} runs using {len(labels)} reviewed labels")


if __name__ == "__main__":
    main()
