from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


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


def finding_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("repo"),
        finding.get("tool"),
        finding.get("category"),
        finding.get("cve"),
        finding.get("cwe"),
        finding.get("file"),
        finding.get("line_start"),
        finding.get("message"),
    )


def collect_findings(min_run_id: str | None, max_run_id: str | None, campaign_id: str | None) -> list[dict[str, Any]]:
    findings_by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
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
        config = str(metadata.get("configuration", ""))
        for path_name in ["normalized_findings", "residual_findings"]:
            is_post_remediation = path_name == "residual_findings" and config in ("C4_AgentsOnly", "C5_SecFlowOps")
            for finding in read_jsonl(Path(metadata[path_name])):
                key = finding_key(finding)
                row = findings_by_key.get(key)
                if row is None:
                    row = {
                        "adjudication_id": f"ADJ-{len(findings_by_key) + 1:05d}",
                        "repo": finding.get("repo"),
                        "tool": finding.get("tool"),
                        "category": finding.get("category"),
                        "severity_reported": finding.get("severity"),
                        "cvss_reported": finding.get("cvss"),
                        "cve": finding.get("cve"),
                        "cwe": finding.get("cwe"),
                        "file": finding.get("file"),
                        "line_start": finding.get("line_start"),
                        "message": finding.get("message"),
                        "first_run_id": metadata.get("run_id"),
                        "seen_in_runs": 0,
                        "seen_post_remediation": "false",
                        "review_status": "pending",
                        "true_positive": "",
                        "confirmed_severity": "",
                        "remediation_required": "",
                        "exploitability_notes": "",
                        "reviewer": "",
                        "review_date": "",
                        "adjudication_notes": "",
                        "_seen_runs": set(),
                        "_seen_post_remediation_runs": set(),
                    }
                    findings_by_key[key] = row
                row["_seen_runs"].add(metadata.get("run_id"))
                if is_post_remediation:
                    row["_seen_post_remediation_runs"].add(metadata.get("run_id"))
                    row["seen_post_remediation"] = "true"
    rows = []
    for row in findings_by_key.values():
        row["seen_in_runs"] = len(row.pop("_seen_runs"))
        row["post_remediation_runs"] = len(row.pop("_seen_post_remediation_runs"))
        rows.append(row)
    return sorted(rows, key=lambda r: (r["repo"], r["tool"], r["category"], str(r["file"])))


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str], int] = {}
    for row in rows:
        key = (str(row["repo"]), str(row["tool"]), str(row["category"]))
        counts[key] = counts.get(key, 0) + 1
    return [
        {"repo": repo, "tool": tool, "category": category, "unique_findings": count}
        for (repo, tool, category), count in sorted(counts.items())
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min-run-id", default=None)
    parser.add_argument("--max-run-id", default=None)
    parser.add_argument("--campaign-id", default=None)
    parser.add_argument("--output", default=str(ROOT / "data" / "manual_labels" / "external_adjudication_template.csv"))
    args = parser.parse_args()

    rows = collect_findings(args.min_run_id, args.max_run_id, args.campaign_id)
    output = Path(args.output)
    write_csv(output, rows)
    write_csv(output.with_name("external_adjudication_summary.csv"), summarize(rows))
    print(f"wrote {len(rows)} adjudication rows to {output}")


if __name__ == "__main__":
    main()
