from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


SEVERITY_ORDER = {
    "info": 0,
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def secflowops_root() -> Path:
    return Path(__file__).resolve().parents[2]


def normalize_severity(value: str | None) -> str:
    if not value:
        return "info"
    value = value.lower()
    if value in SEVERITY_ORDER:
        return value
    if value == "error":
        return "high"
    if value == "warning":
        return "medium"
    return "info"


def severity_to_cvss(severity: str) -> float:
    severity = normalize_severity(severity)
    return {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 2.5,
        "info": 0.0,
        "unknown": 0.0,
    }.get(severity, 0.0)


def fingerprint(*parts: Any) -> str:
    material = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


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


def load_ground_truth(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def match_ground_truth(finding: dict[str, Any], ground_truth: list[dict[str, str]]) -> str | None:
    file_name = (finding.get("file") or "").replace("\\", "/")
    category = finding.get("category")
    cve = finding.get("cve")
    cwe = finding.get("cwe")
    tool = finding.get("tool")
    repo = finding.get("repo")

    def cwe_key(value: Any) -> str:
        return str(value or "").lower().replace("cwe-", "").strip()

    for row in ground_truth:
        gt_file = (row.get("file") or "").replace("\\", "/")
        gt_tools = (row.get("tool_expected") or "").split("|")
        if row.get("repo") and repo and row["repo"] != repo:
            continue
        if row.get("expected_detection", "").lower() != "true":
            continue
        if row.get("type") != category:
            continue
        if category != "dast" and gt_file and gt_file not in file_name and file_name not in gt_file:
            continue
        if row.get("cve") and cve and row["cve"] != cve:
            continue
        if row.get("cwe") and cwe and cwe_key(row["cwe"]) != cwe_key(cwe):
            continue
        message_pattern = row.get("match_message_contains")
        if message_pattern and message_pattern not in str(finding.get("message") or ""):
            continue
        if tool and gt_tools and tool not in gt_tools and "trivy" not in gt_tools:
            # Trivy reports SCA, secret and IaC findings in this smoke artifact.
            continue
        return row["finding_id"]
    return None


def enrich_with_ground_truth(
    findings: list[dict[str, Any]], ground_truth: list[dict[str, str]]
) -> list[dict[str, Any]]:
    for finding in findings:
        gt_id = match_ground_truth(finding, ground_truth)
        finding["ground_truth_id"] = gt_id
        finding["is_ground_truth"] = gt_id is not None
        finding["is_false_positive"] = False if gt_id is not None else None
    return findings
