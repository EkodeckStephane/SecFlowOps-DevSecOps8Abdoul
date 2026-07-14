from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import fingerprint, normalize_severity, severity_to_cvss


def parse_file(path: Path, *, repo: str, commit: str, run_id: str) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for result in data.get("results", []) or []:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = normalize_severity(extra.get("severity"))
        file_path = result.get("path")
        start = result.get("start", {})
        rule_id = result.get("check_id")
        findings.append({
            "finding_id": f"{run_id}:semgrep:{rule_id}:{file_path}:{start.get('line')}",
            "tool": "semgrep",
            "category": "sast",
            "repo": repo,
            "commit": commit,
            "file": file_path,
            "line_start": start.get("line"),
            "line_end": (result.get("end") or {}).get("line"),
            "cwe": metadata.get("cwe"),
            "cve": None,
            "severity": severity,
            "cvss": severity_to_cvss(severity),
            "message": extra.get("message") or rule_id,
            "fingerprint": fingerprint("semgrep", rule_id, file_path, start.get("line")),
            "is_ground_truth": None,
            "is_false_positive": None,
            "ground_truth_id": None,
            "remediated": False,
            "remediation_method": "none",
            "timestamps": {},
        })
    return findings
