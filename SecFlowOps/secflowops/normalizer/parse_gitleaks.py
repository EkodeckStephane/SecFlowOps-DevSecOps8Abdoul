from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import fingerprint, severity_to_cvss


def parse_file(path: Path, *, repo: str, commit: str, run_id: str) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("findings", [])
    findings = []
    for item in data or []:
        file_path = item.get("File") or item.get("file")
        line = item.get("StartLine") or item.get("line")
        rule_id = item.get("RuleID") or item.get("rule")
        findings.append({
            "finding_id": f"{run_id}:gitleaks:{rule_id}:{file_path}:{line}",
            "tool": "gitleaks",
            "category": "secret",
            "repo": repo,
            "commit": commit,
            "file": file_path,
            "line_start": int(line) if isinstance(line, int) else None,
            "line_end": int(line) if isinstance(line, int) else None,
            "cwe": None,
            "cve": None,
            "severity": "critical",
            "cvss": severity_to_cvss("critical"),
            "message": item.get("Description") or rule_id or "secret detected",
            "fingerprint": fingerprint("gitleaks", rule_id, file_path, line),
            "is_ground_truth": None,
            "is_false_positive": None,
            "ground_truth_id": None,
            "remediated": False,
            "remediation_method": "none",
            "timestamps": {},
        })
    return findings
