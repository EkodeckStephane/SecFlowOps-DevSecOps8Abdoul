from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .common import fingerprint, normalize_severity, severity_to_cvss


def _severity(risk: str | None) -> str:
    value = (risk or "").lower()
    if value.startswith("critical"):
        return "critical"
    if value.startswith("high"):
        return "high"
    if value.startswith("medium"):
        return "medium"
    if value.startswith("low"):
        return "low"
    if value in {"high", "critical", "medium", "low", "info"}:
        return "critical" if value == "critical" else value
    if value == "informational":
        return "info"
    return "info"


def parse_file(path: Path, *, repo: str, commit: str, run_id: str) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    alerts = data.get("site", [])
    if isinstance(alerts, list):
        expanded = []
        for site in alerts:
            expanded.extend(site.get("alerts", []) or [])
        alerts = expanded
    elif isinstance(data.get("alerts"), list):
        alerts = data["alerts"]
    else:
        alerts = []

    findings = []
    for alert in alerts:
        risk = _severity(alert.get("riskdesc") or alert.get("risk"))
        plugin_id = alert.get("pluginid") or alert.get("pluginId") or alert.get("alertRef")
        instances = alert.get("instances") or [{}]
        for instance in instances:
            uri = instance.get("uri") or instance.get("url") or alert.get("url") or ""
            param = instance.get("param") or ""
            findings.append({
                "finding_id": f"{run_id}:zap:{plugin_id}:{uri}:{param}",
                "tool": "zap",
                "category": "dast",
                "repo": repo,
                "commit": commit,
                "file": uri,
                "line_start": None,
                "line_end": None,
                "cwe": str(alert.get("cweid") or "") if alert.get("cweid") else None,
                "cve": None,
                "severity": risk,
                "cvss": severity_to_cvss(risk),
                "message": alert.get("alert") or alert.get("name") or "ZAP alert",
                "fingerprint": fingerprint("zap", plugin_id, uri, param),
                "is_ground_truth": None,
                "is_false_positive": None,
                "ground_truth_id": None,
                "remediated": False,
                "remediation_method": "none",
                "timestamps": {},
            })
    return findings
