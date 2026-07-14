from __future__ import annotations

from pathlib import Path
from typing import Any

from .common import fingerprint, normalize_severity, severity_to_cvss


def _cvss_from_vulnerability(vuln: dict[str, Any], severity: str) -> float:
    cvss = vuln.get("CVSS") or {}
    for source in ("nvd", "redhat", "ghsa"):
        if source in cvss and isinstance(cvss[source], dict):
            score = cvss[source].get("V3Score") or cvss[source].get("V2Score")
            if score is not None:
                try:
                    return float(score)
                except (TypeError, ValueError):
                    pass
    return severity_to_cvss(severity)


def parse_trivy(data: dict[str, Any], *, repo: str, commit: str, run_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in data.get("Results", []) or []:
        target = result.get("Target")

        for vuln in result.get("Vulnerabilities", []) or []:
            severity = normalize_severity(vuln.get("Severity"))
            cve = vuln.get("VulnerabilityID")
            pkg = vuln.get("PkgName")
            finding_id = f"{run_id}:trivy:vuln:{cve}:{pkg}:{target}"
            findings.append({
                "finding_id": finding_id,
                "tool": "trivy",
                "category": "sca",
                "repo": repo,
                "commit": commit,
                "file": target,
                "line_start": None,
                "line_end": None,
                "cwe": None,
                "cve": cve,
                "severity": severity,
                "cvss": _cvss_from_vulnerability(vuln, severity),
                "message": vuln.get("Title") or vuln.get("Description") or f"{pkg} {cve}",
                "fingerprint": fingerprint("trivy", "vuln", cve, pkg, target),
                "is_ground_truth": None,
                "is_false_positive": None,
                "ground_truth_id": None,
                "remediated": False,
                "remediation_method": "none",
                "timestamps": {},
            })

        for misc in result.get("Misconfigurations", []) or []:
            severity = normalize_severity(misc.get("Severity"))
            loc = misc.get("CauseMetadata", {}).get("StartLine")
            misc_id = misc.get("ID")
            finding_id = f"{run_id}:trivy:misconfig:{misc_id}:{target}:{loc}"
            findings.append({
                "finding_id": finding_id,
                "tool": "trivy",
                "category": "iac",
                "repo": repo,
                "commit": commit,
                "file": target,
                "line_start": int(loc) if isinstance(loc, int) else None,
                "line_end": int(loc) if isinstance(loc, int) else None,
                "cwe": None,
                "cve": None,
                "severity": severity,
                "cvss": severity_to_cvss(severity),
                "message": misc.get("Title") or misc.get("Message") or misc_id,
                "fingerprint": fingerprint("trivy", "misconfig", misc_id, target, loc),
                "is_ground_truth": None,
                "is_false_positive": None,
                "ground_truth_id": None,
                "remediated": False,
                "remediation_method": "none",
                "timestamps": {},
            })

        for secret in result.get("Secrets", []) or []:
            severity = normalize_severity(secret.get("Severity") or "critical")
            line = secret.get("StartLine")
            rule_id = secret.get("RuleID")
            finding_id = f"{run_id}:trivy:secret:{rule_id}:{target}:{line}"
            findings.append({
                "finding_id": finding_id,
                "tool": "trivy",
                "category": "secret",
                "repo": repo,
                "commit": commit,
                "file": target,
                "line_start": int(line) if isinstance(line, int) else None,
                "line_end": int(secret.get("EndLine")) if isinstance(secret.get("EndLine"), int) else None,
                "cwe": None,
                "cve": None,
                "severity": severity,
                "cvss": severity_to_cvss(severity),
                "message": secret.get("Title") or rule_id or "secret detected",
                "fingerprint": fingerprint("trivy", "secret", rule_id, target, line),
                "is_ground_truth": None,
                "is_false_positive": None,
                "ground_truth_id": None,
                "remediated": False,
                "remediation_method": "none",
                "timestamps": {},
            })
    return findings


def parse_file(path: Path, *, repo: str, commit: str, run_id: str) -> list[dict[str, Any]]:
    import json

    if not path.exists() or path.stat().st_size == 0:
        return []
    return parse_trivy(json.loads(path.read_text(encoding="utf-8")), repo=repo, commit=commit, run_id=run_id)
