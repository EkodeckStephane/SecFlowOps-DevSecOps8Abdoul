from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "repos" / "sample_api"

FAMILIES = ["alpha", "beta", "gamma"]
SCENARIOS = [
    "clean",
    "vulnerable_dependency",
    "fake_secret",
    "sast_reflected_xss",
    "sast_sql_injection",
    "docker_misconfiguration",
    "k8s_misconfiguration",
    "multi_layer",
]
CONFIGS = [
    "C0_BuildOnly",
    "C1_NonBlockingScanning",
    "C2_AutoScanning",
    "C3_PolicyOnly",
    "C4_AgentsOnly",
    "C5_SecFlowOps",
]


SAFE_APP = '''#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import html
import sqlite3


def render_search_response(query: str) -> str:
    body = f"<html><body>Search: {html.escape(query)}</body></html>"
    return body


def unsafe_user_lookup(username: str) -> list[tuple]:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice')")
    query = "SELECT name FROM users WHERE name = ?"
    return list(conn.execute(query, (username,)))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, "ok")
            return
        if parsed.path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, render_search_response(query), content_type="text/html")
            return
        if parsed.path == "/lookup":
            username = parse_qs(parsed.query).get("u", [""])[0]
            rows = unsafe_user_lookup(username)
            self._send(200, {"rows": rows})
            return
        self._send(404, "not found")

    def _send(self, status: int, payload, content_type: str = "text/plain") -> None:
        data = str(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    server = HTTPServer(("127.0.0.1", 8080), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
'''


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_clean(repo: Path) -> None:
    write_text(repo / "app.py", SAFE_APP)
    write_text(repo / "requirements.txt", "django==4.2.30\nrequests==2.33.0\n")
    write_text(repo / ".env.test", "# No secret in this clean scenario.\n")
    write_text(
        repo / "Dockerfile",
        "FROM python:3.13-slim\nWORKDIR /app\nCOPY . /app\nRUN pip install --no-cache-dir -r requirements.txt\n"
        "RUN useradd -m appuser\nUSER appuser\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]\n",
    )
    write_text(
        repo / "k8s" / "deployment.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: sample-api\nspec:\n  replicas: 1\n"
        "  selector:\n    matchLabels:\n      app: sample-api\n  template:\n    metadata:\n      labels:\n        app: sample-api\n"
        "    spec:\n      containers:\n        - name: sample-api\n          image: sample-api:latest\n"
        "          securityContext:\n            privileged: false\n            runAsNonRoot: true\n            runAsUser: 10001\n"
        "          ports:\n            - containerPort: 8080\n",
    )


def inject(repo: Path, scenario: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def add(finding_id: str, file: str, category: str, tool: str, severity: str, cvss: str, cwe: str = "", cve: str = "", notes: str = "", message: str = "") -> None:
        rows.append({
            "finding_id": finding_id,
            "repo": repo.name,
            "branch": scenario,
            "commit_intro": "local",
            "commit_fix": "local",
            "file": file,
            "line_start": "1",
            "line_end": "1",
            "type": category,
            "cwe": cwe,
            "cve": cve,
            "tool_expected": tool,
            "severity": severity,
            "cvss": cvss,
            "source": "injected",
            "expected_detection": "true",
            "expected_remediation": "true",
            "match_message_contains": message,
            "notes": notes,
        })

    active = {scenario}
    if scenario == "multi_layer":
        active = {"vulnerable_dependency", "fake_secret", "sast_reflected_xss", "sast_sql_injection", "docker_misconfiguration", "k8s_misconfiguration"}

    if "vulnerable_dependency" in active:
        write_text(repo / "requirements.txt", "django==2.2.0\nrequests==2.19.1\n")
        add(f"GT-SCA-DJANGO-001-{repo.name}", "requirements.txt", "sca", "trivy", "critical", "9.8", cve="CVE-2019-19844", notes="Vulnerable dependency pin")

    if "fake_secret" in active:
        write_text(
            repo / ".env.test",
            "# Fake, invalid test secret. This value is the public AWS documentation example.\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        )
        add(f"GT-SECRET-AWS-001-{repo.name}", ".env.test", "secret", "trivy|gitleaks", "critical", "9.0", notes="Fake documented AWS test key")

    if "sast_reflected_xss" in active:
        text = (repo / "app.py").read_text(encoding="utf-8")
        text = text.replace('body = f"<html><body>Search: {html.escape(query)}</body></html>"', 'body = f"<html><body>Search: {query}</body></html>"')
        text = text.replace("import html\n", "")
        write_text(repo / "app.py", text)
        add(f"GT-SAST-XSS-001-{repo.name}", "app.py", "sast", "semgrep", "high", "7.4", cwe="CWE-79", notes="Reflected unescaped query in HTML response")
        add(f"GT-DAST-XSS-001-{repo.name}", "app.py", "dast", "zap", "high", "7.4", cwe="CWE-79", notes="DAST target endpoint /search?q=<script>alert(1)</script>", message="Cross Site Scripting")

    if "sast_sql_injection" in active:
        text = (repo / "app.py").read_text(encoding="utf-8")
        text = text.replace('query = "SELECT name FROM users WHERE name = ?"\n    return list(conn.execute(query, (username,)))', 'query = f"SELECT name FROM users WHERE name = \'{username}\'"\n    return list(conn.execute(query))')
        write_text(repo / "app.py", text)
        add(f"GT-SAST-SQLI-001-{repo.name}", "app.py", "sast", "semgrep", "high", "8.1", cwe="CWE-89", notes="String formatted SQL query")

    if "docker_misconfiguration" in active:
        text = (repo / "Dockerfile").read_text(encoding="utf-8")
        text = text.replace("RUN useradd -m appuser\nUSER appuser\n", "USER root\n")
        write_text(repo / "Dockerfile", text)
        add(f"GT-IAC-DOCKER-001-{repo.name}", "Dockerfile", "iac", "trivy", "medium", "5.0", notes="Container runs as root")

    if "k8s_misconfiguration" in active:
        text = (repo / "k8s" / "deployment.yaml").read_text(encoding="utf-8")
        text = text.replace("privileged: false", "privileged: true")
        text = text.replace("runAsNonRoot: true\n            runAsUser: 10001", "runAsUser: 0")
        write_text(repo / "k8s" / "deployment.yaml", text)
        add(f"GT-IAC-K8S-001-{repo.name}", "k8s/deployment.yaml", "iac", "trivy", "high", "7.5", notes="Privileged Kubernetes container")

    return rows


def main() -> None:
    all_gt_rows: list[dict[str, str]] = []
    design_rows: list[dict[str, str]] = []
    corpus_rows: list[dict[str, str]] = []
    for family in FAMILIES:
        for scenario in SCENARIOS:
            repo_id = f"full_{family}_{scenario}"
            repo_path = ROOT / "repos" / repo_id
            if repo_path.exists():
                shutil.rmtree(repo_path)
            shutil.copytree(SOURCE, repo_path, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
            make_clean(repo_path)
            gt_rows = inject(repo_path, scenario)
            all_gt_rows.extend(gt_rows)
            write_text(repo_path / "secflowops_scenario.json", json.dumps({"scenario": scenario, "family": family}, indent=2) + "\n")
            corpus_rows.append({
                "repo_id": repo_id,
                "origin_type": "controlled_full_protocol",
                "stack": "python",
                "size_class": "small",
                "scenario": scenario,
                "family": family,
                "file_count": str(len([p for p in repo_path.rglob("*") if p.is_file()])),
                "loc": "",
            })
            for repetition in range(1, 4):
                for config in CONFIGS:
                    design_rows.append({
                        "configuration_id": config.split("_", 1)[0],
                        "configuration_name": config,
                        "repo": repo_id,
                        "scenario": scenario,
                        "repetition": str(repetition),
                        "planned_for_smoke": "false",
                        "planned_for_full_study": "true",
                        "notes": f"full protocol {family} {scenario}",
                    })

    gt_path = ROOT / "repos" / "ground_truth" / "ground_truth_findings.csv"
    existing = []
    if gt_path.exists():
        with gt_path.open("r", encoding="utf-8", newline="") as f:
            existing = [r for r in csv.DictReader(f) if not r.get("repo", "").startswith("full_")]
    fieldnames = [
        "finding_id", "repo", "branch", "commit_intro", "commit_fix", "file", "line_start", "line_end",
        "type", "cwe", "cve", "tool_expected", "severity", "cvss", "source", "expected_detection",
        "expected_remediation", "match_message_contains", "notes",
    ]
    with gt_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(existing)
        writer.writerows(all_gt_rows)

    design_path = ROOT / "experiments" / "design_matrix.csv"
    with design_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(design_rows[0].keys()))
        writer.writeheader()
        writer.writerows(design_rows)

    manifest_path = ROOT / "experiments" / "full_protocol_corpus_manifest.csv"
    with manifest_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(corpus_rows[0].keys()))
        writer.writeheader()
        writer.writerows(corpus_rows)

    print(json.dumps({
        "repos": len(corpus_rows),
        "design_runs": len(design_rows),
        "ground_truth_rows_added": len(all_gt_rows),
        "design_matrix": str(design_path),
    }, indent=2))


if __name__ == "__main__":
    main()
