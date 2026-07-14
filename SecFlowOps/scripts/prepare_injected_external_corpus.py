from __future__ import annotations

import csv
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOS = ROOT / "repos"


BASES = [
    ("injected_requests", "external_requests", "python;pip;docker;kubernetes"),
    ("injected_flask", "external_flask", "python;pip;docker;kubernetes"),
    ("injected_express", "external_express", "javascript;npm;python;pip;docker;kubernetes"),
]


INJECTED_DIR = "secflowops_injected"


GROUND_TRUTH_TEMPLATE = [
    {
        "finding_id": "GT-INJECTED-SAST-XSS-001",
        "file": f"{INJECTED_DIR}/app.py",
        "line_start": "13",
        "line_end": "15",
        "type": "sast",
        "cwe": "CWE-79",
        "cve": "",
        "tool_expected": "semgrep",
        "severity": "high",
        "cvss": "7.4",
        "expected_remediation": "true",
        "match_message_contains": "",
        "notes": "Injected reflected unescaped query in real-repository copy",
    },
    {
        "finding_id": "GT-INJECTED-SAST-SQLI-001",
        "file": f"{INJECTED_DIR}/app.py",
        "line_start": "18",
        "line_end": "24",
        "type": "sast",
        "cwe": "CWE-89",
        "cve": "",
        "tool_expected": "semgrep",
        "severity": "high",
        "cvss": "8.1",
        "expected_remediation": "true",
        "match_message_contains": "",
        "notes": "Injected string-formatted SQL query in real-repository copy",
    },
    {
        "finding_id": "GT-INJECTED-SCA-DJANGO-001",
        "file": f"{INJECTED_DIR}/requirements.txt",
        "line_start": "1",
        "line_end": "1",
        "type": "sca",
        "cwe": "",
        "cve": "CVE-2019-19844",
        "tool_expected": "trivy",
        "severity": "critical",
        "cvss": "9.8",
        "expected_remediation": "true",
        "match_message_contains": "",
        "notes": "Injected vulnerable dependency pin in real-repository copy",
    },
    {
        "finding_id": "GT-INJECTED-SECRET-AWS-001",
        "file": f"{INJECTED_DIR}/.env.test",
        "line_start": "2",
        "line_end": "3",
        "type": "secret",
        "cwe": "",
        "cve": "",
        "tool_expected": "gitleaks",
        "severity": "critical",
        "cvss": "9.0",
        "expected_remediation": "true",
        "match_message_contains": "",
        "notes": "Injected fake AWS documentation key in real-repository copy",
    },
    {
        "finding_id": "GT-INJECTED-IAC-DOCKER-001",
        "file": f"{INJECTED_DIR}/Dockerfile",
        "line_start": "5",
        "line_end": "6",
        "type": "iac",
        "cwe": "",
        "cve": "",
        "tool_expected": "trivy",
        "severity": "medium",
        "cvss": "5.0",
        "expected_remediation": "true",
        "match_message_contains": "Image user should not be 'root'",
        "notes": "Injected root Docker runtime user in real-repository copy",
    },
    {
        "finding_id": "GT-INJECTED-IAC-K8S-001",
        "file": f"{INJECTED_DIR}/k8s/deployment.yaml",
        "line_start": "18",
        "line_end": "20",
        "type": "iac",
        "cwe": "",
        "cve": "",
        "tool_expected": "trivy",
        "severity": "high",
        "cvss": "7.5",
        "expected_remediation": "true",
        "match_message_contains": "Privileged",
        "notes": "Injected privileged Kubernetes container in real-repository copy",
    },
]


APP = '''#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import sqlite3


def render_search_response(query: str) -> str:
    body = f"<html><body>Search: {query}</body></html>"
    return body


def unsafe_user_lookup(username: str) -> list[tuple]:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (name TEXT)")
    conn.execute("INSERT INTO users VALUES ('alice')")
    query = f"SELECT name FROM users WHERE name = '{username}'"
    return list(conn.execute(query))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/search":
            query = parse_qs(parsed.query).get("q", [""])[0]
            self._send(200, render_search_response(query), "text/html")
            return
        if parsed.path == "/lookup":
            username = parse_qs(parsed.query).get("u", [""])[0]
            self._send(200, str(unsafe_user_lookup(username)))
            return
        self._send(404, "not found")

    def _send(self, status: int, payload: str, content_type: str = "text/plain") -> None:
        data = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
'''


DOCKERFILE = """FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
USER root
EXPOSE 8080
CMD ["python", "app.py"]
"""


DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: injected-api
spec:
  replicas: 1
  selector:
    matchLabels:
      app: injected-api
  template:
    metadata:
      labels:
        app: injected-api
    spec:
      containers:
        - name: injected-api
          image: injected-api:latest
          securityContext:
            privileged: true
            runAsUser: 0
          ports:
            - containerPort: 8080
"""


def safe_rmtree(target: Path) -> None:
    if not target.exists():
        return
    resolved_repos = REPOS.resolve()
    resolved_target = target.resolve()
    if resolved_repos not in resolved_target.parents or not target.name.startswith("injected_"):
        raise RuntimeError(f"Refusing to delete unexpected path: {target}")
    shutil.rmtree(target)


def copy_base(base_repo: str, target: Path) -> None:
    source = REPOS / base_repo
    if not source.exists():
        raise RuntimeError(f"Missing base repository: {source}")
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".venv",
            "venv",
            "node_modules",
            "dist",
            "build",
        ),
    )


def inject_findings(target: Path) -> None:
    injected = target / INJECTED_DIR
    (injected / "k8s").mkdir(parents=True, exist_ok=True)
    (injected / "app.py").write_text(APP, encoding="utf-8")
    (injected / "requirements.txt").write_text("django==2.2.0\nrequests==2.19.1\n", encoding="utf-8")
    (injected / ".env.test").write_text(
        "# Fake, invalid test secret. This value is the public AWS documentation example.\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        encoding="utf-8",
    )
    (injected / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    (injected / "k8s" / "deployment.yaml").write_text(DEPLOYMENT, encoding="utf-8")
    (injected / "README.md").write_text(
        "# SecFlowOps injected security fixtures\n\n"
        "These files add controlled vulnerabilities to a copy of a real open-source repository.\n",
        encoding="utf-8",
    )


def count_files_and_loc(repo: Path) -> tuple[int, int]:
    files = [path for path in repo.rglob("*") if path.is_file()]
    loc = 0
    for path in files:
        try:
            loc += len(path.read_text(encoding="utf-8").splitlines())
        except UnicodeDecodeError:
            pass
    return len(files), loc


def write_manifest(rows: list[dict[str, str]]) -> None:
    path = ROOT / "experiments" / "injected_external_corpus_manifest.csv"
    fieldnames = [
        "repo_id",
        "base_repo",
        "origin_type",
        "scenario",
        "stack",
        "file_count",
        "loc",
        "ground_truth_findings",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def update_ground_truth(repo_ids: list[str]) -> None:
    path = REPOS / "ground_truth" / "ground_truth_findings.csv"
    existing = []
    if path.exists():
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or [])
            existing = [row for row in reader if row.get("repo") not in repo_ids]
    else:
        fieldnames = [
            "finding_id",
            "repo",
            "branch",
            "commit_intro",
            "commit_fix",
            "file",
            "line_start",
            "line_end",
            "type",
            "cwe",
            "cve",
            "tool_expected",
            "severity",
            "cvss",
            "source",
            "expected_detection",
            "expected_remediation",
            "match_message_contains",
            "notes",
        ]
    if "match_message_contains" not in fieldnames:
        fieldnames = [*fieldnames[:-1], "match_message_contains", fieldnames[-1]]
        for row in existing:
            row.setdefault("match_message_contains", "")

    rows = existing[:]
    for repo_id in repo_ids:
        for row in GROUND_TRUTH_TEMPLATE:
            rows.append({
                **row,
                "finding_id": f"{row['finding_id']}-{repo_id}",
                "repo": repo_id,
                "branch": "injected_external_real_base",
                "commit_intro": "local",
                "commit_fix": "local",
                "source": "injected_external",
                "expected_detection": "true",
            })

    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_design_matrix(repo_ids: list[str], repetitions: int) -> None:
    path = ROOT / "experiments" / "injected_external_design_matrix.csv"
    configs = ["C1_NonBlockingScanning", "C4_AgentsOnly", "C5_SecFlowOps"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["configuration", "repo_id", "scenario", "planned_repetitions", "primary_metrics"])
        for repo_id in repo_ids:
            for config in configs:
                writer.writerow([
                    config,
                    repo_id,
                    "injected_external_real_base",
                    repetitions,
                    "recall;precision;residual_critical;residual_high;residual_secret;reviewed_resolution_rate;pipeline_time_seconds",
                ])


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()

    rows = []
    repo_ids = []
    for repo_id, base_repo, stack in BASES:
        target = REPOS / repo_id
        safe_rmtree(target)
        copy_base(base_repo, target)
        inject_findings(target)
        file_count, loc = count_files_and_loc(target)
        repo_ids.append(repo_id)
        rows.append({
            "repo_id": repo_id,
            "base_repo": base_repo,
            "origin_type": "injected_external_real_base",
            "scenario": "injected_external_real_base",
            "stack": stack,
            "file_count": str(file_count),
            "loc": str(loc),
            "ground_truth_findings": str(len(GROUND_TRUTH_TEMPLATE)),
            "notes": "Real open-source base repository with controlled injected SecFlowOps findings.",
        })

    write_manifest(rows)
    update_ground_truth(repo_ids)
    write_design_matrix(repo_ids, args.repetitions)
    print(f"prepared {len(repo_ids)} injected external repositories")
    print(" ".join(repo_ids))


if __name__ == "__main__":
    main()
