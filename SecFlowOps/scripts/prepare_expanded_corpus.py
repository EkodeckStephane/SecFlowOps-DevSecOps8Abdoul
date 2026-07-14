from __future__ import annotations

import csv
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOS = ROOT / "repos"


VARIANTS = [
    {"repo_id": "controlled_api_s", "size_class": "small", "benign_python_files": 0, "doc_files": 2},
    {"repo_id": "controlled_api_m", "size_class": "medium", "benign_python_files": 10, "doc_files": 10},
    {"repo_id": "controlled_api_l", "size_class": "large", "benign_python_files": 25, "doc_files": 25},
    {"repo_id": "controlled_api_xl", "size_class": "xlarge", "benign_python_files": 50, "doc_files": 50},
    {"repo_id": "controlled_api_xxl", "size_class": "xxlarge", "benign_python_files": 100, "doc_files": 100},
]

GROUND_TRUTH_TEMPLATE = [
    {
        "finding_id": "GT-SAST-XSS-001",
        "file": "app.py",
        "line_start": "14",
        "line_end": "16",
        "type": "sast",
        "cwe": "CWE-79",
        "cve": "",
        "tool_expected": "semgrep",
        "severity": "high",
        "cvss": "7.4",
        "expected_remediation": "true",
        "notes": "Reflected unescaped query in HTML response",
    },
    {
        "finding_id": "GT-SAST-SQLI-001",
        "file": "app.py",
        "line_start": "19",
        "line_end": "25",
        "type": "sast",
        "cwe": "CWE-89",
        "cve": "",
        "tool_expected": "semgrep",
        "severity": "high",
        "cvss": "8.1",
        "expected_remediation": "true",
        "notes": "String formatted SQL query",
    },
    {
        "finding_id": "GT-SCA-DJANGO-001",
        "file": "requirements.txt",
        "line_start": "1",
        "line_end": "1",
        "type": "sca",
        "cwe": "",
        "cve": "CVE-2019-19844",
        "tool_expected": "trivy",
        "severity": "critical",
        "cvss": "9.8",
        "expected_remediation": "true",
        "notes": "Vulnerable dependency pin used for scanner validation",
    },
    {
        "finding_id": "GT-SECRET-AWS-001",
        "file": ".env.test",
        "line_start": "2",
        "line_end": "3",
        "type": "secret",
        "cwe": "",
        "cve": "",
        "tool_expected": "gitleaks",
        "severity": "critical",
        "cvss": "9.0",
        "expected_remediation": "true",
        "notes": "Fake documented AWS test key",
    },
    {
        "finding_id": "GT-IAC-DOCKER-001",
        "file": "Dockerfile",
        "line_start": "5",
        "line_end": "6",
        "type": "iac",
        "cwe": "",
        "cve": "",
        "tool_expected": "trivy",
        "severity": "medium",
        "cvss": "5.0",
        "expected_remediation": "true",
        "notes": "Container runs as root",
    },
    {
        "finding_id": "GT-IAC-K8S-001",
        "file": "k8s/deployment.yaml",
        "line_start": "18",
        "line_end": "20",
        "type": "iac",
        "cwe": "",
        "cve": "",
        "tool_expected": "trivy",
        "severity": "high",
        "cvss": "7.5",
        "expected_remediation": "true",
        "notes": "Privileged Kubernetes container",
    },
]


def ensure_clean_variant(repo_id: str) -> Path:
    target = REPOS / repo_id
    resolved_repos = REPOS.resolve()
    if target.exists():
        resolved_target = target.resolve()
        if resolved_repos not in resolved_target.parents or not target.name.startswith("controlled_api_"):
            raise RuntimeError(f"Refusing to delete unexpected path: {target}")
        shutil.rmtree(target)
    return target


def copy_base_repo(target: Path) -> None:
    source = REPOS / "sample_api"
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))


def write_benign_python_files(target: Path, count: int) -> None:
    package = target / "benign_modules"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    for idx in range(1, count + 1):
        path = package / f"module_{idx:03d}.py"
        path.write_text(
            "\n".join([
                '"""Benign workload file used only for scanner performance scaling."""',
                "",
                f"CONSTANT_{idx} = {idx}",
                "",
                f"def compute_{idx}(value: int) -> int:",
                f"    return value + CONSTANT_{idx}",
                "",
            ]),
            encoding="utf-8",
        )


def write_doc_files(target: Path, count: int) -> None:
    docs = target / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    for idx in range(1, count + 1):
        (docs / f"note_{idx:03d}.md").write_text(
            f"# Controlled Note {idx}\n\nThis benign file increases repository size for performance measurements.\n",
            encoding="utf-8",
        )


def count_files_and_loc(target: Path) -> tuple[int, int]:
    files = [path for path in target.rglob("*") if path.is_file()]
    loc = 0
    for path in files:
        try:
            loc += len(path.read_text(encoding="utf-8").splitlines())
        except UnicodeDecodeError:
            pass
    return len(files), loc


def write_manifest(rows: list[dict[str, str]]) -> None:
    path = ROOT / "experiments" / "corpus_manifest.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "repo_id",
        "origin",
        "scenario",
        "stack",
        "size_class",
        "benign_python_files",
        "doc_files",
        "file_count",
        "loc",
        "ground_truth_findings",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_ground_truth(repo_ids: list[str]) -> None:
    path = REPOS / "ground_truth" / "ground_truth_findings.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
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
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for repo_id in ["sample_api", *repo_ids]:
            for row in GROUND_TRUTH_TEMPLATE:
                out = {
                    **row,
                    "finding_id": f"{row['finding_id']}-{repo_id}",
                    "repo": repo_id,
                    "branch": "controlled_multi_layer",
                    "commit_intro": "local",
                    "commit_fix": "local",
                    "source": "injected",
                    "expected_detection": "true",
                }
                writer.writerow(out)


def write_design_matrix(repo_ids: list[str]) -> None:
    path = ROOT / "experiments" / "expanded_design_matrix.csv"
    configs = [
        "C0_BuildOnly",
        "C1_NonBlockingScanning",
        "C2_AutoScanning",
        "C3_PolicyOnly",
        "C4_AgentsOnly",
        "C5_SecFlowOps",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["configuration", "repo_id", "scenario", "planned_repetitions", "primary_metrics"])
        for repo_id in repo_ids:
            for config in configs:
                writer.writerow([
                    config,
                    repo_id,
                    "controlled_multi_layer",
                    3,
                    "pipeline_time_seconds;scanner_time_seconds;recall;precision;residual_critical;residual_high;mttr_seconds",
                ])


def main() -> None:
    manifest_rows: list[dict[str, str]] = []
    repo_ids = []
    for variant in VARIANTS:
        repo_id = variant["repo_id"]
        target = ensure_clean_variant(repo_id)
        copy_base_repo(target)
        write_benign_python_files(target, int(variant["benign_python_files"]))
        write_doc_files(target, int(variant["doc_files"]))
        (target / "README.md").write_text(
            f"# {repo_id}\n\nControlled SecFlowOps repository variant for expanded experiments.\n",
            encoding="utf-8",
        )
        file_count, loc = count_files_and_loc(target)
        repo_ids.append(repo_id)
        manifest_rows.append({
            "repo_id": repo_id,
            "origin": "generated_controlled",
            "scenario": "controlled_multi_layer",
            "stack": "python;pip;docker;kubernetes",
            "size_class": variant["size_class"],
            "benign_python_files": str(variant["benign_python_files"]),
            "doc_files": str(variant["doc_files"]),
            "file_count": str(file_count),
            "loc": str(loc),
            "ground_truth_findings": str(len(GROUND_TRUTH_TEMPLATE)),
            "notes": "Same injected security findings; benign files vary scanner workload size.",
        })

    write_manifest(manifest_rows)
    write_ground_truth(repo_ids)
    write_design_matrix(repo_ids)
    print(f"prepared {len(repo_ids)} controlled repositories")
    print(" ".join(repo_ids))


if __name__ == "__main__":
    main()
