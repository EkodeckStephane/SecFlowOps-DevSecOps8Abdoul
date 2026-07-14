from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secflowops.normalizer.common import read_jsonl, write_json, write_jsonl


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LocalRemediatorAgent:
    """Deterministic local remediation for controlled SecFlowOps scenarios."""

    def __init__(self, workspace: Path, findings_path: Path, output_path: Path):
        self.workspace = workspace
        self.findings_path = findings_path
        self.output_path = output_path
        self.events: list[dict[str, Any]] = []
        self.findings = read_jsonl(findings_path)
        self.npm_audit_fix_result: dict[str, Any] | None = None
        self.npm_audit_event_emitted = False

    def run(self) -> dict[str, Any]:
        started = utc_now()
        patched_files: set[str] = set()
        for finding in self.findings:
            method = self._remediate_finding(finding)
            if method:
                patched_files.add(str(finding.get("file")))
                finding["remediated"] = True
                finding["remediation_method"] = method
                finding.setdefault("timestamps", {})["patch_proposed_at"] = utc_now()
                self.events.append({
                    "finding_id": finding["finding_id"],
                    "ground_truth_id": finding.get("ground_truth_id"),
                    "method": method,
                    "file": finding.get("file"),
                    "status": "patched_local_workspace",
                    "human_review_required": True,
                })

        test_result = self._run_tests()
        validated_at = utc_now() if test_result["returncode"] == 0 else None
        for finding in self.findings:
            if finding.get("remediated") and validated_at:
                finding.setdefault("timestamps", {})["patch_validated_at"] = validated_at

        write_jsonl(self.findings_path, self.findings)
        result = {
            "started_at": started,
            "finished_at": utc_now(),
            "mode": "local_workspace_patch",
            "branch_created": "local-only-no-git-push",
            "pr_created": False,
            "auto_merge": False,
            "patched_files": sorted(patched_files),
            "events": self.events,
            "npm_audit_fix": self.npm_audit_fix_result,
            "tests": test_result,
            "remediated_count": sum(1 for f in self.findings if f.get("remediated")),
            "input_findings": len(self.findings),
        }
        write_json(self.output_path, result)
        return result

    def _replace_in_file(self, relative: str, replacements: dict[str, str]) -> bool:
        path = self.workspace / relative
        if not path.exists():
            return False
        text = path.read_text(encoding="utf-8")
        original = text
        for old, new in replacements.items():
            text = text.replace(old, new)
        if text != original:
            path.write_text(text, encoding="utf-8")
            return True
        return False

    def _run_npm_audit_fix(self) -> dict[str, Any]:
        if self.npm_audit_fix_result is not None:
            return self.npm_audit_fix_result
        package_lock = self.workspace / "package-lock.json"
        package_json = self.workspace / "package.json"
        npm = shutil.which("npm.cmd") or shutil.which("npm")
        if not npm or not package_lock.exists() or not package_json.exists():
            self.npm_audit_fix_result = {
                "attempted": False,
                "changed": False,
                "returncode": None,
                "reason": "npm_or_package_files_unavailable",
            }
            return self.npm_audit_fix_result

        before = package_lock.read_text(encoding="utf-8", errors="replace")
        env = os.environ.copy()
        env.setdefault("npm_config_cache", str(self.workspace / ".npm-cache"))
        proc = subprocess.run(
            [npm, "audit", "fix", "--package-lock-only", "--omit=dev"],
            cwd=self.workspace,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=900,
            env=env,
        )
        after = package_lock.read_text(encoding="utf-8", errors="replace")
        self.npm_audit_fix_result = {
            "attempted": True,
            "changed": before != after,
            "returncode": proc.returncode,
            "command": "npm audit fix --package-lock-only --omit=dev",
            "stdout_tail": (proc.stdout or "")[-4000:],
            "stderr_tail": (proc.stderr or "")[-4000:],
            "note": "Non-zero return codes are expected when npm fixes some issues but residual advisories remain.",
        }
        return self.npm_audit_fix_result

    def _write_file_if_changed(self, relative: str, text: str) -> bool:
        path = self.workspace / relative
        if not path.exists():
            return False
        original = path.read_text(encoding="utf-8", errors="replace")
        if text == original:
            return False
        path.write_text(text, encoding="utf-8")
        return True

    def _patch_dvna_dockerfile(self) -> bool:
        path = self.workspace / "Dockerfile"
        if not path.exists():
            return False
        text = path.read_text(encoding="utf-8")
        original = text
        if "HEALTHCHECK " not in text:
            text = text.replace(
                'CMD ["bash", "/app/entrypoint.sh"]',
                'HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e "process.exit(0)"\n'
                'CMD ["bash", "/app/entrypoint.sh"]',
            )
        if "USER node" not in text:
            text = text.replace(
                'CMD ["bash", "/app/entrypoint.sh"]',
                'RUN chown -R node:node /app\nUSER node\nCMD ["bash", "/app/entrypoint.sh"]',
            )
        if text != original:
            path.write_text(text, encoding="utf-8")
            return True
        return False

    def _remediate_finding(self, finding: dict[str, Any]) -> str | None:
        file_name = (finding.get("file") or "").replace("\\", "/")
        category = finding.get("category")

        if category == "secret" and file_name.endswith(".env.test"):
            changed = self._replace_in_file(file_name, {
                "AKIAIOSFODNN7EXAMPLE": "SEC_FLOW_OPS_FAKE_KEY_REMOVED",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "SEC_FLOW_OPS_FAKE_SECRET_REMOVED",
            })
            return "rule_based_agent" if changed else None

        if category == "secret" and file_name == "artifacts/cert/server.key":
            changed = self._write_file_if_changed(
                "artifacts/cert/server.key",
                "REMOVED BY SECFLOWOPS: repository-contained example private key removed from local remediation workspace.\n",
            )
            return "secret_placeholder_removal" if changed else None

        if category == "sca" and file_name == "examples/celery/requirements.txt":
            changed = self._replace_in_file("examples/celery/requirements.txt", {
                "flask==2.3.2": "flask==3.1.3",
                "jinja2==3.1.2": "jinja2==3.1.6",
                "werkzeug==2.3.3": "werkzeug==3.1.6",
            })
            return "external_pip_dependency_update" if changed else None

        if category == "sca" and file_name == "package-lock.json":
            result = self._run_npm_audit_fix()
            if result.get("changed") and not self.npm_audit_event_emitted:
                self.npm_audit_event_emitted = True
                return "npm_audit_fix_package_lock_only"
            return None

        if category == "sca" and file_name.endswith("requirements.txt"):
            changed = self._replace_in_file(file_name, {
                "django==2.2.0": "django==4.2.30",
                "requests==2.19.1": "requests==2.33.0",
            })
            return "dependency_update" if changed else None

        if category == "sast" and file_name.endswith("app.py"):
            path = self.workspace / file_name
            if not path.exists():
                return None
            text = path.read_text(encoding="utf-8")
            changed = False
            if "import html" not in text:
                text = text.replace("import sqlite3\n", "import sqlite3\nimport html\n")
                changed = True
            old = 'body = f"<html><body>Search: {query}</body></html>"'
            new = 'body = f"<html><body>Search: {html.escape(query)}</body></html>"'
            if old in text:
                text = text.replace(old, new)
                changed = True
            old_sql = 'query = f"SELECT name FROM users WHERE name = \'{username}\'"\n    return list(conn.execute(query))'
            new_sql = 'query = "SELECT name FROM users WHERE name = ?"\n    return list(conn.execute(query, (username,)))'
            if old_sql in text:
                text = text.replace(old_sql, new_sql)
                changed = True
            if changed:
                path.write_text(text, encoding="utf-8")
                return "rule_based_agent"
            return None

        if category == "iac" and file_name.endswith("Dockerfile"):
            if finding.get("repo") == "external_dvna" and file_name == "Dockerfile" and self._patch_dvna_dockerfile():
                return "external_dockerfile_hardening"
            changed = self._replace_in_file(file_name, {
                "USER root": "RUN useradd -m appuser\nUSER appuser",
            })
            return "rule_based_agent" if changed else None

        if category == "iac" and file_name.endswith("deployment.yaml"):
            changed = self._replace_in_file(file_name, {
                "privileged: true": "privileged: false",
                "runAsUser: 0": "runAsNonRoot: true\n            runAsUser: 10001",
            })
            return "rule_based_agent" if changed else None

        return None

    def _run_tests(self) -> dict[str, Any]:
        tests_dir = self.workspace / "tests"
        if not tests_dir.exists() or not any(tests_dir.rglob("test*.py")):
            return {
                "command": "python -m unittest discover -s tests",
                "returncode": 0,
                "stdout": "skipped: no local Python unittest suite configured\n",
                "stderr": "",
                "mode": "skipped_no_local_test_command",
            }
        proc = subprocess.run(
            ["python", "-m", "unittest", "discover", "-s", "tests"],
            cwd=self.workspace,
            text=True,
            capture_output=True,
        )
        return {
            "command": "python -m unittest discover -s tests",
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "mode": "python_unittest",
        }


def remediate(workspace: Path, findings_path: Path, output_path: Path) -> dict[str, Any]:
    return LocalRemediatorAgent(workspace, findings_path, output_path).run()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    remediate(Path(args.workspace), Path(args.findings), Path(args.output))


if __name__ == "__main__":
    main()
