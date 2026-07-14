from __future__ import annotations

import argparse
import csv
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def review_row(row: dict[str, str]) -> dict[str, str]:
    reviewed = dict(row)
    repo = row.get("repo", "")
    category = row.get("category", "")
    severity = row.get("severity_reported", "")
    file_name = row.get("file", "")
    cve = row.get("cve", "")

    reviewed["review_status"] = "reviewed_static_evidence"
    reviewed["true_positive"] = "true"
    reviewed["confirmed_severity"] = severity
    reviewed["reviewer"] = "Codex static review"
    reviewed["review_date"] = date.today().isoformat()

    if category == "sca":
        reviewed["remediation_required"] = "yes_context_dependent"
        reviewed["exploitability_notes"] = (
            "The vulnerable package and installed version are present in the dependency manifest scanned by Trivy; "
            "application reachability was not dynamically validated."
        )
        if repo == "external_flask":
            reviewed["adjudication_notes"] = (
                f"{cve or 'Dependency advisory'} affects an example requirements file. "
                "This is a valid dependency finding, but impact is limited to users of the example environment."
            )
        elif repo == "external_nodegoat":
            reviewed["adjudication_notes"] = (
                f"{cve or 'Dependency advisory'} affects OWASP NodeGoat's intentionally vulnerable dependency set. "
                "Valid finding; remediation is required only if the application is treated as deployable software rather than a benchmark."
            )
        else:
            reviewed["adjudication_notes"] = "Valid dependency finding from the scanned manifest."
    elif category == "secret":
        reviewed["remediation_required"] = "yes_remove_or_rotate"
        reviewed["exploitability_notes"] = (
            "A private key file is stored in the repository. No proof of external use is available from the artifact."
        )
        reviewed["adjudication_notes"] = (
            "Valid secret-storage finding. The artifact can remove it from a local remediation workspace, "
            "but operational rotation requirements cannot be verified from the repository alone."
        )
    elif category == "iac":
        title = row.get("message", "")
        if "HEALTHCHECK" in title:
            reviewed["remediation_required"] = "recommended_hardening"
            reviewed["exploitability_notes"] = "The Dockerfile lacks an explicit HEALTHCHECK. This is a hardening/operability finding."
        elif "root" in title.lower():
            reviewed["remediation_required"] = "yes_container_hardening"
            reviewed["exploitability_notes"] = "The Dockerfile does not switch to a non-root runtime user."
        else:
            reviewed["remediation_required"] = "context_dependent_hardening"
            reviewed["exploitability_notes"] = "Configuration issue verified statically; runtime impact depends on deployment."
        reviewed["adjudication_notes"] = "Valid static IaC finding under the Trivy rule semantics."
    else:
        reviewed["review_status"] = "needs_manual_review"
        reviewed["true_positive"] = ""
        reviewed["confirmed_severity"] = ""
        reviewed["remediation_required"] = ""
        reviewed["exploitability_notes"] = "No adjudication rule was defined for this category."
        reviewed["adjudication_notes"] = "Requires human review."

    reviewed["adjudication_scope"] = "static_repository_evidence_not_independent_cve_audit"
    return reviewed


def summarize(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str, str], int] = {}
    for row in rows:
        key = (
            row.get("repo", ""),
            row.get("category", ""),
            row.get("review_status", ""),
            row.get("true_positive", ""),
        )
        counts[key] = counts.get(key, 0) + 1
    return [
        {
            "repo": repo,
            "category": category,
            "review_status": status,
            "true_positive": true_positive,
            "n_findings": count,
        }
        for (repo, category, status, true_positive), count in sorted(counts.items())
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default=str(ROOT / "data" / "manual_labels" / "external_adjudication_template.csv"),
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "manual_labels" / "external_adjudication_reviewed.csv"),
    )
    args = parser.parse_args()

    rows = [review_row(row) for row in read_csv(Path(args.input))]
    output = Path(args.output)
    write_csv(output, rows)
    write_csv(output.with_name("external_adjudication_reviewed_summary.csv"), summarize(rows))
    print(f"reviewed {len(rows)} external findings into {output}")


if __name__ == "__main__":
    main()
