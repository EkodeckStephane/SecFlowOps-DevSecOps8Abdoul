from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "manual_labels" / "external_adjudication_template.csv"


REVIEW_COLUMNS = [
    "reviewer_id",
    "review_status",
    "true_positive",
    "confirmed_severity",
    "evidence_type",
    "remediation_required",
    "exploitability_assessment",
    "review_date",
    "review_notes",
]


CODEBOOK = """# Dual External Adjudication Codebook

Each external finding must be reviewed independently by two reviewers before consensus.

## Review status

- `confirmed`: repository evidence supports the finding under the scanner rule semantics.
- `rejected`: repository evidence contradicts the finding.
- `uncertain`: evidence is insufficient without additional runtime, advisory, or maintainer context.

## True positive

- `true`: the finding is valid under the documented evidence type.
- `false`: the finding is invalid under the documented evidence type.
- `unknown`: the reviewer cannot decide from the provided artifact.

## Evidence type

- `static_code`: source/configuration evidence only.
- `dependency_manifest`: manifest or lockfile evidence.
- `advisory_database`: CVE/GHSA/npm advisory evidence.
- `dynamic_runtime`: executable exploit or runtime observation.
- `secret_material`: committed credential/key/token evidence.

## Consensus rule

Consensus is accepted when both reviewers agree on `true_positive` and compatible severity.
Disagreements require a consensus row with a written reason; do not overwrite reviewer files.
"""


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def reviewer_rows(rows: list[dict[str, str]], reviewer_id: str) -> list[dict[str, str]]:
    out = []
    for row in rows:
        item = dict(row)
        item.update({
            "reviewer_id": reviewer_id,
            "review_status": "pending",
            "true_positive": "",
            "confirmed_severity": "",
            "evidence_type": "",
            "remediation_required": "",
            "exploitability_assessment": "",
            "review_date": "",
            "review_notes": "",
        })
        out.append(item)
    return out


def consensus_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    out = []
    for row in rows:
        out.append({
            "adjudication_id": row.get("adjudication_id", ""),
            "repo": row.get("repo", ""),
            "tool": row.get("tool", ""),
            "category": row.get("category", ""),
            "severity_reported": row.get("severity_reported", ""),
            "cve": row.get("cve", ""),
            "cwe": row.get("cwe", ""),
            "file": row.get("file", ""),
            "line_start": row.get("line_start", ""),
            "message": row.get("message", ""),
            "reviewer_a_true_positive": "",
            "reviewer_b_true_positive": "",
            "agreement": "",
            "consensus_true_positive": "",
            "consensus_severity": "",
            "consensus_evidence_type": "",
            "consensus_notes": "",
        })
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--prefix", default="external_adjudication")
    args = parser.parse_args()

    rows = read_csv(Path(args.input))
    if not rows:
        raise SystemExit(f"No adjudication rows found in {args.input}")
    base_fields = list(rows[0].keys())
    output_dir = ROOT / "data" / "manual_labels"
    write_csv(output_dir / f"{args.prefix}_reviewer_a.csv", reviewer_rows(rows, "reviewer_a"), base_fields + REVIEW_COLUMNS)
    write_csv(output_dir / f"{args.prefix}_reviewer_b.csv", reviewer_rows(rows, "reviewer_b"), base_fields + REVIEW_COLUMNS)
    write_csv(output_dir / f"{args.prefix}_consensus_template.csv", consensus_rows(rows), list(consensus_rows(rows)[0].keys()))
    (output_dir / f"{args.prefix}_dual_codebook.md").write_text(CODEBOOK, encoding="utf-8")
    print(f"prepared dual adjudication protocol for {len(rows)} findings")


if __name__ == "__main__":
    main()
