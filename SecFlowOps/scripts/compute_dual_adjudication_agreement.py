from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def cohen_kappa(pairs: list[tuple[str, str]]) -> float:
    labels = sorted({label for pair in pairs for label in pair})
    if not pairs or len(labels) < 2:
        return 0.0
    observed = sum(1 for left, right in pairs if left == right) / len(pairs)
    expected = 0.0
    for label in labels:
        p_left = sum(1 for left, _ in pairs if left == label) / len(pairs)
        p_right = sum(1 for _, right in pairs if right == label) / len(pairs)
        expected += p_left * p_right
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1.0 - expected)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reviewer-a", default=str(ROOT / "data" / "manual_labels" / "external_adjudication_reviewer_a.csv"))
    parser.add_argument("--reviewer-b", default=str(ROOT / "data" / "manual_labels" / "external_adjudication_reviewer_b.csv"))
    parser.add_argument("--output", default=str(ROOT / "tables" / "dual_adjudication_agreement.csv"))
    args = parser.parse_args()

    rows_a = {row.get("adjudication_id", ""): row for row in read_csv(Path(args.reviewer_a))}
    rows_b = {row.get("adjudication_id", ""): row for row in read_csv(Path(args.reviewer_b))}
    common = sorted(set(rows_a) & set(rows_b))
    completed_pairs = []
    unresolved = 0
    for key in common:
        a = rows_a[key].get("true_positive", "").strip().lower()
        b = rows_b[key].get("true_positive", "").strip().lower()
        if not a or not b:
            unresolved += 1
            continue
        completed_pairs.append((a, b))

    agree = sum(1 for a, b in completed_pairs if a == b)
    rows = [{
        "n_common_findings": len(common),
        "n_completed_pairs": len(completed_pairs),
        "n_unresolved_pairs": unresolved,
        "raw_agreement": agree / len(completed_pairs) if completed_pairs else 0.0,
        "cohen_kappa_true_positive": cohen_kappa(completed_pairs),
        "status": "complete" if completed_pairs and unresolved == 0 else "pending_reviewer_labels",
    }]
    write_csv(Path(args.output), rows)
    print(rows[0])


if __name__ == "__main__":
    main()
