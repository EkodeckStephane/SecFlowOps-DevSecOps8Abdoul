from __future__ import annotations

import argparse
import csv
import random
import statistics
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def bootstrap_ci(values: list[float], *, n: int = 1000) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], values[0]
    means = []
    rng = random.Random(42)
    for _ in range(n):
        sample = [rng.choice(values) for _ in values]
        means.append(statistics.mean(sample))
    means.sort()
    return means[int(0.025 * n)], means[int(0.975 * n)]


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="", help="Optional input/output label, e.g. external reads run_metrics_external.csv.")
    args = parser.parse_args()

    suffix = f"_{args.label}" if args.label else ""
    rows = read_rows(ROOT / "data" / "processed" / f"run_metrics{suffix}.csv")
    metrics = ["pipeline_time_seconds", "recall", "precision", "auto_remediation_rate", "mttr_seconds"]
    out = []
    configs = sorted({row["configuration"] for row in rows})
    for config in configs:
        config_rows = [row for row in rows if row["configuration"] == config]
        for metric in metrics:
            values = [float(row[metric]) for row in config_rows]
            lo, hi = bootstrap_ci(values)
            out.append({
                "configuration": config,
                "metric": metric,
                "n": len(values),
                "mean": statistics.mean(values) if values else 0.0,
                "median": statistics.median(values) if values else 0.0,
                "bootstrap_ci95_low": lo,
                "bootstrap_ci95_high": hi,
                "note": "Descriptive bootstrap interval; not a substitute for independent replication" if len(values) < 30 else "",
            })
    write_csv(ROOT / "tables" / f"bootstrap_descriptives{suffix}.csv", out)
    print(f"wrote {len(out)} descriptive rows")


if __name__ == "__main__":
    main()
