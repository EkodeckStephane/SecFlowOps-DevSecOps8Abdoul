#!/usr/bin/env python3
"""Repository-aware descriptive analysis for the EMSE trajectory corpus."""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path


def bootstrap_mean(values: list[float], clusters: list[str], reps: int = 10000, seed: int = 20260831):
    if not values:
        return (math.nan, math.nan, math.nan)
    by_cluster: dict[str, list[float]] = defaultdict(list)
    for value, cluster in zip(values, clusters):
        by_cluster[cluster].append(value)
    keys = sorted(by_cluster)
    rng = random.Random(seed)
    boots = []
    for _ in range(reps):
        sampled_keys = [rng.choice(keys) for _ in keys]
        sample = [v for key in sampled_keys for v in by_cluster[key]]
        boots.append(sum(sample) / len(sample))
    boots.sort()
    lo = boots[int(0.025 * (len(boots) - 1))]
    hi = boots[int(0.975 * (len(boots) - 1))]
    return sum(values) / len(values), lo, hi


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="trajectory-level CSV")
    ap.add_argument("--output", required=True)
    ap.add_argument("--bootstrap", type=int, default=10000)
    args = ap.parse_args()

    with open(args.input, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    repos = [row.get("repo_slug", "") for row in rows]
    summary = {
        "n_trajectories": len(rows),
        "n_repositories": len(set(repos)),
        "ecosystems": dict(Counter(row.get("ecosystem", "unknown") for row in rows)),
        "cwe_categories": len(set(row.get("cwe_id", "") for row in rows if row.get("cwe_id"))),
    }
    for metric in ("resolved_count", "persistent_count", "new_count"):
        values, clusters = [], []
        for row in rows:
            try:
                values.append(float(row[metric]))
                clusters.append(row.get("repo_slug", "unknown"))
            except (KeyError, TypeError, ValueError):
                pass
        if values:
            mean, lo, hi = bootstrap_mean(values, clusters, args.bootstrap)
            summary[metric] = {
                "mean": mean,
                "cluster_bootstrap_95ci": [lo, hi],
                "n": len(values),
            }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
