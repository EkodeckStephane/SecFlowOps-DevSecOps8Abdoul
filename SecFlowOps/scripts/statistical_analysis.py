from __future__ import annotations

import argparse
import csv
import math
import random
import statistics
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

COMPARISONS = [
    ("PolicyOnly_vs_ScanOnly", "PolicyOnly", "ScanOnly"),
    ("RemediationOnly_vs_ScanOnly", "RemediationOnly", "ScanOnly"),
    ("SecFlowOps_vs_RemediationOnly", "SecFlowOps", "RemediationOnly"),
    ("SecFlowOps_vs_ScanOnly", "SecFlowOps", "ScanOnly"),
]
CONTINUOUS_METRICS = [
    "pipeline_time_seconds",
    "finding_count_residual",
    "ground_truth_recall",
    "residual_ground_truth_count",
]


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def numeric(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def bool_value(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    return value.lower() in {"true", "1", "yes"}


def bootstrap_mean_ci(values: list[float], n: int = 10000, seed: int = 42) -> tuple[float, float]:
    if not values:
        return math.nan, math.nan
    if len(values) == 1:
        return values[0], values[0]
    rng = random.Random(seed)
    means = []
    for _ in range(n):
        means.append(statistics.mean(rng.choice(values) for _ in values))
    means.sort()
    lo = means[int(0.025 * (n - 1))]
    hi = means[int(0.975 * (n - 1))]
    return lo, hi


def exact_two_sided_binomial(successes: int, trials: int) -> float:
    if trials == 0:
        return 1.0
    k = min(successes, trials - successes)
    tail = sum(math.comb(trials, i) for i in range(k + 1)) / (2 ** trials)
    return min(1.0, 2.0 * tail)


def sign_test_p(deltas: list[float]) -> float:
    nz = [d for d in deltas if d != 0]
    if not nz:
        return 1.0
    positives = sum(d > 0 for d in nz)
    return exact_two_sided_binomial(positives, len(nz))


def holm_adjust(p_values: list[float]) -> list[float]:
    n = len(p_values)
    order = sorted(range(n), key=lambda i: p_values[i])
    adjusted = [1.0] * n
    running = 0.0
    for rank, idx in enumerate(order):
        value = min(1.0, (n - rank) * p_values[idx])
        running = max(running, value)
        adjusted[idx] = running
    return adjusted


def aggregate_workloads(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for row in rows:
        key = (row["repo"], row["scenario"], row["configuration"])
        grouped.setdefault(key, []).append(row)

    out: list[dict[str, Any]] = []
    for (repo, scenario, config), reps in sorted(grouped.items()):
        item: dict[str, Any] = {
            "repo": repo,
            "scenario": scenario,
            "configuration": config,
            "technical_repetitions": len(reps),
        }
        for metric in CONTINUOUS_METRICS:
            vals = [v for r in reps if (v := numeric(r.get(metric))) is not None]
            item[metric] = "" if not vals else statistics.mean(vals)
        exec_vals = [bool_value(r.get("execution_success")) for r in reps]
        exec_vals = [v for v in exec_vals if v is not None]
        item["execution_completion_rate"] = "" if not exec_vals else sum(exec_vals) / len(exec_vals)

        release_vals = [bool_value(r.get("release_allowed")) for r in reps]
        release_vals = [v for v in release_vals if v is not None]
        if release_vals:
            item["release_allow_rate"] = sum(release_vals) / len(release_vals)
            item["release_consistent"] = len(set(release_vals)) == 1
            item["release_allowed"] = release_vals[0] if len(set(release_vals)) == 1 else ""
        else:
            item["release_allow_rate"] = ""
            item["release_consistent"] = ""
            item["release_allowed"] = ""
        out.append(item)
    return out


def paired_continuous(workloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(r["repo"], r["scenario"], r["configuration"]): r for r in workloads}
    results: list[dict[str, Any]] = []
    for comp_name, lhs, rhs in COMPARISONS:
        for metric in CONTINUOUS_METRICS:
            deltas: list[float] = []
            for repo, scenario, config in list(by_key):
                if config != lhs:
                    continue
                left = by_key[(repo, scenario, lhs)].get(metric)
                right = by_key.get((repo, scenario, rhs), {}).get(metric)
                if left == "" or right in (None, ""):
                    continue
                deltas.append(float(left) - float(right))
            if not deltas:
                continue
            lo, hi = bootstrap_mean_ci(deltas)
            sd = statistics.stdev(deltas) if len(deltas) > 1 else 0.0
            results.append({
                "comparison": comp_name,
                "lhs": lhs,
                "rhs": rhs,
                "metric": metric,
                "n_workloads": len(deltas),
                "mean_paired_delta": statistics.mean(deltas),
                "median_paired_delta": statistics.median(deltas),
                "bootstrap_ci95_low": lo,
                "bootstrap_ci95_high": hi,
                "paired_standardized_effect_dz": "" if sd == 0 else statistics.mean(deltas) / sd,
                "sign_test_p": sign_test_p(deltas),
            })

    pvals = [float(r["sign_test_p"]) for r in results]
    adjusted = holm_adjust(pvals) if pvals else []
    for row, adj in zip(results, adjusted):
        row["holm_adjusted_p"] = adj
    return results


def paired_release(workloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(r["repo"], r["scenario"], r["configuration"]): r for r in workloads}
    results: list[dict[str, Any]] = []
    for comp_name, lhs, rhs in COMPARISONS:
        both_allow = lhs_allow_rhs_deny = lhs_deny_rhs_allow = both_deny = 0
        for repo, scenario, config in list(by_key):
            if config != lhs:
                continue
            left = by_key[(repo, scenario, lhs)].get("release_allowed")
            right = by_key.get((repo, scenario, rhs), {}).get("release_allowed")
            if left == "" or right in (None, ""):
                continue
            left_b, right_b = bool(left), bool(right)
            if left_b and right_b:
                both_allow += 1
            elif left_b and not right_b:
                lhs_allow_rhs_deny += 1
            elif not left_b and right_b:
                lhs_deny_rhs_allow += 1
            else:
                both_deny += 1
        n = both_allow + lhs_allow_rhs_deny + lhs_deny_rhs_allow + both_deny
        if n == 0:
            continue
        discordant = lhs_allow_rhs_deny + lhs_deny_rhs_allow
        mcnemar_p = exact_two_sided_binomial(min(lhs_allow_rhs_deny, lhs_deny_rhs_allow), discordant) if discordant else 1.0
        lhs_allow_rate = (both_allow + lhs_allow_rhs_deny) / n
        rhs_allow_rate = (both_allow + lhs_deny_rhs_allow) / n
        results.append({
            "comparison": comp_name,
            "lhs": lhs,
            "rhs": rhs,
            "n_workloads": n,
            "both_allow": both_allow,
            "lhs_allow_rhs_deny": lhs_allow_rhs_deny,
            "lhs_deny_rhs_allow": lhs_deny_rhs_allow,
            "both_deny": both_deny,
            "lhs_allow_rate": lhs_allow_rate,
            "rhs_allow_rate": rhs_allow_rate,
            "allow_rate_difference": lhs_allow_rate - rhs_allow_rate,
            "mcnemar_exact_p": mcnemar_p,
        })
    pvals = [float(r["mcnemar_exact_p"]) for r in results]
    adjusted = holm_adjust(pvals) if pvals else []
    for row, adj in zip(results, adjusted):
        row["holm_adjusted_p"] = adj
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="")
    args = parser.parse_args()
    suffix = f"_{args.label}" if args.label else ""
    rows = read_rows(ROOT / "data" / "processed" / f"run_metrics{suffix}.csv")
    workloads = aggregate_workloads(rows)
    write_csv(ROOT / "tables" / f"workload_level_metrics{suffix}.csv", workloads)
    write_csv(ROOT / "tables" / f"paired_effects{suffix}.csv", paired_continuous(workloads))
    write_csv(ROOT / "tables" / f"paired_release_decisions{suffix}.csv", paired_release(workloads))
    print(f"aggregated {len(rows)} executions into {len(workloads)} workload-configuration cells")


if __name__ == "__main__":
    main()
