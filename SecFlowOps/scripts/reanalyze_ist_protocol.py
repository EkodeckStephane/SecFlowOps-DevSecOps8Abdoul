from __future__ import annotations

import csv
import math
import random
import statistics
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data" / "processed" / "run_metrics_full_protocol.csv"

CONFIG_MAP = {
    "C0_BuildOnly": "BuildOnly",
    "C1_NonBlockingScanning": "ScanOnly",
    "C3_PolicyOnly": "PolicyOnly",
    "C4_AgentsOnly": "RemediationOnly",
    "C5_SecFlowOps": "SecFlowOps",
}

PAIRED_COMPARISONS = [
    ("PolicyOnly_vs_ScanOnly", "PolicyOnly", "ScanOnly"),
    ("RemediationOnly_vs_ScanOnly", "RemediationOnly", "ScanOnly"),
    ("SecFlowOps_vs_RemediationOnly", "SecFlowOps", "RemediationOnly"),
    ("SecFlowOps_vs_PolicyOnly", "SecFlowOps", "PolicyOnly"),
    ("SecFlowOps_vs_ScanOnly", "SecFlowOps", "ScanOnly"),
]


def read_csv(path: Path) -> list[dict[str, str]]:
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


def bootstrap_ci(values: list[float], *, n: int = 20000, seed: int = 20260825) -> tuple[float, float]:
    if not values:
        return math.nan, math.nan
    if len(values) == 1:
        return values[0], values[0]
    rng = random.Random(seed)
    means = [statistics.mean(rng.choice(values) for _ in values) for _ in range(n)]
    means.sort()
    return means[int(0.025 * (n - 1))], means[int(0.975 * (n - 1))]


def exact_binomial_two_sided(a: int, b: int) -> float:
    n = a + b
    if n == 0:
        return 1.0
    k = min(a, b)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2.0 * tail)


def holm_adjust(p_values: list[float]) -> list[float]:
    n = len(p_values)
    order = sorted(range(n), key=lambda i: p_values[i])
    adjusted = [1.0] * n
    monotone = 0.0
    for rank, idx in enumerate(order):
        candidate = min(1.0, (n - rank) * p_values[idx])
        monotone = max(monotone, candidate)
        adjusted[idx] = monotone
    return adjusted


def aggregate_workload_cells(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for row in rows:
        config = CONFIG_MAP.get(row["configuration"])
        if not config:
            continue
        grouped.setdefault((row["repo"], row["scenario"], config), []).append(row)

    out: list[dict[str, Any]] = []
    for (repo, scenario, config), reps in sorted(grouped.items()):
        times = [float(r["pipeline_time_seconds"]) for r in reps]
        initial = [float(r["finding_count_initial"]) for r in reps]
        residual = [float(r["finding_count_residual"]) for r in reps]
        policy_values = [
            r["policy_allow"].strip().lower() == "true"
            for r in reps
            if r.get("policy_engine") == "opa" and r.get("policy_allow", "") != ""
        ]
        out.append({
            "repo": repo,
            "scenario": scenario,
            "configuration": config,
            "technical_repetitions": len(reps),
            "mean_pipeline_time_seconds": statistics.mean(times),
            "median_pipeline_time_seconds": statistics.median(times),
            "mean_initial_findings": statistics.mean(initial),
            "mean_residual_findings": statistics.mean(residual),
            "mean_finding_reduction": statistics.mean(i - r for i, r in zip(initial, residual)),
            "release_allow": "" if not policy_values else policy_values[0] if len(set(policy_values)) == 1 else "mixed",
            "release_allow_rate_across_repetitions": "" if not policy_values else sum(policy_values) / len(policy_values),
        })
    return out


def descriptive_summary(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_config: dict[str, list[dict[str, Any]]] = {}
    for row in cells:
        by_config.setdefault(row["configuration"], []).append(row)
    out = []
    for config, rows in sorted(by_config.items()):
        allow_rows = [r for r in rows if r["release_allow"] in {True, False}]
        out.append({
            "configuration": config,
            "n_independent_workloads": len(rows),
            "technical_repetitions_per_workload": min(int(r["technical_repetitions"]) for r in rows),
            "mean_pipeline_time_seconds": statistics.mean(float(r["mean_pipeline_time_seconds"]) for r in rows),
            "median_workload_pipeline_time_seconds": statistics.median(float(r["mean_pipeline_time_seconds"]) for r in rows),
            "mean_initial_findings": statistics.mean(float(r["mean_initial_findings"]) for r in rows),
            "mean_residual_findings": statistics.mean(float(r["mean_residual_findings"]) for r in rows),
            "release_allow_rate": "" if not allow_rows else sum(bool(r["release_allow"]) for r in allow_rows) / len(allow_rows),
        })
    return out


def paired_effects(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(r["repo"], r["scenario"], r["configuration"]): r for r in cells}
    rows: list[dict[str, Any]] = []
    for name, lhs, rhs in PAIRED_COMPARISONS:
        for metric in ["mean_pipeline_time_seconds", "mean_residual_findings"]:
            deltas: list[float] = []
            for (repo, scenario, config), left in by_key.items():
                if config != lhs:
                    continue
                right = by_key.get((repo, scenario, rhs))
                if right is None:
                    continue
                deltas.append(float(left[metric]) - float(right[metric]))
            if not deltas:
                continue
            lo, hi = bootstrap_ci(deltas)
            nz = [d for d in deltas if d != 0]
            positives = sum(d > 0 for d in nz)
            p = exact_binomial_two_sided(positives, len(nz) - positives) if nz else 1.0
            sd = statistics.stdev(deltas) if len(deltas) > 1 else 0.0
            rows.append({
                "comparison": name,
                "lhs": lhs,
                "rhs": rhs,
                "metric": metric,
                "n_independent_workloads": len(deltas),
                "mean_paired_delta": statistics.mean(deltas),
                "median_paired_delta": statistics.median(deltas),
                "bootstrap_ci95_low": lo,
                "bootstrap_ci95_high": hi,
                "paired_effect_dz": "" if sd == 0 else statistics.mean(deltas) / sd,
                "exact_sign_test_p": p,
            })
    adjusted = holm_adjust([float(r["exact_sign_test_p"]) for r in rows])
    for row, p_adj in zip(rows, adjusted):
        row["holm_adjusted_p"] = p_adj
    return rows


def paired_release(cells: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(r["repo"], r["scenario"], r["configuration"]): r for r in cells}
    comparisons = [("SecFlowOps_vs_PolicyOnly", "SecFlowOps", "PolicyOnly")]
    out = []
    for name, lhs, rhs in comparisons:
        both_allow = lhs_allow_rhs_deny = lhs_deny_rhs_allow = both_deny = 0
        for (repo, scenario, config), left in by_key.items():
            if config != lhs:
                continue
            right = by_key.get((repo, scenario, rhs))
            if right is None or left["release_allow"] not in {True, False} or right["release_allow"] not in {True, False}:
                continue
            l, r = bool(left["release_allow"]), bool(right["release_allow"])
            if l and r:
                both_allow += 1
            elif l and not r:
                lhs_allow_rhs_deny += 1
            elif not l and r:
                lhs_deny_rhs_allow += 1
            else:
                both_deny += 1
        n = both_allow + lhs_allow_rhs_deny + lhs_deny_rhs_allow + both_deny
        if n:
            out.append({
                "comparison": name,
                "n_independent_workloads": n,
                "both_allow": both_allow,
                "secflowops_allow_policyonly_deny": lhs_allow_rhs_deny,
                "secflowops_deny_policyonly_allow": lhs_deny_rhs_allow,
                "both_deny": both_deny,
                "secflowops_allow_rate": (both_allow + lhs_allow_rhs_deny) / n,
                "policyonly_allow_rate": (both_allow + lhs_deny_rhs_allow) / n,
                "allow_rate_difference": (lhs_allow_rhs_deny - lhs_deny_rhs_allow) / n,
                "mcnemar_exact_p": exact_binomial_two_sided(lhs_allow_rhs_deny, lhs_deny_rhs_allow),
            })
    return out


def main() -> None:
    raw = read_csv(INPUT)
    retained = [r for r in raw if r["configuration"] in CONFIG_MAP]
    cells = aggregate_workload_cells(retained)
    write_csv(ROOT / "tables" / "ist_retained_execution_manifest.csv", retained)
    write_csv(ROOT / "tables" / "ist_workload_level_metrics.csv", cells)
    write_csv(ROOT / "tables" / "ist_descriptive_summary.csv", descriptive_summary(cells))
    write_csv(ROOT / "tables" / "ist_paired_effects.csv", paired_effects(cells))
    write_csv(ROOT / "tables" / "ist_paired_release_decisions.csv", paired_release(cells))
    print(f"retained_executions={len(retained)} workload_cells={len(cells)}")


if __name__ == "__main__":
    main()
