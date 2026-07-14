"""Calibrated remediation-policy sensitivity simulation.

The simulation is anchored to the full-protocol finding population.  For each
matched C1/C5 run pair, C1 supplies the unremediated finding set and C5 supplies
the empirically observed residual set after bounded remediation.  The only
simulated quantity is the probability that a finding observed as removable in C5
is removed before policy evaluation.
"""

from __future__ import annotations

import csv
import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FINDINGS = ROOT / "data" / "processed" / "finding_metrics_full_protocol.csv"
TABLE_DIR = ROOT / "tables"
FIGURE_DIR = ROOT / "figures"
OUT_CSV = TABLE_DIR / "calibrated_remediation_simulation.csv"
OUT_TABLE = TABLE_DIR / "calibrated_remediation_simulation_selected.csv"
OUT_FIGURE = FIGURE_DIR / "calibrated_remediation_simulation.png"

REMOVAL_PROBABILITIES = sorted({round(i / 10, 1) for i in range(0, 11)} | {0.25, 0.75})
SELECTED_PROBABILITIES = {0.0, 0.25, 0.5, 0.75, 1.0}
N_TRIALS = 200
SEED = 20260714


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    category: str
    severity: str
    cvss: float


def run_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (row["repo"], row["scenario"], row["repetition"])


def parse_cvss(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def load_run_sets() -> tuple[dict[tuple[str, str, str], dict[str, Finding]], dict[tuple[str, str, str], dict[str, Finding]]]:
    c1_initial: dict[tuple[str, str, str], dict[str, Finding]] = defaultdict(dict)
    c5_residual: dict[tuple[str, str, str], dict[str, Finding]] = defaultdict(dict)

    with FINDINGS.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            config = row["configuration"]
            stage = row["stage"]
            if not (
                (config == "C1_NonBlockingScanning" and stage == "initial")
                or (config == "C5_SecFlowOps" and stage == "residual")
            ):
                continue
            finding = Finding(
                fingerprint=row["fingerprint"],
                category=row["category"].lower(),
                severity=row["severity"].lower(),
                cvss=parse_cvss(row.get("cvss", "")),
            )
            target = c1_initial if config == "C1_NonBlockingScanning" else c5_residual
            target[run_key(row)][finding.fingerprint] = finding

    common_keys = sorted(set(c1_initial) & set(c5_residual))
    return (
        {key: c1_initial[key] for key in common_keys},
        {key: c5_residual[key] for key in common_keys},
    )


def policy_allows(findings: list[Finding]) -> tuple[bool, int, int, int, float]:
    critical = sum(1 for item in findings if item.severity == "critical")
    high = sum(1 for item in findings if item.severity == "high")
    secrets = sum(1 for item in findings if item.category == "secret")
    max_cvss = max((item.cvss for item in findings), default=0.0)
    allow = critical == 0 and high <= 3 and secrets == 0 and max_cvss <= 9.0
    return allow, critical, high, secrets, max_cvss


def simulate() -> list[dict[str, float | int]]:
    c1_initial, c5_residual = load_run_sets()
    rng = random.Random(SEED)
    rows: list[dict[str, float | int]] = []

    for probability in REMOVAL_PROBABILITIES:
        n_observations = 0
        allow_count = 0
        residual_total = 0
        critical_total = 0
        high_total = 0
        secret_total = 0
        max_cvss_total = 0.0

        for key, initial in c1_initial.items():
            sticky = c5_residual[key]
            removable = [item for fp, item in initial.items() if fp not in sticky]
            sticky_findings = list(sticky.values())

            for _ in range(N_TRIALS):
                retained = [
                    item for item in removable if rng.random() >= probability
                ]
                residual = sticky_findings + retained
                allow, critical, high, secrets, max_cvss = policy_allows(residual)
                n_observations += 1
                allow_count += int(allow)
                residual_total += len(residual)
                critical_total += critical
                high_total += high
                secret_total += secrets
                max_cvss_total += max_cvss

        rows.append(
            {
                "removal_probability": probability,
                "n_run_pairs": len(c1_initial),
                "n_trials_per_pair": N_TRIALS,
                "n_observations": n_observations,
                "allow_rate": allow_count / n_observations,
                "deny_rate": 1.0 - (allow_count / n_observations),
                "mean_residual_findings": residual_total / n_observations,
                "mean_residual_critical": critical_total / n_observations,
                "mean_residual_high": high_total / n_observations,
                "mean_residual_secrets": secret_total / n_observations,
                "mean_max_cvss": max_cvss_total / n_observations,
            }
        )

    return rows


def write_csv(path: Path, rows: list[dict[str, float | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_selected(rows: list[dict[str, float | int]]) -> None:
    selected = [
        row
        for row in rows
        if float(row["removal_probability"]) in SELECTED_PROBABILITIES
    ]
    write_csv(OUT_TABLE, selected)


def write_figure(rows: list[dict[str, float | int]]) -> bool:
    try:
        import matplotlib

        matplotlib.use("Agg", force=True)
        import matplotlib.pyplot as plt
    except (ImportError, ModuleNotFoundError) as exc:
        print(f"matplotlib is unavailable; skipping PNG figure generation: {exc}")
        return False

    FIGURE_DIR.mkdir(parents=True, exist_ok=True)
    x = [float(row["removal_probability"]) for row in rows]
    allow = [float(row["allow_rate"]) for row in rows]
    residual = [float(row["mean_residual_findings"]) for row in rows]

    try:
        fig, ax1 = plt.subplots(figsize=(6.2, 3.6))
        ax1.plot(x, allow, marker="o", color="#1f77b4", label="Policy allow rate")
        ax1.set_xlabel("Removable-finding removal probability")
        ax1.set_ylabel("Policy allow rate", color="#1f77b4")
        ax1.tick_params(axis="y", labelcolor="#1f77b4")
        ax1.set_ylim(-0.02, 1.02)

        ax2 = ax1.twinx()
        ax2.plot(x, residual, marker="s", color="#b23b3b", label="Mean residual findings")
        ax2.set_ylabel("Mean residual findings", color="#b23b3b")
        ax2.tick_params(axis="y", labelcolor="#b23b3b")

        fig.tight_layout()
        fig.savefig(OUT_FIGURE, dpi=300)
        plt.close(fig)
    except Exception as exc:
        print(f"Could not write PNG figure; CSV outputs remain valid: {exc}")
        return False
    return True


def main() -> None:
    rows = simulate()
    write_csv(OUT_CSV, rows)
    write_selected(rows)
    figure_written = write_figure(rows)
    print(f"Wrote {OUT_CSV.relative_to(ROOT)}")
    print(f"Wrote {OUT_TABLE.relative_to(ROOT)}")
    if figure_written:
        print(f"Wrote {OUT_FIGURE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
