from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def bar(rows: list[dict[str, str]], metric: str, output: Path, ylabel: str) -> None:
    if not rows:
        return
    labels = [r["configuration"].replace("C", "C\n", 1) for r in rows]
    values = [float(r[metric]) for r in rows]
    fig, ax = plt.subplots(figsize=(9, 4.8))
    ax.bar(labels, values, color="#4C78A8")
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", alpha=0.3)
    ax.set_title(metric.replace("_", " "))
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def grouped_bar(rows: list[dict[str, str]], label_key: str, metric: str, output: Path, ylabel: str) -> None:
    if not rows:
        return
    labels = [r[label_key].replace("_", "\n") for r in rows]
    values = [float(r[metric]) for r in rows]
    fig, ax = plt.subplots(figsize=(10, 5.2))
    ax.bar(labels, values, color="#59A14F")
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", alpha=0.3)
    ax.set_title(metric.replace("_", " "))
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def line_by_size(rows: list[dict[str, str]], output: Path) -> None:
    if not rows:
        return
    order = ["small", "medium", "large", "xlarge", "xxlarge"]
    configs = sorted({row["configuration"] for row in rows})
    fig, ax = plt.subplots(figsize=(9.5, 5.2))
    for config in configs:
        values = []
        labels = []
        for size in order:
            matching = [row for row in rows if row["configuration"] == config and row["size_class"] == size]
            if matching:
                labels.append(size)
                values.append(float(matching[0]["mean_pipeline_time_seconds"]))
        if values:
            ax.plot(labels, values, marker="o", label=config)
    ax.set_ylabel("seconds")
    ax.set_title("pipeline time by repository size")
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=8)
    plt.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def text_diagram(title: str, boxes: list[str], output: Path) -> None:
    fig, ax = plt.subplots(figsize=(11, 3.5))
    ax.axis("off")
    ax.set_title(title, fontsize=14, pad=16)
    xs = np.linspace(0.08, 0.92, len(boxes))
    for i, (x, label) in enumerate(zip(xs, boxes)):
        ax.text(
            x,
            0.55,
            label,
            ha="center",
            va="center",
            bbox={"boxstyle": "round,pad=0.45", "fc": "#E8F0FE", "ec": "#4C78A8"},
            fontsize=9,
        )
        if i < len(boxes) - 1:
            ax.annotate("", xy=(xs[i + 1] - 0.055, 0.55), xytext=(x + 0.055, 0.55),
                        arrowprops={"arrowstyle": "->", "color": "#333333"})
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def metric_cluster(rows: list[dict[str, str]], metrics: list[str], output: Path, title: str) -> None:
    if not rows:
        return
    configs = [r["configuration"] for r in rows]
    x = np.arange(len(configs))
    width = 0.8 / len(metrics)
    fig, ax = plt.subplots(figsize=(10, 5.2))
    for i, metric in enumerate(metrics):
        values = [float(r.get(metric, 0.0) or 0.0) for r in rows]
        ax.bar(x + i * width, values, width=width, label=metric.replace("mean_", "").replace("_", " "))
    ax.set_xticks(x + width * (len(metrics) - 1) / 2)
    ax.set_xticklabels([c.replace("_", "\n") for c in configs], fontsize=8)
    ax.set_title(title)
    ax.grid(axis="y", alpha=0.3)
    ax.legend(fontsize=8)
    plt.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def heatmap(rows: list[dict[str, str]], output: Path, title: str) -> None:
    if not rows:
        return
    comparisons = sorted({r["comparison"] for r in rows})
    metrics = sorted({r["metric"] for r in rows})
    matrix = np.zeros((len(comparisons), len(metrics)))
    for r in rows:
        i = comparisons.index(r["comparison"])
        j = metrics.index(r["metric"])
        matrix[i, j] = float(r.get("mean_delta", 0.0) or 0.0)
    fig, ax = plt.subplots(figsize=(11, 5.5))
    im = ax.imshow(matrix, aspect="auto", cmap="coolwarm")
    ax.set_xticks(range(len(metrics)))
    ax.set_xticklabels([m.replace("_", "\n") for m in metrics], fontsize=8)
    ax.set_yticks(range(len(comparisons)))
    ax.set_yticklabels([c.replace("_", "\n") for c in comparisons], fontsize=8)
    ax.set_title(title)
    fig.colorbar(im, ax=ax, shrink=0.85)
    plt.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def policy_sensitivity_plot(rows: list[dict[str, str]], output: Path) -> None:
    if not rows:
        return
    filtered = [r for r in rows if r.get("block_on_secret") == "True" and float(r.get("cvss_ceiling", 0)) == 9.0]
    filtered.sort(key=lambda r: float(r["high_threshold"]))
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    ax.plot([float(r["high_threshold"]) for r in filtered], [float(r["allow_rate"]) for r in filtered], marker="o")
    ax.set_xlabel("high severity threshold")
    ax.set_ylabel("allow rate")
    ax.set_ylim(-0.05, 1.05)
    ax.set_title("policy sensitivity at CVSS ceiling 9.0 and block-on-secret enabled")
    ax.grid(alpha=0.3)
    plt.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def limitations_table(output: Path) -> None:
    rows = [
        ["External recall", "No complete natural OSS ground truth"],
        ["GitHub CI", "Workflow templates present; remote runs require repository auth"],
        ["DAST", "ZAP workflow present; local ZAP execution requires image/installation"],
        ["Remediation", "Local workspace patches unless PR workflow is run on GitHub"],
        ["Tool data", "Advisory databases are time-sensitive"],
    ]
    fig, ax = plt.subplots(figsize=(10, 3.8))
    ax.axis("off")
    table = ax.table(cellText=rows, colLabels=["Threat", "Current control"], loc="center", cellLoc="left")
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.6)
    ax.set_title("limitations and validity controls", pad=12)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def with_label(name: str, label: str) -> Path:
    stem, suffix = name.rsplit(".", 1)
    filename = f"{stem}_{label}.{suffix}" if label else name
    return ROOT / "figures" / filename


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="")
    args = parser.parse_args()
    suffix = f"_{args.label}" if args.label else ""

    rows = read_rows(ROOT / "tables" / f"summary_metrics{suffix}.csv")
    text_diagram(
        "SecFlowOps architecture",
        ["CI/CD", "Scanners", "Normalizer", "Remediator", "OPA Policy", "Metrics"],
        with_label("architecture_secflowops.png", args.label),
    )
    text_diagram(
        "CI/CD evidence flow",
        ["Checkout", "Build/Test", "Scan", "Normalize", "Patch", "Rescan", "Gate", "Archive"],
        with_label("cicd_flow.png", args.label),
    )
    bar(rows, "mean_pipeline_time_seconds", with_label("pipeline_time_by_config.png", args.label), "seconds")
    bar(rows, "pipeline_success_rate", with_label("pipeline_success_by_config.png", args.label), "rate")
    bar(rows, "mean_recall", with_label("recall_by_config.png", args.label), "recall")
    bar(rows, "mean_auto_remediation_rate", with_label("auto_remediation_by_config.png", args.label), "rate")
    metric_cluster(rows, ["mean_recall", "mean_precision"], with_label("coverage_precision_recall.png", args.label), "coverage, precision and recall")
    metric_cluster(rows, ["mean_mttd_seconds", "mean_mttr_seconds"], with_label("mttd_mttr_by_config.png", args.label), "MTTD and MTTR")

    perf = read_rows(ROOT / "tables" / f"performance_by_config{suffix}.csv")
    grouped_bar(perf, "configuration", "mean_total_scanner_time_seconds", with_label("performance_scanner_time_by_config.png", args.label), "seconds")
    grouped_bar(perf, "configuration", "mean_remediation_time_seconds", with_label("performance_remediation_time_by_config.png", args.label), "seconds")

    overheads = read_rows(ROOT / "tables" / f"performance_overheads{suffix}.csv")
    grouped_bar(overheads, "comparison", "mean_delta_seconds", with_label("performance_overheads.png", args.label), "delta seconds")

    perf_size = read_rows(ROOT / "tables" / f"performance_by_size{suffix}.csv")
    line_by_size(perf_size, with_label("performance_scaling_by_size.png", args.label))

    ablations = read_rows(ROOT / "tables" / f"ablation_results{suffix}.csv")
    heatmap(ablations, with_label("ablation_heatmap.png", args.label), "ablation mean deltas")

    sensitivity = read_rows(ROOT / "tables" / f"policy_sensitivity{suffix}.csv")
    policy_sensitivity_plot(sensitivity, with_label("policy_sensitivity.png", args.label))
    limitations_table(with_label("limitations_table.png", args.label))
    print("figures generated")


if __name__ == "__main__":
    main()
