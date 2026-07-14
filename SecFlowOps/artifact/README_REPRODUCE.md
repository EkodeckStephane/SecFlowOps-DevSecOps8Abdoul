# SecFlowOps Reproduction Notes

This artifact contains a controlled local smoke campaign for SecFlowOps. It uses real tools where available: Trivy for SCA/IaC/secret scanning, Semgrep for controlled SAST rules, Gitleaks for controlled secret detection, and OPA for policy decisions.

## Current Verified Tooling

The verified local status is written to `SecFlowOps/artifact/tool_status.json`.

Expected tools:

- Python 3.13
- Docker
- Java 24.0.1 or Java 17+
- Trivy 0.71.2
- Semgrep 1.169.0
- OPA 1.18.2, bundled at `SecFlowOps/tools/opa.exe`
- Gitleaks 8.30.1, bundled at `SecFlowOps/tools/gitleaks/gitleaks.exe`
- OWASP ZAP 2.17.0, bundled at `SecFlowOps/tools/zap/ZAP_2.17.0`

## Reproduce The Smoke Campaign

From the repository root:

```powershell
.\SecFlowOps\artifact\run_smoke.ps1
```

The script runs:

1. tool diagnostics;
2. OPA policy tests;
3. one repetition for `C0` through `C5`;
4. metric computation on the six latest campaign runs;
5. descriptive bootstrap summaries;
6. figure generation.

## Reproduce The Expanded Controlled Study

From the repository root:

```powershell
.\SecFlowOps\artifact\run_expanded_study.ps1 -Repetitions 3 -CampaignId expanded_manual
```

The expanded script generates five controlled repository variants, runs six configurations over each repository, and computes both security and performance metrics. With three repetitions this produces 90 runs.

## Reproduce The Full Protocol Study

From the repository root:

```powershell
.\SecFlowOps\artifact\run_full_protocol_study.ps1 -Repetitions 3 -CampaignId full_protocol_manual
```

This prepares 24 controlled repositories and executes:

```text
3 families x 8 scenarios x 6 configurations x 3 repetitions = 432 runs
```

Use `-PrepareOnly` to create only the repositories, design matrix, and ground truth without launching the long campaign.

## Reproduce The ZAP DAST Probe

ZAP requires Java 17 or later. This artifact was validated with:

```text
C:\Program Files\Java\jdk-24\bin\java.exe
```

The runner resolves Java 24 when present and uses the bundled ZAP Core archive. To run a targeted DAST probe:

```powershell
python SecFlowOps\scripts\run_matrix.py --campaign-id zap_manual --scenario auto --build-mode python_unittest --repetitions 1 --repos full_alpha_sast_reflected_xss --configs C1_NonBlockingScanning C3_PolicyOnly --enable-zap
```

The run starts the copied local API on a dynamically allocated loopback port, runs ZAP quick scan, and writes `scanner_outputs/zap.json`.

## Reproduce The External Open-Source Study

From the repository root:

```powershell
.\SecFlowOps\artifact\run_external_study.ps1 -Repetitions 3 -CampaignId external_manual
```

The external script clones or updates five open-source repositories, runs `C1`, `C2`, `C3`, `C4`, and `C5` over each repository, computes external security, adjudication, statistical, and performance summaries, and writes a reviewed first-pass adjudication table. With three repetitions this produces 75 runs. The command uses `--build-mode skip` because project-specific dependency installation and test execution are not part of the external security-pipeline measurement.

## Reproduce The NodeGoat npm Remediation Study

From the repository root:

```powershell
.\SecFlowOps\artifact\run_nodegoat_npm_study.ps1 -Repetitions 3 -CampaignId nodegoat_npm_manual
```

This script isolates OWASP NodeGoat and evaluates the npm remediation path. It runs `npm audit fix --package-lock-only --omit=dev` inside the temporary run workspace for agent configurations and measures the residual SCA findings after the post-remediation scan.

## Reproduce The npm audit-only Baseline

From the repository root:

```powershell
.\SecFlowOps\artifact\run_npm_audit_only_baseline.ps1 -Repetitions 3 -CampaignId npm_audit_only_manual
```

This script runs `npm audit fix --package-lock-only --omit=dev` without SecFlowOps secret remediation or OPA gating. It is used to separate package-manager remediation effects from the combined SecFlowOps pipeline.

## Reproduce The Injected External Recall Study

From the repository root:

```powershell
.\SecFlowOps\artifact\run_injected_external_study.ps1 -Repetitions 3 -CampaignId injected_external_manual
```

This script copies real OSS repositories, injects controlled SecFlowOps findings under `secflowops_injected/`, updates the ground-truth file, and evaluates recall/remediation on real repository bases with complete injected ground truth.

## Outputs

- Raw per-run logs: `SecFlowOps/data/raw/<run_id>/`
- Normalized findings: `SecFlowOps/data/normalized/`
- Per-run metrics: `SecFlowOps/data/processed/run_metrics.csv`
- External per-run metrics: `SecFlowOps/data/processed/run_metrics_external.csv`
- Summary table: `SecFlowOps/tables/summary_metrics.csv`
- External summary table: `SecFlowOps/tables/summary_metrics_external.csv`
- Descriptive bootstrap table: `SecFlowOps/tables/bootstrap_descriptives.csv`
- Performance components: `SecFlowOps/data/processed/performance_components.csv`
- Performance summaries: `SecFlowOps/tables/performance_by_config.csv`, `SecFlowOps/tables/performance_by_size.csv`, `SecFlowOps/tables/performance_overheads.csv`
- External performance summaries: `SecFlowOps/tables/performance_by_config_external.csv`, `SecFlowOps/tables/performance_by_size_external.csv`, `SecFlowOps/tables/performance_overheads_external.csv`
- External adjudication template: `SecFlowOps/data/manual_labels/external_adjudication_template.csv`
- Reviewed external adjudication: `SecFlowOps/data/manual_labels/external_adjudication_reviewed.csv`
- Adjudicated external metrics: `SecFlowOps/tables/summary_metrics_external_adjudicated.csv`, `SecFlowOps/tables/summary_metrics_external_adjudicated_by_repo.csv`
- External bootstrap descriptives: `SecFlowOps/tables/bootstrap_descriptives_external.csv`
- NodeGoat npm metrics: `SecFlowOps/tables/summary_metrics_nodegoat_npm.csv`, `SecFlowOps/tables/performance_by_config_nodegoat_npm.csv`
- npm audit-only baseline: `SecFlowOps/tables/npm_audit_only_baseline.csv`
- Injected external recall metrics: `SecFlowOps/tables/summary_metrics_injected_external.csv`, `SecFlowOps/tables/performance_by_config_injected_external.csv`, `SecFlowOps/tables/bootstrap_descriptives_injected_external.csv`
- Full protocol metrics: `SecFlowOps/tables/summary_metrics_full_protocol.csv`, `SecFlowOps/tables/performance_by_config_full_protocol.csv`, `SecFlowOps/tables/ablation_results_full_protocol.csv`, `SecFlowOps/tables/policy_sensitivity_full_protocol.csv`
- ZAP DAST probe metrics: `SecFlowOps/tables/summary_metrics_zap_probe_matched.csv`, `SecFlowOps/tables/performance_by_config_zap_probe_matched.csv`
- Figures: `SecFlowOps/figures/*.png`

## Scope Limitation

The smoke campaign is useful to validate the pipeline implementation, data schema, and measurement workflow. The expanded controlled study adds corpus size variation, repetitions, and performance measurement. The full protocol study executes the 432-run local controlled design. The external study adds real open-source repositories and an adjudication workflow. The NodeGoat npm study measures partial real npm remediation. The injected external study provides measurable recall for injected findings on real repository bases, but it is not a complete census of all naturally occurring vulnerabilities in those repositories. GitHub Actions workflows and PR creation require a valid GitHub repository and authenticated `gh` session; this workspace does not currently provide those prerequisites.
