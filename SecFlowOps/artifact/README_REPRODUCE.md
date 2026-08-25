# SecFlowOps reproduction guide

This guide reproduces the SecFlowOps finding-to-release-decision experiments and the final workload-level analysis.

## Recorded toolchain

The reported local evidence records:

- Python 3.11.9
- Git 2.51.2
- Docker 29.6.1
- Java 24.0.1
- Trivy 0.71.2
- Semgrep 1.169.0
- OPA 1.18.2
- Gitleaks 8.30.1
- OWASP ZAP 2.17.0

Exact availability and paths are stored in `SecFlowOps/artifact/tool_status.json`.

## Smoke validation

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_smoke.ps1
```

The smoke workflow checks the toolchain and Rego policy, executes the five behaviorally distinct configurations, computes metrics, and runs the statistical-analysis scripts.

## Controlled protocol

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_full_protocol_study.ps1 -Repetitions 3 -CampaignId full_protocol_manual
```

The controlled design contains:

```text
3 codebase families x 8 scenarios = 24 independent workloads
24 workloads x 5 configurations x 3 technical repetitions = 360 executions
```

Configurations are `C0_BuildOnly`, `C1_ScanOnly`, `C2_PolicyOnly`, `C3_RemediationOnly`, and `C4_SecFlowOps`.

## Final workload-level analysis

The analysis treats the family-scenario workload as the independent unit. Technical repetitions are aggregated within each workload-configuration cell before paired comparisons.

For newly generated runs:

```powershell
python SecFlowOps\scripts\compute_metrics.py --label full_protocol
python SecFlowOps\scripts\statistical_analysis.py --label full_protocol
```

The final IST reanalysis of the recorded full-protocol dataset is generated with:

```powershell
python SecFlowOps\scripts\reanalyze_ist_protocol.py
```

It writes:

- `SecFlowOps/tables/ist_retained_execution_manifest.csv`
- `SecFlowOps/tables/ist_workload_level_metrics.csv`
- `SecFlowOps/tables/ist_descriptive_summary.csv`
- `SecFlowOps/tables/ist_paired_effects.csv`
- `SecFlowOps/tables/ist_paired_release_decisions.csv`

## External open-source study

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_external_study.ps1 -Repetitions 3 -CampaignId external_manual
```

The study executes ScanOnly, PolicyOnly, RemediationOnly, and SecFlowOps over five open-source repositories. Build/test behavior is recorded separately from scanner-to-policy evidence so application compatibility can be tied to explicit native or fallback validation commands.

## Extended external breadth and adjudication

The extended external corpus covers 11 repositories across Python, JavaScript/npm, security-benchmark, and Go ecosystems. Natural scanner findings are reviewed through the dual-adjudication protocol:

```powershell
python SecFlowOps\scripts\create_dual_adjudication_protocol.py
python SecFlowOps\scripts\compute_dual_adjudication_agreement.py
```

Adjudication records and consensus tables are stored under `SecFlowOps/data/manual_labels/` and `SecFlowOps/tables/`.

## NodeGoat dependency study

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_nodegoat_npm_study.ps1 -Repetitions 3 -CampaignId nodegoat_npm_manual
```

Package-manager baselines are generated with:

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_npm_audit_only_baseline.ps1 -Repetitions 3 -CampaignId npm_audit_only_manual
```

The validated migration follow-up uses the recorded NodeGoat workspace and executes smoke tests, Docker-backed Cypress tests, scanner reruns, npm audit, and OPA evaluation.

## Injected external ground truth

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_injected_external_study.ps1 -Repetitions 3 -CampaignId injected_external_manual
```

The study injects enumerated target findings into copies of real repositories, enabling scoped detection recall and residual-target measurement after remediation.

## Systematic OWASP ZAP study

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_dast_systematic_study.ps1 -CampaignId dast_systematic_manual -ActiveTimeout 120
```

The campaign records quick, baseline, and active modes over controlled public and authenticated targets, including raw ZAP JSON, crawl coverage, and target matching.

## Advisory reproducibility

Frozen and current advisory checks are separated:

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_advisory_frozen_rerun.ps1 -RunId advisory_frozen_manual
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_advisory_latest_rerun.ps1 -RunId advisory_latest_manual
```

The frozen state binds the numerical claims to the recorded advisory database. Current-database reruns provide drift measurements.

## Main output locations

- normalized findings: `SecFlowOps/data/normalized/`
- processed metrics: `SecFlowOps/data/processed/`
- workload and publication tables: `SecFlowOps/tables/`
- study records and CI evidence: `SecFlowOps/experiments/`
- OPA/Rego policies: `SecFlowOps/policies/rego/`
- integrity and advisory records: `SecFlowOps/artifact/`

GitHub Actions compiles the revised analysis code, executes unit and Rego tests, regenerates the final IST workload-level tables, and publishes those tables as workflow evidence.
