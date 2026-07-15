# SecFlowOps DevSecOps Empirical Artifact

SecFlowOps is an executable research artifact for evaluating the trajectory from security scanner findings to remediation, post-remediation rescanning, residual-risk measurement, and Open Policy Agent (OPA) policy decisions in a CI/CD-style workflow.

This repository contains the public artifact for the SecFlowOps study. It is not only source code: it includes controlled benchmarks, external open-source campaign outputs, raw scanner logs, normalized findings, processed metrics, statistical tables, dynamic testing evidence, application-validation matrices, advisory reproducibility archives, and GitHub governance evidence.

## What Was Built

The artifact implements and evaluates a DevSecOps pipeline that combines:

- Trivy for software composition analysis, secret scanning, IaC/container checks, and filesystem scans;
- Semgrep for controlled static application security testing;
- Gitleaks for secret detection;
- npm audit for JavaScript dependency remediation baselines;
- OWASP ZAP for dynamic web-application testing;
- OPA/Rego for residual-risk policy gates;
- GitHub Actions for remote CI and PR validation.

The main experimental comparison uses six configurations:

- `C0_BaselineNoSecurity`: baseline without security automation;
- `C1_NonBlockingScanning`: scanner-only, non-blocking pipeline;
- `C2_AutoScanning`: automated scanning path;
- `C3_PolicyOnly`: OPA policy gate over residual findings;
- `C4_AgentsOnly`: remediation-agent path without the full SecFlowOps gate;
- `C5_SecFlowOps`: scanner, remediation, rescan, residual-risk, and policy-gated pipeline.

## Main Evidence Produced

The repository records several layers of evidence.

### Controlled Protocol

- A full controlled protocol with 432 local runs.
- A controlled size study with 90 runs.
- Injected ground truth for SAST, SCA, secrets, and IaC/security findings.
- Raw scanner outputs, normalized findings, residual findings, remediation traces, and OPA decisions.
- Main tables under `SecFlowOps/tables/`, including full-protocol summary, performance, ablation, and policy-sensitivity tables.

### External Open-Source Validation

- External campaigns over real open-source projects from Python, JavaScript/npm, security-benchmark, and Go ecosystems.
- Extended external corpus of 11 repositories.
- Native application-validation matrix separating `tested_pass`, `tested_fail`, and `not_testable_with_reason` repositories.
- Compatibility claims are restricted to projects whose native tests passed before and after the checked workspace.

### Dual Adjudication Of Natural Findings

- Two independent reviewer files were prepared and completed for 94 natural findings.
- Final adjudication status: 94 completed findings, 93 direct agreements, 1 consensus-resolved disagreement, 0 open disagreements.
- Consensus and agreement evidence is stored under `SecFlowOps/data/manual_labels/` and `SecFlowOps/tables/`.

### NodeGoat Dependency Migration

The initial non-breaking npm remediation left critical/high residual findings on OWASP NodeGoat. A follow-up migration was performed to replace abandoned or breaking dependencies, adapt the application, and verify the migrated state.

Recorded result:

- residual critical findings: 0;
- residual high findings: 0;
- residual secrets: 0;
- residual state: one low finding;
- OPA C5 decision: `allow=true`;
- smoke tests: passed;
- Docker-backed Cypress end-to-end suite: 13 specs, 64/64 tests passing;
- no use of `npm audit --force` as sufficient remediation proof.

### Systematic DAST Campaign

The earlier focused ZAP probe was replaced by a systematic DAST campaign:

- two controlled web targets: public and authenticated;
- three ZAP modes: quick, baseline, active;
- vulnerability classes: reflected XSS, stored XSS, SQL injection, auth/session cookie hardening, insecure headers, and CSRF;
- authenticated crawl coverage for protected paths;
- complete ZAP JSON and daemon logs;
- active-scan recall: 11/11 controlled DAST ground-truth items;
- mean endpoint coverage: 1.0.

### Advisory Reproducibility And Drift Control

The artifact freezes the advisory-sensitive state used by numerical vulnerability claims.

Frozen state includes:

- full Trivy cache archive: `SecFlowOps/artifact/frozen_advisories/trivy_cache_frozen_20260715.tar`;
- package-lock snapshots;
- archived npm audit JSON outputs;
- Node and npm versions;
- Docker image digests and frozen compose file;
- exported NodeGoat OCI image;
- Semgrep, Gitleaks, Rego, ZAP, and Trivy hash records.

Recorded checks:

- frozen rerun: 5/5 advisory-sensitive count rows reproduced;
- latest rerun: 5/5 rows completed against a separate latest Trivy cache;
- latest drift: zero count drift in `SecFlowOps/tables/advisory_latest_drift.csv`.

The paper's numerical vulnerability/advisory claims are tied to the frozen manifest, not to mutable future advisory databases.

### Remote GitHub CI And Governance

The repository includes GitHub Actions workflows for remote CI and remediation-PR evidence. The governance hardening adds:

- root `README.md` describing the public artifact;
- `.github/CODEOWNERS` assigning review ownership to independent collaborators;
- branch protection on `main`;
- required CI checks;
- two required approving reviewers;
- code-owner review requirement;
- stale-review dismissal;
- self-approval refusal evidence;
- exported GitHub API JSON evidence under `SecFlowOps/experiments/github_governance_evidence/`.

## Repository Layout

```text
.github/workflows/              Remote GitHub Actions workflows
SecFlowOps/artifact/            Reproduction wrappers, requirements, checksums, frozen advisory archives
SecFlowOps/data/raw/            Raw run logs and scanner outputs
SecFlowOps/data/normalized/     Normalized finding records
SecFlowOps/data/processed/      Metrics, validation outputs, and derived records
SecFlowOps/experiments/         Study reports and evidence manifests
SecFlowOps/figures/             Generated figures
SecFlowOps/literature/          Related-work and source-verification material
SecFlowOps/policies/rego/       OPA policy and tests
SecFlowOps/repos/               Controlled and external workspaces used by the artifact
SecFlowOps/scanners/            Local scanner configurations
SecFlowOps/scripts/             Experiment, validation, summarization, and reproducibility scripts
SecFlowOps/tables/              Publication-facing tables and metric summaries
SecFlowOps/tools/               Bundled OPA, Gitleaks, and ZAP tools where applicable
```

## Reproduction Entry Points

The canonical reproduction guide is:

```text
SecFlowOps/artifact/README_REPRODUCE.md
```

Typical commands from the repository parent directory are:

```powershell
python SecFlowOps\scripts\check_tools.py
python SecFlowOps\scripts\run_matrix.py --smoke
python SecFlowOps\scripts\compute_metrics.py
python SecFlowOps\scripts\statistical_analysis.py
python SecFlowOps\scripts\generate_figures.py
```

Focused reproduction commands include:

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_dast_systematic_study.ps1 -CampaignId dast_systematic_manual -ActiveTimeout 120
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_advisory_frozen_rerun.ps1 -RunId advisory_frozen_manual
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_advisory_latest_rerun.ps1 -RunId advisory_latest_manual
```

For NodeGoat migration validation:

```powershell
Push-Location .\SecFlowOps\repos\external_nodegoat
npm install --omit=dev
npm run smoke
npm run test:e2e
Pop-Location
```

## Toolchain

The checked local environment recorded in `SecFlowOps/artifact/tool_status.json` includes:

- Python 3.11.9;
- Git 2.51.2;
- Docker 29.6.1;
- Java 24.0.1;
- Trivy 0.71.2;
- Semgrep 1.169.0;
- OPA 1.18.2;
- Gitleaks 8.30.1;
- OWASP ZAP 2.17.0;
- Node v25.2.1 and npm 11.6.2 for the frozen advisory follow-up.

GitHub Actions uses its own Ubuntu runner environment and records remote CI evidence separately.

## Integrity And Traceability

Important traceability files:

- `SecFlowOps/artifact/checksums.sha256`;
- `SecFlowOps/experiments/advisory_snapshot_manifest.json`;
- `SecFlowOps/tables/advisory_snapshot_manifest.csv`;
- `SecFlowOps/experiments/priority_validation_execution_report.md`;
- `SecFlowOps/experiments/github_actions_evidence.md`;
- `SecFlowOps/experiments/github_governance_evidence/`.

Checksums include the frozen Trivy cache archive, latest Trivy DB file used for drift checking, paper PDF, scripts, tables, and selected raw rerun evidence.

## Scope Boundaries

This artifact supports auditability of the SecFlowOps experimental workflow. It does not claim that arbitrary software can be automatically repaired or safely deployed. External natural-vulnerability recall is not claimed unless complete ground truth exists. Compatibility claims are limited to repositories with explicit native test evidence. Latest advisory reruns are diagnostic drift checks and are reported separately from frozen numerical claims.

## Citation And Use

Use this repository as the executable artifact for the SecFlowOps study. When reporting numerical vulnerability/advisory results, cite the frozen advisory manifest and the corresponding table or raw run evidence rather than rerunning against mutable online advisory databases without recording drift.