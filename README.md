# SecFlowOps empirical artifact

SecFlowOps is the executable artifact for a finding-to-release-decision study of DevSecOps pipelines. The measured trajectory is:

`initial findings -> bounded remediation -> post-remediation rescan -> residual findings -> OPA/Rego release decision`

The artifact integrates Trivy, Semgrep, Gitleaks, npm audit, OWASP ZAP, and Open Policy Agent, and records normalized security evidence, remediation traces, policy decisions, timing measurements, advisory provenance, and CI validation.

## Final experimental configurations

The final analysis uses five behaviorally distinct configurations:

- `C0_BuildOnly`: build/test reference;
- `C1_ScanOnly`: initial security scanning;
- `C2_PolicyOnly`: scanning followed by OPA evaluation of the observed findings;
- `C3_RemediationOnly`: scanning, bounded remediation, and post-remediation rescanning;
- `C4_SecFlowOps`: scanning, bounded remediation, rescanning, and OPA evaluation of residual findings.

The controlled analysis contains 24 independent family-scenario workloads. Each workload has three technical repetitions under each configuration, yielding 360 retained measured executions. Statistical comparisons aggregate the technical repetitions within each workload before paired analysis.

## Main evidence

- Controlled matched workloads with workload-level paired effects and release-decision analysis.
- Open-source validation across Python, JavaScript/npm, security-benchmark, and Go repositories.
- An independent adjudication protocol for natural scanner findings; article-level external results use observed initial/residual evidence and release outcomes.
- Injected-external ground truth on real repository bases.
- NodeGoat dependency remediation and validated dependency migration.
- OWASP ZAP dynamic testing with a matched reflected-XSS ground-truth probe and a three-family breadth rerun.
- Frozen advisory snapshots and drift checks for advisory-sensitive measurements.
- GitHub Actions and protected-branch governance evidence.

## Reproduction entry points

The canonical reproduction guide is `SecFlowOps/artifact/README_REPRODUCE.md`.

Typical analysis commands are:

```powershell
python SecFlowOps\scripts\check_tools.py
python SecFlowOps\scripts\run_matrix.py --smoke
python SecFlowOps\scripts\compute_metrics.py
python SecFlowOps\scripts\statistical_analysis.py
```

The controlled protocol is launched with:

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_full_protocol_study.ps1 -Repetitions 3
```

## Toolchain recorded for the reported evidence

- Python 3.11.9
- Git 2.51.2
- Docker 29.6.1
- Java 24.0.1
- Trivy 0.71.2
- Semgrep 1.169.0
- OPA 1.18.2
- Gitleaks 8.30.1
- OWASP ZAP 2.17.0

## Reproducibility and provenance

The artifact stores processed measurements, normalized evidence, policies, analysis scripts, validation matrices, advisory manifests, selected checksums, and CI evidence. Advisory-sensitive numerical results are associated with the recorded frozen advisory state. Compatibility evidence is associated with the explicit native or fallback validation command recorded for each repository.

## Statistical outputs for the IST analysis

`SecFlowOps/scripts/reanalyze_ist_protocol.py` reconstructs the final five-configuration scientific comparison from the measured full-protocol dataset and produces:

- `ist_workload_level_metrics.csv`;
- `ist_descriptive_summary.csv`;
- `ist_paired_effects.csv`;
- `ist_paired_release_decisions.csv`.

The GitHub Actions workflow compiles the revised code, runs unit and Rego tests, regenerates these tables, and publishes them as CI evidence.
