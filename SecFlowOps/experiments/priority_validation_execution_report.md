# Priority Validation Execution Report

Date: 2026-07-14

This report records the execution of priority limits 1, 2, 4, and 6 from `SecFlowOps/VALIDATION_LIMITS_ROADMAP.md`.

## Priority 1: External validation breadth

Status: executed, with remaining adjudication limits.

The external corpus was expanded to 11 repositories across Python, JavaScript/npm, security-benchmark, and Go ecosystems:

- `external_requests`
- `external_flask`
- `external_click`
- `external_itsdangerous`
- `external_express`
- `external_body_parser`
- `external_morgan`
- `external_nodegoat`
- `external_dvna`
- `external_gorilla_mux`
- `external_gorilla_websocket`

The manifest is recorded in `SecFlowOps/experiments/extended_external_corpus_manifest.csv`.
The campaign `priority_validation_extended_external` ran three configurations over these 11 repositories:

- `C1_NonBlockingScanning`
- `C4_AgentsOnly`
- `C5_SecFlowOps`

Executed runs: 33.
Successful runs: 31.
Policy-blocked runs: 2.

The two blocked runs were expected policy-denial outcomes, not tool crashes:

- `external_nodegoat`, `C5_SecFlowOps`: 31 residual findings, including 3 critical and 12 high findings; OPA denied the pipeline.
- `external_gorilla_websocket`, `C5_SecFlowOps`: 12 residual findings, including 5 high findings; OPA denied the pipeline.

Key outputs:

- `SecFlowOps/data/processed/run_metrics_extended_external.csv`
- `SecFlowOps/data/processed/finding_metrics_extended_external.csv`
- `SecFlowOps/data/processed/remediation_metrics_extended_external.csv`
- `SecFlowOps/tables/summary_metrics_extended_external.csv`
- `SecFlowOps/tables/performance_by_config_extended_external.csv`
- `SecFlowOps/tables/performance_overheads_extended_external.csv`
- `SecFlowOps/tables/bootstrap_descriptives_extended_external.csv`

Scientific interpretation: this expands external breadth and records real scanner/policy/remediation behavior on 11 OSS repositories. It does not create complete natural ground truth for every true vulnerability in those repositories; therefore natural precision/recall remains unresolved until adjudication is completed.

## Priority 2: Natural external finding adjudication

Status: protocol implemented; independent adjudication not yet completed.

The extended external campaign produced 94 unique natural findings in the adjudication template:

- `external_nodegoat`: 67
- `external_flask`: 13
- `external_gorilla_websocket`: 12
- `external_dvna`: 2

Generated reviewer artifacts:

- `SecFlowOps/data/manual_labels/external_adjudication_template.csv`
- `SecFlowOps/data/manual_labels/external_adjudication_reviewer_a.csv`
- `SecFlowOps/data/manual_labels/external_adjudication_reviewer_b.csv`
- `SecFlowOps/data/manual_labels/external_adjudication_consensus_template.csv`
- `SecFlowOps/data/manual_labels/external_adjudication_dual_codebook.md`
- `SecFlowOps/tables/dual_adjudication_agreement.csv`

Current agreement status:

- common findings: 94
- completed reviewer pairs: 0
- unresolved pairs: 94
- status: `pending_reviewer_labels`

Scientific interpretation: the single-reviewer limitation has been structurally addressed by a two-reviewer protocol and agreement computation, but it is not yet scientifically lifted because the two independent reviewer files have not been completed.

## Priority 4: DAST breadth

Status: executed on three controlled dynamic targets.

The campaign `priority_validation_zap_breadth` ran OWASP ZAP against three reflected-XSS controlled targets:

- `full_alpha_sast_reflected_xss`
- `full_beta_sast_reflected_xss`
- `full_gamma_sast_reflected_xss`

Configurations:

- `C1_NonBlockingScanning`
- `C3_PolicyOnly`

Executed runs: 6.
Successful runs: 6.
Tool failures: 0.

Summary:

- mean initial findings: 23 per run
- ZAP finding rows: 28 per target in `finding_metrics_zap_breadth.csv`
- mean recall against the available controlled ground truth: 0.5
- mean precision under the current ground-truth matching rules: 0.043478260869565216

Key outputs:

- `SecFlowOps/data/processed/run_metrics_zap_breadth.csv`
- `SecFlowOps/data/processed/finding_metrics_zap_breadth.csv`
- `SecFlowOps/tables/summary_metrics_zap_breadth.csv`
- `SecFlowOps/tables/performance_by_config_zap_breadth.csv`
- `SecFlowOps/tables/bootstrap_descriptives_zap_breadth.csv`

Scientific interpretation: the earlier single-target DAST limitation is reduced because ZAP now executes on three independently generated controlled targets. The DAST evidence remains focused on reflected-XSS-style local targets and should not be generalized to broad web-application DAST coverage.

## Priority 6: Application regression validation

Status: executed for two repositories with practical native tests.

The campaign `priority_validation_regression` ran native tests before and after SecFlowOps remediation workspaces for:

- `external_gorilla_mux`
- `external_gorilla_websocket`

Command:

```text
go test ./...
```

Results:

- `external_gorilla_mux`: before return code 0; after return code 0.
- `external_gorilla_websocket`: before return code 0; after return code 0.
- remediated findings in both after-workspaces: 0.

Key output:

- `SecFlowOps/data/processed/application_regression_checks_priority_validation.csv`

Scientific interpretation: this verifies native build/test preservation on two executable Go projects. Because no automatic remediation was applied in these two runs, this is evidence of non-regression for the pipeline workspace, not evidence that every future generated patch preserves application semantics.

## Tooling verification

`SecFlowOps/artifact/tool_status.json` records successful availability of:

- Python 3.11.9
- Git 2.51.2
- Docker 29.6.1
- Java 24.0.1
- Trivy 0.71.2
- OPA 1.18.2
- Semgrep 1.169.0
- Gitleaks 8.30.1
- OWASP ZAP 2.17.0

The full tool check required execution outside the restricted sandbox because Trivy and ZAP are installed outside the writable workspace.

## Article repository exclusion

The manuscript directory `SecFlowOps/paper/` has been removed from Git tracking with `git rm --cached` and added to `.gitignore`.
The local manuscript files remain on disk but are no longer intended to be pushed to GitHub.

## Remaining limits

3. Bounded remediation
   NodeGoat still has residual critical/high findings after automated non-breaking remediation. Removing them requires breaking upgrades, package replacement, manual redesign, or a richer remediator.

5. Organizational CI/PR validation
   The existing GitHub evidence validates CI and PR mechanics. It does not validate independent code-owner review, branch-protection governance, or organization-level deployment policy.

7. Time-sensitive advisory databases
   Trivy, npm, Semgrep rules, and advisory databases evolve. Exact vulnerability counts remain time-sensitive unless scanner databases and rule/advisory snapshots are archived.

8. Statistical breadth
   The new priority campaigns use one repetition per configuration. They are valid execution evidence but not sufficient for narrow confidence intervals or strong distributional claims.

Additional unresolved item from priority 2:

- The two-reviewer natural adjudication protocol is prepared, but independent reviewer labels and consensus are still required before natural precision/false-positive claims can be made.
