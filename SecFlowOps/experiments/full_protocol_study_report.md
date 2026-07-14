# Full Protocol Study Report

Campaign: `full_protocol_20260713_rigorous`

## Protocol

- Generated controlled repositories: 24
- Families: `alpha`, `beta`, `gamma`
- Scenarios per family: `clean`, `vulnerable_dependency`, `fake_secret`, `sast_reflected_xss`, `sast_sql_injection`, `docker_misconfiguration`, `k8s_misconfiguration`, `multi_layer`
- Configurations: `C0_BuildOnly`, `C1_NonBlockingScanning`, `C2_AutoScanning`, `C3_PolicyOnly`, `C4_AgentsOnly`, `C5_SecFlowOps`
- Repetitions: 3
- Executed runs: 432
- Build mode: `python_unittest`

This matches the prompt design target:

```text
3 families x 8 scenarios x 6 configurations x 3 repetitions = 432 runs
```

## Security Summary

| Configuration | Runs | Success rate | Initial findings | Residual findings | Recall | Precision |
|---|---:|---:|---:|---:|---:|---:|
| C0_BuildOnly | 72 | 1.000 | 0.0 | 0.0 | 0.000 | 0.000 |
| C1_NonBlockingScanning | 72 | 1.000 | 28.0 | 28.0 | 0.795 | 0.111 |
| C2_AutoScanning | 72 | 1.000 | 27.8 | 27.8 | 0.795 | 0.124 |
| C3_PolicyOnly | 72 | 0.625 | 28.0 | 28.0 | 0.795 | 0.111 |
| C4_AgentsOnly | 72 | 1.000 | 28.0 | 16.0 | 0.795 | 0.111 |
| C5_SecFlowOps | 72 | 1.000 | 28.0 | 16.0 | 0.795 | 0.111 |

The recall is below 1.0 in this full protocol campaign because DAST ground-truth rows are included, while the 432-run campaign was completed before ZAP was enabled in `run_matrix.py`. ZAP execution is covered separately in `zap_dast_study_report.md`.

## Performance Summary

| Configuration | Runs | Mean pipeline time | Median pipeline time | Mean scanner time |
|---|---:|---:|---:|---:|
| C0_BuildOnly | 72 | 0.248 s | 0.219 s | 0.000 s |
| C1_NonBlockingScanning | 72 | 22.061 s | 20.691 s | 21.757 s |
| C2_AutoScanning | 72 | 76.418 s | 20.715 s | 76.120 s |
| C3_PolicyOnly | 72 | 23.002 s | 20.828 s | 22.508 s |
| C4_AgentsOnly | 72 | 44.174 s | 41.692 s | 43.563 s |
| C5_SecFlowOps | 72 | 43.749 s | 41.409 s | 42.973 s |

One C2 run had a Semgrep runtime of 3944.596 seconds. It is retained in the raw metrics and explains the high C2 mean and standard deviation. The median should be preferred for the primary descriptive comparison unless an exclusion rule is explicitly justified.

## Produced Files

- `SecFlowOps/data/processed/run_metrics_full_protocol.csv`
- `SecFlowOps/data/processed/finding_metrics_full_protocol.csv`
- `SecFlowOps/data/processed/remediation_metrics_full_protocol.csv`
- `SecFlowOps/tables/summary_metrics_full_protocol.csv`
- `SecFlowOps/tables/performance_by_config_full_protocol.csv`
- `SecFlowOps/tables/ablation_results_full_protocol.csv`
- `SecFlowOps/tables/policy_sensitivity_full_protocol.csv`
- `SecFlowOps/figures/*_full_protocol.png`

## Remaining Limits

- The 432-run campaign does not include ZAP because it completed before the ZAP/JDK24 integration was fixed.
- GitHub Actions workflows were created but not executed remotely because this workspace is not a valid Git repository and `gh` is not authenticated.
- Remediation in local runs patches copied workspaces, not real GitHub PRs.
