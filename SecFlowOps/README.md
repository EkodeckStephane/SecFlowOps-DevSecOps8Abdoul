# SecFlowOps

SecFlowOps implements the measured trajectory from initial security findings to residual findings and an explicit release decision.

## Configurations

| ID | Configuration | Scan | Remediation | Rescan | OPA |
|---|---|---:|---:|---:|---:|
| C0 | BuildOnly | no | no | no | no |
| C1 | ScanOnly | yes | no | no | no |
| C2 | PolicyOnly | yes | no | no | yes |
| C3 | RemediationOnly | yes | yes | yes | no |
| C4 | SecFlowOps | yes | yes | yes | yes |

The controlled protocol uses 24 independent workloads (three families by eight scenarios). Three technical repetitions are executed per workload and configuration. Statistical analysis first aggregates those repetitions within each workload and then performs matched comparisons across workloads.

## Core commands

```powershell
python SecFlowOps\scripts\check_tools.py
python SecFlowOps\scripts\run_matrix.py --smoke
python SecFlowOps\scripts\compute_metrics.py
python SecFlowOps\scripts\statistical_analysis.py
```

For the complete controlled study:

```powershell
powershell -ExecutionPolicy Bypass -File .\SecFlowOps\artifact\run_full_protocol_study.ps1 -Repetitions 3
```

## Outcome model

Each run records execution completion separately from release outcome. Gated configurations produce `ALLOW` or `DENY`; ungated configurations record the release decision as not applicable. Remediation validation is likewise explicit: `passed`, `failed`, or `not_tested` according to the executed validation command.

Ground-truth recall is calculated only for target findings whose expected detector is active in the corresponding study. Natural external findings are handled through the separate adjudication workflow.
