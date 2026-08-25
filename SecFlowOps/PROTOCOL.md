# SecFlowOps experimental protocol

## Scientific object

The protocol measures the transition from initial security evidence to residual security evidence and an explicit Policy-as-Code release decision. It separates the effect of remediation/rescanning from the effect of policy gating under matched workloads.

## Experimental configurations

| ID | Configuration | Build/Test | Scan | Remediation | Rescan | OPA |
|---|---|---:|---:|---:|---:|---:|
| C0 | BuildOnly | yes | no | no | no | no |
| C1 | ScanOnly | yes | yes | no | no | no |
| C2 | PolicyOnly | yes | yes | no | no | yes |
| C3 | RemediationOnly | yes | yes | yes | yes | no |
| C4 | SecFlowOps | yes | yes | yes | yes | yes |

## Controlled design

The controlled corpus contains three codebase families and eight scenarios:

- clean;
- vulnerable dependency;
- fake secret;
- reflected XSS;
- SQL injection;
- Docker misconfiguration;
- Kubernetes misconfiguration;
- multi-layer.

The resulting 24 family-scenario workloads are the independent experimental units. Each workload is executed three times per configuration as a technical repetition:

```text
24 workloads x 5 configurations x 3 technical repetitions = 360 executions
```

## Outcome model

Each execution records:

- execution completion;
- initial normalized findings;
- residual normalized findings where remediation applies;
- remediation events and validation state;
- release decision (`ALLOW`, `DENY`, or not applicable);
- scanner, remediation, policy, and end-to-end timing.

A policy `DENY` is a valid release outcome and is recorded independently from execution completion.

## Ground truth

Ground-truth records are stored in `repos/ground_truth/ground_truth_findings.csv`. Recall denominators include only target findings marked for expected detection whose specified detector is active in the corresponding study. Residual target counts are measured after the post-remediation scanner pass.

Natural external scanner findings are evaluated through the independent adjudication workflow and are kept separate from injected-ground-truth metrics.

## Statistical plan

Technical repetitions are aggregated within each workload-configuration cell. The final controlled analysis reports:

- workload-level descriptive summaries;
- paired mean differences;
- workload-bootstrap 95% confidence intervals;
- paired standardized effects where defined;
- exact paired sign tests for continuous effects;
- exact McNemar tests for matched release decisions;
- Holm adjustment within reported inferential families.

Policy robustness is evaluated by replaying alternative severity thresholds over measured residual finding sets.

## Provenance

Tool versions, policy files, advisory snapshots, normalized evidence, processed tables, and checksums are recorded in the artifact. Advisory-sensitive comparisons use the recorded frozen advisory state, while later advisory reruns are reported as separate drift checks.
