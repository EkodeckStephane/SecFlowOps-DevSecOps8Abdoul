# Injected External Recall Study Report

Campaign: `injected_external_20260713_r3_precise`

This campaign measures recall on real open-source repository bases with controlled injected vulnerabilities. It addresses the external-recall limitation: arbitrary OSS repositories do not provide complete ground truth, so this campaign injects known findings into real codebases and measures whether the pipeline detects and remediates them.

## Corpus

The corpus is defined in `SecFlowOps/experiments/injected_external_corpus_manifest.csv`.

| Repository ID | Base repository | Files | LOC | Injected ground truth |
| --- | --- | ---: | ---: | ---: |
| `injected_requests` | `external_requests` | 136 | 19,544 | 6 |
| `injected_flask` | `external_flask` | 242 | 36,516 | 6 |
| `injected_express` | `external_express` | 219 | 26,780 | 6 |

Each repository contains injected SAST, SCA, secret, Dockerfile, and Kubernetes findings under `secflowops_injected/`.

## Execution Summary

- Configurations: `C1_NonBlockingScanning`, `C4_AgentsOnly`, `C5_SecFlowOps`
- Repetitions: 3
- Total runs: 27
- Successful runs: 27
- Tool failures: 0

## Detection and Remediation Outcomes

Mean recall against injected ground truth:

- `C1_NonBlockingScanning`: 1.000
- `C4_AgentsOnly`: 1.000
- `C5_SecFlowOps`: 1.000

For `C5_SecFlowOps`, all nine runs had:

- pipeline success: true
- residual critical findings: 0
- residual secrets: 0
- residual injected ground-truth findings: 0

Residual findings remain after remediation, with mean residual count 16.0, but they are non-ground-truth hardening findings reported by scanners on the injected Kubernetes/Docker files and do not correspond to the six injected target findings after precise message matching.

## Performance Outcomes

Mean pipeline times:

- `C1_NonBlockingScanning`: 18.155 s
- `C4_AgentsOnly`: 35.818 s
- `C5_SecFlowOps`: 35.519 s

Mean total scanner time:

- `C1_NonBlockingScanning`: 18.039 s
- `C4_AgentsOnly`: 34.921 s
- `C5_SecFlowOps`: 34.571 s

Paired overheads:

- `C5` vs `C1`: +17.364 s
- `C4` vs `C1`: +17.663 s
- `C5` vs `C4`: -0.299 s

The main overhead remains the second scanner pass after remediation.

## Interpretation

This campaign does not prove recall over all naturally occurring vulnerabilities in OSS repositories. It does provide a complete and reproducible ground truth for injected vulnerabilities placed inside real repository contexts, and it demonstrates full recall and removal of the injected target findings under that protocol.
