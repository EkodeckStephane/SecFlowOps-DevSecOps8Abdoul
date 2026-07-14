# Expanded SecFlowOps Study Report

Campaign: `expanded_20260713_cached_r3`

This campaign evaluates five generated controlled repositories across six configurations and three repetitions, for 90 total runs.

## Corpus

The corpus is defined in `SecFlowOps/experiments/corpus_manifest.csv`.

- Repositories: 5
- Size classes: small, medium, large, xlarge, xxlarge
- Stacks: Python, pip, Docker, Kubernetes
- Ground-truth injected findings per repository: 6
- Total expected ground-truth findings across the controlled corpus: 30

## Execution Summary

- Total runs: 90
- Successful runs: 75
- Expected policy-blocked runs: 15 (`C3_PolicyOnly`)
- Tool failures: 0

Success by configuration:

- `C0_BuildOnly`: 15/15
- `C1_NonBlockingScanning`: 15/15
- `C2_AutoScanning`: 15/15
- `C3_PolicyOnly`: 0/15
- `C4_AgentsOnly`: 15/15
- `C5_SecFlowOps`: 15/15

## Security Outcomes

For `C5_SecFlowOps`, all 15 runs ended with:

- residual critical findings: 0
- residual high findings: 2
- residual secrets: 0
- OPA decision: allow

The residual high findings are remaining Kubernetes hardening findings below the configured high-severity threshold.

## Detection Metrics

Across scanning configurations, recall against the injected ground truth is 1.0. Precision is reported as 0.133 because all scanner findings not linked to the injected ground truth are conservatively counted as unknown or false-positive candidates. They have not yet been manually adjudicated.

## Performance Results

Mean pipeline times:

- `C0_BuildOnly`: 0.246 s
- `C1_NonBlockingScanning`: 9.181 s
- `C2_AutoScanning`: 9.323 s
- `C3_PolicyOnly`: 9.345 s
- `C4_AgentsOnly`: 17.759 s
- `C5_SecFlowOps`: 18.122 s

Mean component times for `C5_SecFlowOps`:

- build tests: 0.214 s
- initial scanners: 8.819 s
- post-remediation scanners: 8.553 s
- remediation: 0.288 s
- policy gate: 0.121 s

Paired overheads:

- `C5` vs `C0`: +17.875 s
- `C5` vs `C1`: +8.941 s
- `C3` vs `C1`: +0.164 s
- `C4` vs `C1`: +8.578 s
- `C5` vs `C4`: +0.363 s

## Interpretation

The dominant cost is scanner execution, especially the second scan after remediation. The OPA policy gate adds a small mean overhead compared with scanner and rescan costs.

The campaign lifts the original single-repository smoke-run limitation and adds a performance study, but it remains a controlled generated corpus. External validity still requires real open-source repositories with independently reviewed findings.

