# External SecFlowOps Study Report

Campaign: `external_20260713_r3_baselines`

This campaign evaluates SecFlowOps on five real open-source repositories across five configurations and three repetitions, for 75 total runs. Project-specific builds and tests were intentionally skipped with `--build-mode skip` so that missing local dependencies in heterogeneous external projects do not confound the security pipeline measurement.

## Corpus

The corpus is defined in `SecFlowOps/experiments/external_corpus_manifest.csv`.

| Repository ID | Source | Commit | Files | LOC | Status |
| --- | --- | --- | ---: | ---: | --- |
| `external_requests` | `https://github.com/psf/requests.git` | `f361ead047be5cb873174218582f7d8b9fcd9f49` | 130 | 19,464 | no findings in this campaign |
| `external_flask` | `https://github.com/pallets/flask.git` | `36e4a824f340fdee7ed50937ba8e7f6bc7d17f81` | 236 | 36,436 | first-pass static adjudication |
| `external_express` | `https://github.com/expressjs/express.git` | `ae6dd37680e3a00618d6c8a3e522f0ee4eeba1a4` | 213 | 26,700 | no findings in this campaign |
| `external_nodegoat` | `https://github.com/OWASP/NodeGoat.git` | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | 111 | 42,046 | first-pass static adjudication |
| `external_dvna` | `https://github.com/appsecco/dvna.git` | `9ba473add536f66ac9007966acb2a775dd31277a` | 151 | 12,278 | first-pass static adjudication |

## Execution Summary

- Total runs: 75
- Successful runs: 69
- Tool failures: 0
- Configurations: `C1_NonBlockingScanning`, `C2_AutoScanning`, `C3_PolicyOnly`, `C4_AgentsOnly`, `C5_SecFlowOps`
- Repetitions: 3

Success by configuration:

- `C1_NonBlockingScanning`: 15/15
- `C2_AutoScanning`: 15/15
- `C3_PolicyOnly`: 12/15
- `C4_AgentsOnly`: 15/15
- `C5_SecFlowOps`: 12/15

The six failed runs are the three `C3_PolicyOnly` and three `C5_SecFlowOps` runs on `external_nodegoat`. These failures are policy denials, not scanner or build failures.

## Security Outcomes

The external campaign produced 82 unique findings. A first-pass static adjudication is stored in `SecFlowOps/data/manual_labels/external_adjudication_reviewed.csv`.

- `external_flask`: 13 Trivy SCA findings
- `external_nodegoat`: 65 Trivy SCA findings, 1 Trivy secret finding, and 1 Trivy IaC finding
- `external_dvna`: 2 Trivy IaC findings

No unique findings were produced for `external_requests` or `external_express` in this run.

All 82 findings are marked as true positives under static repository evidence: vulnerable package versions are present in the scanned manifests, the private key file is present in the repository, and the Dockerfile hardening findings match the scanned Dockerfiles. This is not an independent CVE-status audit and does not establish application-level exploitability or external recall.

For `C5_SecFlowOps`, remediation outcomes by repository were:

- `external_requests`: 0 reviewed findings initially, 0 residual
- `external_flask`: 13 reviewed findings initially, 0 residual
- `external_express`: 0 reviewed findings initially, 0 residual
- `external_nodegoat`: 78 reviewed findings initially, 77 residual
- `external_dvna`: 2 reviewed findings initially, 0 residual

The implemented external remediations therefore resolve Flask example dependency findings, DVNA Dockerfile hardening findings, and the NodeGoat repository-stored private key. They do not remediate the NodeGoat vulnerable npm dependency set, so `external_nodegoat` remains blocked by the policy gate with 10 residual critical findings and 39 residual high findings.

Follow-up npm remediation is reported separately in `SecFlowOps/experiments/nodegoat_npm_study_report.md`. With `npm audit fix --package-lock-only --omit=dev`, NodeGoat residual findings are reduced from 78 to 31, including 3 critical and 12 high findings, and the policy gate still correctly denies the residual state.

## Performance Results

Mean pipeline times:

- `C1_NonBlockingScanning`: 14.671 s
- `C2_AutoScanning`: 14.133 s
- `C3_PolicyOnly`: 14.926 s
- `C4_AgentsOnly`: 27.924 s
- `C5_SecFlowOps`: 28.637 s

Mean component times for `C5_SecFlowOps`:

- skipped build step: 0.056 s
- initial scanner pass: 14.304 s
- post-remediation scanner pass: 13.663 s
- remediation step: 0.401 s
- policy gate: 0.097 s

Paired overheads:

- `C5` vs `C1`: +13.966 s
- `C4` vs `C1`: +13.253 s
- `C5` vs `C4`: +0.713 s
- `C3` vs `C1`: +0.255 s

The dominant external runtime cost is scanner execution. The full SecFlowOps configuration is approximately one additional scanner pass plus a small remediation and policy overhead relative to non-blocking scanning. Descriptive bootstrap intervals are written to `SecFlowOps/tables/bootstrap_descriptives_external.csv`; they are descriptive and not a substitute for independent replication.

## Interpretation

This campaign addresses the prior limitation that all evidence came from generated controlled repositories. It adds real open-source code, real scanner outputs, policy-gate behavior on intentionally vulnerable benchmarks, baseline comparisons, repeated runs, performance measurements, and an adjudication table.

It does not establish external recall because no complete independent ground truth exists for the external repositories. It also does not establish general remediation effectiveness across arbitrary npm applications, because NodeGoat's vulnerable dependency set remains unresolved.
