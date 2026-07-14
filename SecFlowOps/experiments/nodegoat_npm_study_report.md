# NodeGoat npm Remediation Study Report

Campaign: `nodegoat_npm_20260713_r3`

npm-only baseline: `npm_audit_only_20260713_r3`

This campaign isolates OWASP NodeGoat to evaluate whether npm lockfile remediation reduces the major remaining limitation observed in the external campaign.

## Protocol

- Repository: `external_nodegoat`
- Configurations: `C1_NonBlockingScanning`, `C2_AutoScanning`, `C3_PolicyOnly`, `C4_AgentsOnly`, `C5_SecFlowOps`
- Repetitions: 3
- Build mode: `skip`
- Total runs: 15
- Successful runs: 9

The remediator runs `npm audit fix --package-lock-only --omit=dev` in the temporary run workspace. A non-zero npm exit code is not treated as tool failure because npm returns non-zero when residual advisories remain after partial fixes.

## Security Outcome

Initial NodeGoat findings were stable across runs:

- total findings: 78
- critical findings: 10
- high findings: 40
- secrets: 1

For `C4_AgentsOnly` and `C5_SecFlowOps`, residual findings were stable across runs:

- total findings: 31
- critical findings: 3
- high findings: 12
- secrets: 0

The npm-only baseline reduced NodeGoat from 78 findings to 32 findings:

- residual critical findings: 3
- residual high findings: 13
- residual secrets: 1
- resolved total findings: 46
- resolved critical findings: 7
- resolved high findings: 27
- resolved secrets: 0

Thus, npm lockfile remediation alone addresses many dependency advisories but does not remove the repository secret. npm lockfile remediation plus repository private-key removal reduced NodeGoat findings from 78 to 31 and removed the secret finding. The remaining critical and high findings still exceed the configured policy, so `C5_SecFlowOps` correctly remains blocked.

## Performance Outcome

Mean pipeline times:

- `B1_NpmAuditOnly`: 104.518 s
- `C1_NonBlockingScanning`: 19.620 s
- `C2_AutoScanning`: 19.267 s
- `C3_PolicyOnly`: 24.250 s
- `C4_AgentsOnly`: 95.662 s
- `C5_SecFlowOps`: 96.302 s

Mean npm audit-only time:

- `B1_NpmAuditOnly`: 51.078 s

Mean total scanner time:

- `C1_NonBlockingScanning`: 19.495 s
- `C4_AgentsOnly`: 53.270 s
- `C5_SecFlowOps`: 50.366 s

Mean remediation time:

- `C4_AgentsOnly`: 42.185 s
- `C5_SecFlowOps`: 44.778 s

The npm remediation step is substantially more expensive than the deterministic text patches used in the controlled campaign.

## Interpretation

This removes the previous all-or-nothing NodeGoat limitation. NodeGoat is no longer merely reported as unremediated: the artifact now performs a real npm remediation, measures an npm-only baseline, and measures the additional effect of SecFlowOps secret remediation and policy gating.

The remaining limitation is narrower and scientifically defensible: NodeGoat contains residual vulnerable npm dependencies requiring breaking upgrades, replacement of unmaintained packages, or manual application redesign. The policy gate correctly refuses the residual state.
