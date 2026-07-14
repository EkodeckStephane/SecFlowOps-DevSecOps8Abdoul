# SecFlowOps

SecFlowOps is the artifact-backed follow-up to the original SecFlow simulation
paper. The goal is to evaluate the same architectural idea with real CI/CD
steps, real scanner outputs, a real Policy-as-Code gate, and traceable
remediation logs.

This repository is intentionally conservative:

- all vulnerable code is local and controlled;
- secrets are fake test tokens only;
- results are written to `data/raw`, `data/normalized`, `data/processed`,
  `tables`, and `figures`;
- no claim of industrial or production validation is made until CI runs and
  logs exist.

## Local Smoke Run

From the repository root:

```powershell
python SecFlowOps\scripts\check_tools.py
python SecFlowOps\scripts\run_matrix.py --smoke
python SecFlowOps\scripts\compute_metrics.py
python SecFlowOps\scripts\statistical_analysis.py
python SecFlowOps\scripts\generate_figures.py
```

The smoke run executes the six configurations once on the controlled
`repos/sample_api` application. It is not the full study; it verifies that the
pipeline, normalization, policy gate, metrics, and logs are wired correctly.

## Configurations

- `C0_BuildOnly`: build and tests only.
- `C1_NonBlockingScanning`: real scans, no blocking gate, no remediation.
- `C2_AutoScanning`: real scans and normalized reports, no gate, no remediation.
- `C3_PolicyOnly`: real scans and OPA/Rego gate on raw findings.
- `C4_AgentsOnly`: real scans and semi-autonomous local patches, no gate.
- `C5_SecFlowOps`: real scans, remediation, rescan, and gate on residual findings.

## Current Scope

The local version uses Trivy immediately when available. Semgrep, Gitleaks, OPA,
and ZAP are supported by the scripts when installed or made available through
Docker, but missing tools are recorded as scanner/tool failures instead of being
silently simulated.

For Q1-level claims, run the preregistered design in `PROTOCOL.md`, not only the
smoke test.
