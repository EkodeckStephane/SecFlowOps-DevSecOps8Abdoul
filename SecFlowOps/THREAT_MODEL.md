# Threat Model

## Protected Assets

- application source code;
- CI/CD workflow integrity;
- scanner outputs and policy decisions;
- remediation patches;
- fake test secrets used for detection experiments;
- experimental logs and metrics.

## Trust Assumptions

- The local machine is trusted for the smoke run.
- Scanners are assumed to execute their documented checks correctly enough for
  experimental comparison, but their findings are not treated as ground truth.
- The Policy-as-Code gate is trusted to evaluate normalized findings according
  to the supplied Rego policy or the explicitly marked Python fallback.
- The local RemediatorAgent is not allowed to push to `main` or auto-merge.

## In-Scope Risks

- vulnerable dependencies;
- fake secret exposure;
- Docker/Kubernetes misconfiguration;
- SAST-detectable unsafe code patterns;
- policy-gate bypass by unnormalized findings;
- remediation that fails to remove a finding;
- remediation that breaks tests.

## Out-of-Scope Risks

- attacks against third-party systems;
- real credential exposure;
- malicious compromise of the scanner binaries;
- malicious compromise of the operating system;
- insider attacks on the experimenter machine;
- production adversaries exploiting a live service.

## Agent Safety

The local remediation agent can modify only a copied run workspace under
`data/raw/<run_id>/workspace`. It logs every file edit. Non-trivial, LLM-based,
or security-sensitive changes are out of scope for the automated smoke run.

## Security Claim Boundaries

SecFlowOps measures detection, gating, and controlled remediation behavior. It
does not prove that an application is secure, that all vulnerabilities are found,
or that autonomous remediation is safe in production.
