# SecFlowOps Experimental Protocol

## Objective

Evaluate whether an integrated DevSecOps pipeline combining real multi-layer
scanning, Policy-as-Code, and semi-autonomous remediation changes detection,
remediation, and deployment-gate outcomes compared with ablated configurations.

## Scope

This artifact starts with a controlled local study. It does not claim production
readiness, industrial validation, or direct cognitive-load reduction.

## Hypotheses

- H1: configurations with remediation automation reduce time-to-patch and MTTR
  relative to scan-only configurations.
- H2: Policy-as-Code changes deployment success and residual-risk outcomes by
  enforcing explicit blocking rules.
- H3: the full configuration exposes the trade-off between remediation gains and
  policy-gate strictness more clearly than either pillar alone.

## Experimental Unit

One run is one complete execution of one configuration on one repository
scenario, with raw logs, scanner outputs, normalized findings, policy decision,
and remediation log preserved under `data/raw/<run_id>/`.

## Configurations

| ID | Name | Build/Test | Scanners | Remediation | Policy Gate |
|---|---|---:|---:|---:|---:|
| C0 | BuildOnly | yes | no | no | no |
| C1 | NonBlockingScanning | yes | yes | no | no |
| C2 | AutoScanning | yes | yes | no | no |
| C3 | PolicyOnly | yes | yes | no | yes, raw findings |
| C4 | AgentsOnly | yes | yes | yes | no |
| C5 | SecFlowOps | yes | yes | yes | yes, residual findings |

`C1` is not called "ManualSecurity" because no human intervention is measured in
the local artifact.

## Repositories and Scenarios

Initial controlled repository:

- `repos/sample_api`: Python HTTP API with intentionally injected, defensive
  test vulnerabilities.

Initial scenarios:

- vulnerable dependency in `requirements.txt`;
- fake test secret in `.env.test`;
- SAST-detectable reflected output pattern in `app.py`;
- Dockerfile and Kubernetes misconfigurations;
- clean endpoint for build/test sanity.

The target full study should expand to at least:

```text
3 repositories x 8 scenarios x 6 configurations x 3 repetitions = 432 runs
```

The smoke run is explicitly not sufficient for publication-level generalization.

## Ground Truth

Ground-truth records are stored in
`repos/ground_truth/ground_truth_findings.csv`.

Rows marked `expected_detection=false` or `source=uncertain` are excluded from
strict recall and false-negative denominators.

## Metrics

Primary metrics:

- pipeline time;
- scanner time by tool;
- MTTD;
- MTTR;
- security coverage / recall;
- precision;
- false positive rate;
- false negative rate;
- auto-remediation rate;
- patch success rate;
- policy gate pass rate;
- pipeline success rate;
- human escalation rate.

Every percentage denominator must be explicit in the metrics CSV or companion
metadata.

## Exclusion Criteria

Runs are not deleted silently. A run may be flagged as excluded from a specific
analysis only if:

- the build/test stage failed before security tooling could run;
- a required tool was unavailable and the analysis specifically requires that
  tool;
- raw output is corrupt or unparsable.

The raw run remains in `data/raw` and is listed in `experiments/raw_logs_manifest.csv`.

## Failure Handling

Tool failures are recorded in `metadata.json` and can trigger Rego warnings.
They are not converted into synthetic findings.

## Statistical Plan

For the full study:

- descriptive statistics by configuration;
- bootstrap 95% confidence intervals;
- non-parametric or Welch tests as secondary evidence;
- effect sizes;
- mixed-effects or robust regression when there are enough repositories and
  scenarios;
- sensitivity analysis of policy thresholds.

The smoke run only validates the machinery and produces descriptive outputs.
