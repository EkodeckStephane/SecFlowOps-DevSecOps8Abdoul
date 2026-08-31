# EMSE empirical extension

This directory defines the additional evidence required for the Empirical Software Engineering revision.

## Protected scientific object

A security-finding trajectory links a vulnerable or pre-change state to a changed state and records:

`F0 -> software change -> F1 -> application validation -> release decision`

At finding level the transition is decomposed into resolved (`R`), persistent (`Q`), and newly observed (`N`) evidence. The independent material is the vulnerability/fix trajectory; repeated executions are technical measurements rather than new cases.

## Evidence layers

1. **Controlled attribution**: the existing 24 matched workloads isolate scanning, remediation/rescanning, and policy evaluation.
2. **Real developer-fix trajectories**: the core corpus starts from the 79 PoV-based Vul4J vulnerabilities, each paired with its human patch and proof-of-vulnerability tests.
3. **SecFlowOps remediation comparison**: where the bounded remediator supports the affected weakness or dependency, the same vulnerable state is evaluated with both the observed developer fix and the SecFlowOps remediation.
4. **Cross-ecosystem transfer**: a non-Java corpus will be added from reproducible security updates with pinned pre/post states and executable project validation.

## Inclusion gate for a real trajectory

A retained trajectory must have an identifiable repository and security issue, an unambiguous pre-change state, a documented fix state, reproducible security validation, and sufficient source/build material to replay the comparison. Exclusions are recorded with machine-readable reasons.

## Main outputs

- `data/emse/candidate_security_fixes.csv`: mined candidates and screening status.
- `results/emse/*/trajectory_validation.csv`: replay/validation evidence.
- trajectory-level evidence containing `F0`, `F1`, `R`, `Q`, `N`, validation status, and release decisions.
- repository-aware statistical summaries using the trajectory as the analysis unit and repository-clustered uncertainty where needed.

## Quality rules

The public artifact stores commands, manifests, hashes, exclusions, logs, and replay metadata. The manuscript reports scientific results rather than the execution runbook. Results based on developer fixes, SecFlowOps remediation, or scanner evidence are labelled by their actual evidence source and are never pooled when their validity conditions differ.
