# SecFlowOps Validation Limits Roadmap

This roadmap records the remaining scientific limits and the execution order for strengthening the SecFlowOps study.

## Priority execution block

1. External validation breadth
   - Expand the external corpus beyond the current five projects.
   - Cover multiple ecosystems where practical.
   - Prefer projects where native build/test commands can be executed.
   - Report tool failures, build/test failures, and security-pipeline outcomes separately.

2. Natural external finding adjudication
   - Replace single first-pass static adjudication with a two-reviewer protocol.
   - Keep reviewer labels separate.
   - Compute agreement and consensus.
   - Distinguish static evidence, advisory evidence, exploitability evidence, and unresolved cases.

4. DAST breadth
   - Expand beyond the current focused ZAP reflected-XSS probe.
   - Use several dynamic web targets or scenarios.
   - Report executable ZAP coverage, matched DAST ground truth, residual findings, and timing.

6. Application regression validation
   - Execute native project tests before and after remediation when the project environment is practical.
   - Distinguish projects with executable tests from projects requiring build-skip mode.
   - Report pass/fail, command, duration, and failure reason.

## Remaining limits to report after the priority block

3. Bounded remediation
   - NodeGoat still contains residual critical/high findings after non-breaking npm remediation.
   - Breaking upgrades, package replacement, or manual redesign remain outside the current automated remediator.

5. Organizational CI/PR validation
   - Current remote evidence validates functional CI/PR execution, not multi-reviewer governance or branch-protection effectiveness.

7. Time-sensitive advisory databases
   - Scanner and npm advisory databases evolve; exact future vulnerability counts may differ unless advisory snapshots or containerized caches are archived.

8. Statistical breadth
   - Some focused modules, especially DAST and npm-only baselines, need more repetitions and confidence intervals before supporting broader comparative claims.

## Completion report requirements

When the priority block is complete, report:

- what was executed;
- which repositories/targets were included;
- which build/test commands were run;
- which findings were adjudicated and by whom;
- DAST targets, ZAP outputs, and matched ground truth;
- residual limitations from points 3, 5, 7, and 8;
- exact files, tables, scripts, and commits changed.
