# Reproducibility

## Minimum Environment

- Python 3.11 or newer;
- Git;
- Trivy for the initial local scanner path;
- optional: OPA, Semgrep, Gitleaks, Docker, OWASP ZAP.

Python package requirements are listed in `artifact/requirements.txt`.

## Reproduce the Smoke Run

```powershell
python SecFlowOps\scripts\check_tools.py
python SecFlowOps\scripts\run_matrix.py --smoke
python SecFlowOps\scripts\compute_metrics.py
python SecFlowOps\scripts\statistical_analysis.py
python SecFlowOps\scripts\generate_figures.py
```

Outputs:

- raw logs: `data/raw/<run_id>/`;
- normalized findings: `data/normalized/`;
- processed metrics: `data/processed/`;
- summary tables: `tables/`;
- figures: `figures/`.

## Reproducibility Status Labels

- `available`: file or tool exists.
- `executed`: command was run and output exists.
- `verified`: output was parsed and used by a metrics script.
- `not_available`: missing dependency or unsupported environment.
- `not_executed`: planned but not run.

Do not describe a result as reproduced unless the command was actually executed
in the current artifact state.
