Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\check_tools.py --strict
SecFlowOps\tools\opa.exe test SecFlowOps\policies\rego

python SecFlowOps\scripts\run_matrix.py --smoke --configs C0_BuildOnly C1_NonBlockingScanning C2_AutoScanning C3_PolicyOnly C4_AgentsOnly C5_SecFlowOps

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Sort-Object Name -Descending |
  Select-Object -First 6 |
  Sort-Object Name

if ($runs.Count -ne 6) {
  throw "Expected six latest campaign runs, found $($runs.Count)."
}

$minRunId = $runs[0].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId
python SecFlowOps\scripts\statistical_analysis.py
python SecFlowOps\scripts\generate_figures.py

Write-Host "SecFlowOps smoke campaign complete. Metrics: SecFlowOps\tables\summary_metrics.csv"
