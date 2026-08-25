Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\check_tools.py --strict
SecFlowOps\tools\opa.exe test SecFlowOps\policies\rego

$configs = @("C0_BuildOnly", "C1_ScanOnly", "C2_PolicyOnly", "C3_RemediationOnly", "C4_SecFlowOps")
python SecFlowOps\scripts\run_matrix.py --smoke --configs $configs

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Sort-Object Name -Descending |
  Select-Object -First $configs.Count |
  Sort-Object Name

if ($runs.Count -ne $configs.Count) {
  throw "Expected $($configs.Count) latest campaign runs, found $($runs.Count)."
}

$minRunId = $runs[0].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId
python SecFlowOps\scripts\statistical_analysis.py
python SecFlowOps\scripts\generate_figures.py

Write-Host "SecFlowOps smoke campaign complete."
