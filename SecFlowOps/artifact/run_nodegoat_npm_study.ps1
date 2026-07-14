param(
  [int]$Repetitions = 3,
  [string]$CampaignId = "nodegoat_npm_manual"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\prepare_external_corpus.py --repetitions $Repetitions
python SecFlowOps\scripts\check_tools.py --strict
SecFlowOps\tools\opa.exe test SecFlowOps\policies\rego

$configs = @(
  "C1_NonBlockingScanning",
  "C2_AutoScanning",
  "C3_PolicyOnly",
  "C4_AgentsOnly",
  "C5_SecFlowOps"
)

python SecFlowOps\scripts\run_matrix.py `
  --smoke `
  --campaign-id $CampaignId `
  --build-mode skip `
  --repetitions $Repetitions `
  --scenario external_open_source_npm_remediation `
  --repos external_nodegoat `
  --configs $configs

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Where-Object { $_.Name -like "*external_nodegoat*" } |
  Sort-Object Name -Descending |
  Select-Object -First ($configs.Count * $Repetitions) |
  Sort-Object Name

if ($runs.Count -eq 0) {
  throw "No NodeGoat npm campaign runs found."
}

$minRunId = $runs[0].Name
$maxRunId = $runs[$runs.Count - 1].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId --max-run-id $maxRunId --label nodegoat_npm
python SecFlowOps\scripts\analyze_performance.py --min-run-id $minRunId --max-run-id $maxRunId --label nodegoat_npm
python SecFlowOps\scripts\statistical_analysis.py --label nodegoat_npm

Write-Host "NodeGoat npm SecFlowOps campaign complete. Metrics: SecFlowOps\tables\summary_metrics_nodegoat_npm.csv"
