param(
  [int]$Repetitions = 3,
  [string]$CampaignId = "injected_external_manual",
  [string[]]$Repos = @(
    "injected_requests",
    "injected_flask",
    "injected_express"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\prepare_injected_external_corpus.py --repetitions $Repetitions
python SecFlowOps\scripts\check_tools.py --strict
SecFlowOps\tools\opa.exe test SecFlowOps\policies\rego

$configs = @(
  "C1_NonBlockingScanning",
  "C4_AgentsOnly",
  "C5_SecFlowOps"
)

python SecFlowOps\scripts\run_matrix.py `
  --smoke `
  --campaign-id $CampaignId `
  --build-mode skip `
  --repetitions $Repetitions `
  --scenario injected_external_real_base `
  --repos $Repos `
  --configs $configs

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Where-Object { $_.Name -like "*injected_*" } |
  Sort-Object Name -Descending |
  Select-Object -First ($Repos.Count * $configs.Count * $Repetitions) |
  Sort-Object Name

if ($runs.Count -eq 0) {
  throw "No injected external campaign runs found."
}

$minRunId = $runs[0].Name
$maxRunId = $runs[$runs.Count - 1].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId --max-run-id $maxRunId --label injected_external
python SecFlowOps\scripts\analyze_performance.py --min-run-id $minRunId --max-run-id $maxRunId --label injected_external
python SecFlowOps\scripts\statistical_analysis.py --label injected_external

Write-Host "Injected external SecFlowOps campaign complete. Metrics: SecFlowOps\tables\summary_metrics_injected_external.csv"
