param(
  [int]$Repetitions = 3,
  [string]$CampaignId = "expanded_manual",
  [string[]]$Repos = @(
    "controlled_api_s",
    "controlled_api_m",
    "controlled_api_l",
    "controlled_api_xl",
    "controlled_api_xxl"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\prepare_expanded_corpus.py
python SecFlowOps\scripts\check_tools.py --strict
SecFlowOps\tools\opa.exe test SecFlowOps\policies\rego

$configs = @(
  "C0_BuildOnly",
  "C1_NonBlockingScanning",
  "C2_AutoScanning",
  "C3_PolicyOnly",
  "C4_AgentsOnly",
  "C5_SecFlowOps"
)

python SecFlowOps\scripts\run_matrix.py `
  --smoke `
  --campaign-id $CampaignId `
  --repetitions $Repetitions `
  --repos $Repos `
  --configs $configs

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Where-Object { $_.Name -like "*controlled_api*" } |
  Sort-Object Name -Descending |
  Select-Object -First ($Repos.Count * $configs.Count * $Repetitions) |
  Sort-Object Name

if ($runs.Count -eq 0) {
  throw "No expanded campaign runs found."
}

$minRunId = $runs[0].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId
python SecFlowOps\scripts\analyze_performance.py --min-run-id $minRunId
python SecFlowOps\scripts\statistical_analysis.py
python SecFlowOps\scripts\generate_figures.py

Write-Host "Expanded SecFlowOps campaign complete. Metrics: SecFlowOps\tables\summary_metrics.csv"
