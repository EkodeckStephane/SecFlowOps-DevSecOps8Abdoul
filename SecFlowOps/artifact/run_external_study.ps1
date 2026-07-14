param(
  [int]$Repetitions = 3,
  [string]$CampaignId = "external_manual",
  [string[]]$Repos = @(
    "external_requests",
    "external_flask",
    "external_express",
    "external_nodegoat",
    "external_dvna"
  )
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
  --scenario external_open_source `
  --repos $Repos `
  --configs $configs

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Where-Object { $_.Name -like "*external_*" } |
  Sort-Object Name -Descending |
  Select-Object -First ($Repos.Count * $configs.Count * $Repetitions) |
  Sort-Object Name

if ($runs.Count -eq 0) {
  throw "No external campaign runs found."
}

$minRunId = $runs[0].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId --label external
python SecFlowOps\scripts\analyze_performance.py --min-run-id $minRunId --label external
python SecFlowOps\scripts\create_adjudication_template.py --campaign-id $CampaignId
python SecFlowOps\scripts\review_external_adjudication.py
python SecFlowOps\scripts\compute_adjudicated_metrics.py --campaign-id $CampaignId
python SecFlowOps\scripts\statistical_analysis.py --label external

Write-Host "External SecFlowOps campaign complete. Metrics: SecFlowOps\tables\summary_metrics_external.csv"
