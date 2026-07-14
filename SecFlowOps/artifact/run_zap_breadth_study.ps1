param(
  [int]$Repetitions = 1,
  [string]$CampaignId = "zap_breadth_manual",
  [string[]]$Repos = @(
    "full_alpha_sast_reflected_xss",
    "full_beta_sast_reflected_xss",
    "full_gamma_sast_reflected_xss"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\check_tools.py --strict
SecFlowOps\tools\opa.exe test SecFlowOps\policies\rego

$configs = @(
  "C1_NonBlockingScanning",
  "C3_PolicyOnly"
)

python SecFlowOps\scripts\run_matrix.py `
  --campaign-id $CampaignId `
  --build-mode python_unittest `
  --repetitions $Repetitions `
  --scenario auto `
  --repos $Repos `
  --configs $configs `
  --enable-zap

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Where-Object { $_.Name -like "*sast_reflected_xss*" } |
  Sort-Object Name -Descending |
  Select-Object -First ($Repos.Count * $configs.Count * $Repetitions) |
  Sort-Object Name

if ($runs.Count -eq 0) {
  throw "No ZAP breadth runs found."
}

$minRunId = $runs[0].Name
$maxRunId = $runs[$runs.Count - 1].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId --max-run-id $maxRunId --campaign-id-filter $CampaignId --label zap_breadth
python SecFlowOps\scripts\analyze_performance.py --min-run-id $minRunId --max-run-id $maxRunId --campaign-id-filter $CampaignId --label zap_breadth
python SecFlowOps\scripts\statistical_analysis.py --label zap_breadth

Write-Host "ZAP breadth study complete. Metrics: SecFlowOps\tables\summary_metrics_zap_breadth.csv"
