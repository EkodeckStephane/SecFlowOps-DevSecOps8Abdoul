param(
  [int]$Repetitions = 3,
  [string]$CampaignId = "full_protocol_manual",
  [switch]$PrepareOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\prepare_full_protocol_corpus.py
python SecFlowOps\scripts\check_tools.py --strict
SecFlowOps\tools\opa.exe test SecFlowOps\policies\rego

if ($PrepareOnly) {
  Write-Host "Full protocol corpus prepared. Design matrix: SecFlowOps\experiments\design_matrix.csv"
  exit 0
}

$repos = Get-Content SecFlowOps\experiments\full_protocol_corpus_manifest.csv |
  Select-Object -Skip 1 |
  ForEach-Object { ($_ -split ',')[0] }

python SecFlowOps\scripts\run_matrix.py `
  --campaign-id $CampaignId `
  --scenario auto `
  --build-mode python_unittest `
  --repetitions $Repetitions `
  --repos $repos `
  --configs C0_BuildOnly C1_NonBlockingScanning C2_AutoScanning C3_PolicyOnly C4_AgentsOnly C5_SecFlowOps

$runs = Get-ChildItem -Path SecFlowOps\data\raw -Directory |
  Where-Object { $_.Name -like "*full_*" } |
  Sort-Object Name -Descending |
  Select-Object -First ($repos.Count * 6 * $Repetitions) |
  Sort-Object Name

if ($runs.Count -eq 0) {
  throw "No full protocol runs found."
}

$minRunId = $runs[0].Name
$maxRunId = $runs[$runs.Count - 1].Name
python SecFlowOps\scripts\compute_metrics.py --min-run-id $minRunId --max-run-id $maxRunId --label full_protocol
python SecFlowOps\scripts\analyze_performance.py --min-run-id $minRunId --max-run-id $maxRunId --label full_protocol
python SecFlowOps\scripts\statistical_analysis.py --label full_protocol

Write-Host "Full protocol campaign complete. Metrics: SecFlowOps\tables\summary_metrics_full_protocol.csv"
