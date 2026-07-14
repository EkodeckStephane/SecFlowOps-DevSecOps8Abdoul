param(
  [int]$Repetitions = 1,
  [string]$CampaignId = "extended_external_manual",
  [int]$ExternalLimit = 0,
  [string[]]$Configs = @(
    "C1_NonBlockingScanning",
    "C4_AgentsOnly",
    "C5_SecFlowOps"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\prepare_extended_external_corpus.py --limit $ExternalLimit

$manifest = Import-Csv -Path SecFlowOps\experiments\extended_external_corpus_manifest.csv
$repos = @($manifest | ForEach-Object { $_.repo_id })
if ($repos.Count -eq 0) {
  throw "No repositories found in SecFlowOps\experiments\extended_external_corpus_manifest.csv"
}

python SecFlowOps\scripts\run_matrix.py `
  --campaign-id $CampaignId `
  --build-mode skip `
  --repetitions $Repetitions `
  --scenario external_oss_security_pipeline `
  --repos $repos `
  --configs $Configs

python SecFlowOps\scripts\compute_metrics.py --campaign-id-filter $CampaignId --label extended_external
python SecFlowOps\scripts\analyze_performance.py --campaign-id-filter $CampaignId --label extended_external
python SecFlowOps\scripts\statistical_analysis.py --label extended_external
python SecFlowOps\scripts\create_adjudication_template.py --campaign-id $CampaignId

Write-Host "Extended external study complete. Metrics: SecFlowOps\tables\summary_metrics_extended_external.csv"
