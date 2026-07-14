param(
  [string]$CampaignId = "priority_validation_manual",
  [int]$ExternalLimit = 0,
  [string[]]$RegressionRepos = @(
    "external_gorilla_mux",
    "external_gorilla_websocket"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\prepare_extended_external_corpus.py --limit $ExternalLimit

.\SecFlowOps\artifact\run_extended_external_study.ps1 `
  -Repetitions 1 `
  -CampaignId "$CampaignId-extended-external" `
  -ExternalLimit $ExternalLimit `
  -Configs @(
    "C1_NonBlockingScanning",
    "C4_AgentsOnly",
    "C5_SecFlowOps"
  )

python SecFlowOps\scripts\create_dual_adjudication_protocol.py
python SecFlowOps\scripts\compute_dual_adjudication_agreement.py

python SecFlowOps\scripts\run_application_regression_checks.py `
  --campaign-id "$CampaignId-regression" `
  --repos $RegressionRepos `
  --post-remediation `
  --timeout 900 `
  --output-label priority_validation

.\SecFlowOps\artifact\run_zap_breadth_study.ps1 -CampaignId "$CampaignId-zap"

Write-Host "Priority validation block completed. Review dual adjudication reviewer files before claiming independent adjudication."
