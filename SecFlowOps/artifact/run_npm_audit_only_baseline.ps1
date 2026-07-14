param(
  [int]$Repetitions = 3,
  [string]$CampaignId = "npm_audit_only_manual",
  [string]$Repo = "external_nodegoat"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

python SecFlowOps\scripts\prepare_external_corpus.py --repetitions $Repetitions
python SecFlowOps\scripts\check_tools.py --strict

python SecFlowOps\scripts\run_npm_audit_only_baseline.py `
  --repo $Repo `
  --repetitions $Repetitions `
  --campaign-id $CampaignId

Write-Host "npm audit-only baseline complete. Metrics: SecFlowOps\tables\npm_audit_only_baseline.csv"
