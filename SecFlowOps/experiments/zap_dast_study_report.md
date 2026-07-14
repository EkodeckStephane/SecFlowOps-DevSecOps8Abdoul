# ZAP DAST Study Report

Campaign: `zap_enabled_probe_20260714_matched`

## Installation and Tooling

- ZAP version: 2.17.0
- ZAP artifact: `SecFlowOps/tools/zap/ZAP_2.17.0_Core.zip`
- Release checksum verified: `0cb73b7f72d12c263fb61de304edb82a455d7aa4e1813c216c061765c306f5b7`
- Java used: `C:\Program Files\Java\jdk-24\bin\java.exe`
- Java version: 24.0.1

The native `winget install ZAP.ZAP` path failed because the installer required administrator elevation. The portable ZAP Core archive was therefore used inside the artifact.

## Protocol

- Repository: `full_alpha_sast_reflected_xss`
- Configurations: `C1_NonBlockingScanning`, `C3_PolicyOnly`
- Repetitions: 1
- Runner flag: `--enable-zap`
- Target: local copied workspace started by `app.py`
- Target port: dynamically allocated per run
- ZAP proxy port: dynamically allocated per run

## Results

Both runs completed successfully and produced `scanner_outputs/zap.json`.

ZAP detected a reflected XSS finding:

- tool: `zap`
- category: `dast`
- severity: `high`
- message: `Cross Site Scripting (Reflected)`
- matched ground truth: `GT-DAST-XSS-001-full_alpha_sast_reflected_xss`

Summary metrics:

| Configuration | Runs | Success rate | Findings | Recall | Precision |
|---|---:|---:|---:|---:|---:|
| C1_NonBlockingScanning | 1 | 1.000 | 24.0 | 1.000 | 0.083 |
| C3_PolicyOnly | 1 | 1.000 | 24.0 | 1.000 | 0.083 |

Performance:

| Configuration | Pipeline time | Total scanner time |
|---|---:|---:|
| C1_NonBlockingScanning | 44.056 s | 25.845 s |
| C3_PolicyOnly | 38.903 s | 20.116 s |

## Produced Files

- `SecFlowOps/data/processed/run_metrics_zap_probe_matched.csv`
- `SecFlowOps/data/processed/finding_metrics_zap_probe_matched.csv`
- `SecFlowOps/tables/summary_metrics_zap_probe_matched.csv`
- raw ZAP JSON under `SecFlowOps/data/raw/*zap_enabled_probe_20260714_matched*/scanner_outputs/zap.json`

## Remaining Limits

This is a targeted DAST probe, not a complete rerun of all 432 full-protocol runs with ZAP enabled. A full ZAP-enabled 432-run campaign is now technically possible but would be substantially slower because each ZAP quick scan adds roughly 17 to 26 seconds in the observed probe.
