#!/usr/bin/env bash
set -euo pipefail

python SecFlowOps/scripts/check_tools.py --strict
python SecFlowOps/scripts/prepare_full_protocol_corpus.py
python SecFlowOps/scripts/run_matrix.py \
  --campaign-id run_all_full_protocol \
  --scenario auto \
  --build-mode python_unittest \
  --repetitions 3 \
  --repos $(tail -n +2 SecFlowOps/experiments/full_protocol_corpus_manifest.csv | cut -d, -f1) \
  --configs C0_BuildOnly C1_NonBlockingScanning C2_AutoScanning C3_PolicyOnly C4_AgentsOnly C5_SecFlowOps
python SecFlowOps/scripts/compute_metrics.py
python SecFlowOps/scripts/analyze_performance.py
python SecFlowOps/scripts/statistical_analysis.py
python SecFlowOps/scripts/generate_figures.py
(cd SecFlowOps/paper && pdflatex -interaction=nonstopmode main.tex && bibtex main && pdflatex -interaction=nonstopmode main.tex && pdflatex -interaction=nonstopmode main.tex)
