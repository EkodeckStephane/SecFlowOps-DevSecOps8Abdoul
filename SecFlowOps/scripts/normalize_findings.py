from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from secflowops.normalizer.common import enrich_with_ground_truth, load_ground_truth, write_jsonl
from secflowops.normalizer.parse_gitleaks import parse_file as parse_gitleaks
from secflowops.normalizer.parse_semgrep import parse_file as parse_semgrep
from secflowops.normalizer.parse_trivy import parse_file as parse_trivy
from secflowops.normalizer.parse_zap import parse_file as parse_zap


def normalize_run(
    raw_dir: Path,
    output_path: Path,
    *,
    repo: str,
    commit: str,
    run_id: str,
    ground_truth_path: Path | None = None,
) -> list[dict]:
    scanner_dir = raw_dir / "scanner_outputs"
    findings: list[dict] = []
    findings.extend(parse_trivy(scanner_dir / "trivy_fs.json", repo=repo, commit=commit, run_id=run_id))
    findings.extend(parse_semgrep(scanner_dir / "semgrep.json", repo=repo, commit=commit, run_id=run_id))
    findings.extend(parse_gitleaks(scanner_dir / "gitleaks.json", repo=repo, commit=commit, run_id=run_id))
    findings.extend(parse_zap(scanner_dir / "zap.json", repo=repo, commit=commit, run_id=run_id))
    findings.extend(parse_zap(scanner_dir / "report_json.json", repo=repo, commit=commit, run_id=run_id))

    ground_truth = load_ground_truth(
        ground_truth_path or ROOT / "repos" / "ground_truth" / "ground_truth_findings.csv"
    )
    enrich_with_ground_truth(findings, ground_truth)
    detected_at = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        finding.setdefault("timestamps", {})["detected_at"] = detected_at
    write_jsonl(output_path, findings)
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repo", default="sample_api")
    parser.add_argument("--commit", default="local")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    normalize_run(
        Path(args.raw_dir),
        Path(args.output),
        repo=args.repo,
        commit=args.commit,
        run_id=args.run_id,
    )


if __name__ == "__main__":
    main()
