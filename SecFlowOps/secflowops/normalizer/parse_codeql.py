from __future__ import annotations

from pathlib import Path


def parse_file(path: Path, *, repo: str, commit: str, run_id: str) -> list[dict]:
    # CodeQL SARIF support is planned for GitHub Actions mode.
    return []
