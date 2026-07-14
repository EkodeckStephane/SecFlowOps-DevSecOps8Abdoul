from __future__ import annotations

from pathlib import Path


def parse_file(path: Path, *, repo: str, commit: str, run_id: str) -> list[dict]:
    # Dependabot/OSV support is intentionally a separate extension because
    # GitHub-hosted alert APIs require repository permissions.
    return []
