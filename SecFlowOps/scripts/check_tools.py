from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


TOOLS = {
    "python": ["python", "--version"],
    "git": ["git", "--version"],
    "docker": ["docker", "--version"],
    "java": ["java", "-version"],
    "trivy": ["trivy", "--version"],
    "opa": ["opa", "version"],
    "semgrep": ["semgrep", "--version"],
    "gitleaks": ["gitleaks", "version"],
    "zap": ["zap", "-version"],
}

TOOL_TIMEOUTS = {
    "semgrep": 150,
    "trivy": 60,
    "zap": 120,
}


def tool_environment() -> dict[str, str]:
    env = os.environ.copy()
    semgrep_home = ROOT / "artifact" / "semgrep_home"
    trivy_cache = ROOT / "artifact" / "trivy_cache"
    semgrep_home.mkdir(parents=True, exist_ok=True)
    trivy_cache.mkdir(parents=True, exist_ok=True)
    env.setdefault("XDG_CONFIG_HOME", str(semgrep_home))
    env.setdefault("SEMGREP_LOG_FILE", str(semgrep_home / "semgrep.log"))
    env.setdefault("SEMGREP_SETTINGS_FILE", str(semgrep_home / "settings.yml"))
    env.setdefault("TRIVY_CACHE_DIR", str(trivy_cache))
    return env


def resolve_executable(command: list[str]) -> str | None:
    if command[0] == "java":
        java_candidates = [
            Path(r"C:\Program Files\Java\jdk-24\bin\java.exe"),
            Path(r"C:\Program Files\Eclipse Adoptium\jre-17.0.19.10-hotspot\bin\java.exe"),
        ]
        for candidate in java_candidates:
            if candidate.exists():
                command[0] = str(candidate)
                return str(candidate)
    exe = shutil.which(command[0])
    if exe:
        return exe
    if command[0] == "zap":
        java_cmd = ["java", "-version"]
        java_exe = resolve_executable(java_cmd)
        zap_dir = ROOT / "tools" / "zap" / "ZAP_2.17.0"
        zap_jar = zap_dir / "zap-2.17.0.jar"
        if java_exe and zap_jar.exists():
            command[:] = [java_exe, "-jar", str(zap_jar), "-version"]
            return str(zap_jar)
    local_names = {
        "opa": ROOT / "tools" / "opa.exe",
        "gitleaks": ROOT / "tools" / "gitleaks" / "gitleaks.exe",
    }
    local_exe = local_names.get(command[0])
    if local_exe and local_exe.exists():
        command[0] = str(local_exe)
        return str(local_exe)
    return None


def check_tool(name: str, command: list[str]) -> dict:
    command = list(command)
    exe = resolve_executable(command)
    if not exe:
        return {"tool": name, "available": False, "path": None, "version": None, "error": "not in PATH"}
    try:
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=TOOL_TIMEOUTS.get(name, 30),
            env=tool_environment(),
            cwd=ROOT / "tools" / "zap" / "ZAP_2.17.0" if name == "zap" else None,
        )
        version = (proc.stdout or proc.stderr).strip().splitlines()[:3]
        return {
            "tool": name,
            "available": proc.returncode == 0,
            "path": exe,
            "version": " | ".join(version),
            "error": None if proc.returncode == 0 else proc.stderr.strip(),
        }
    except Exception as exc:  # noqa: BLE001 - diagnostic script
        return {"tool": name, "available": False, "path": exe, "version": None, "error": str(exc)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when any required tool is unavailable.")
    args = parser.parse_args()

    rows = [check_tool(name, cmd) for name, cmd in TOOLS.items()]
    out = ROOT / "artifact" / "tool_status.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    for row in rows:
        status = "OK" if row["available"] else "MISSING"
        print(f"{status:8} {row['tool']:8} {row['version'] or row['error']}")
    print(f"wrote {out}")
    if args.strict and any(not row["available"] for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
