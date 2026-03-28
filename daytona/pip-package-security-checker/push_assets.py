#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import os
import subprocess
from pathlib import Path


def push_file(root: Path, sandbox: str, src: Path, dst: str) -> None:
    payload = base64.b64encode(src.read_bytes()).decode("ascii")
    code = (
        f'p=__import__("pathlib").Path("{dst}");'
        "p.parent.mkdir(parents=True,exist_ok=True);"
        f'p.write_bytes(__import__("base64").b64decode("{payload}"))'
    )
    env = dict(os.environ)
    env.setdefault("DAYTONA_API_URL", "https://app.daytona.io/api")
    completed = subprocess.run(
        ["daytona", "exec", sandbox, "--", "python3", "-c", f"'{code}'"],
        text=True,
        capture_output=True,
        env=env,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"failed to write {dst}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    if src.suffix in {".sh", ".py"}:
        chmod_completed = subprocess.run(
            ["daytona", "exec", sandbox, "--", "chmod", "+x", dst],
            text=True,
            capture_output=True,
            env=env,
        )
        if chmod_completed.returncode != 0:
            raise RuntimeError(
                f"failed to chmod {dst}\nstdout:\n{chmod_completed.stdout}\nstderr:\n{chmod_completed.stderr}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Push local pip-package-security-checker assets into a Daytona sandbox.")
    parser.add_argument("--sandbox", default="pip-package-security-checker", help="Daytona sandbox name or id")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    files = {
        root / "provision.sh": "/home/daytona/pip-package-security-checker/setup/provision.sh",
        root / "codex-pip-checker.sh": "/home/daytona/.local/bin/codex-pip-checker",
        root / "start-scan-service.sh": "/home/daytona/.local/bin/start-pip-package-security-checker",
        root / "workspace" / "stage_pypi_release.py": "/home/daytona/pip-package-security-checker/tools/stage_pypi_release.py",
        root / "workspace" / "run_scan_job.py": "/home/daytona/pip-package-security-checker/tools/run_scan_job.py",
        root / "workspace" / "scan_service.py": "/home/daytona/pip-package-security-checker/tools/scan_service.py",
        root / "workspace" / "rebuild_job_artifacts.py": "/home/daytona/pip-package-security-checker/tools/rebuild_job_artifacts.py",
        root / "workspace" / "report_template.html": "/home/daytona/pip-package-security-checker/tools/report_template.html",
        root / "workspace" / "verdict_schema.json": "/home/daytona/pip-package-security-checker/tools/verdict_schema.json",
        root / "skill" / "SKILL.md": "/home/daytona/.codex-home/skills/pip-package-security-checker/SKILL.md",
        root / "skill" / "references" / "checklist.md": "/home/daytona/.codex-home/skills/pip-package-security-checker/references/checklist.md",
        root / "skill" / "references" / "report-template.md": "/home/daytona/.codex-home/skills/pip-package-security-checker/references/report-template.md",
    }
    for src, dst in files.items():
        push_file(root, args.sandbox, src, dst)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
