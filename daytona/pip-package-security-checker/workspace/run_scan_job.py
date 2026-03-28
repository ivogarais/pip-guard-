#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import os
import re
import shlex
import subprocess
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from urllib.parse import quote

WORKSPACE_DIR = Path("/home/daytona/pip-package-security-checker")
JOBS_DIR = WORKSPACE_DIR / "jobs"
VENV_BIN_DIR = WORKSPACE_DIR / ".venv" / "bin"
PYTHON_BIN = VENV_BIN_DIR / "python"
BANDIT_BIN = VENV_BIN_DIR / "bandit"
DETECT_SECRETS_BIN = VENV_BIN_DIR / "detect-secrets"
CYCLODX_BIN = VENV_BIN_DIR / "cyclonedx-py"
PINNED_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)")
DECISION_VALUES = {"allow", "warn", "block"}
RISK_VALUES = {"low", "medium", "high", "critical"}
CONFIDENCE_VALUES = {"low", "medium", "high"}
RISK_SCORES = {"low": 24, "medium": 49, "high": 74, "critical": 94}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def update_status(job_dir: Path, **fields: object) -> dict[str, object]:
    path = job_dir / "status.json"
    payload = read_json(path)
    payload.update(fields)
    write_json(path, payload)
    return payload


def shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def html_escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def truncate_text(value: str, limit: int = 240) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def strip_code_fences(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def run_logged(
    cmd: list[str],
    *,
    log_path: Path,
    cwd: Path = WORKSPACE_DIR,
    accepted_codes: set[int] | None = None,
    capture_stdout: bool = False,
) -> subprocess.CompletedProcess[str]:
    accepted_codes = accepted_codes or {0}
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if capture_stdout:
        completed = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
        with log_path.open("w", encoding="utf-8") as handle:
            if completed.stdout:
                handle.write(completed.stdout)
            if completed.stderr:
                if completed.stdout:
                    handle.write("\n")
                handle.write(completed.stderr)
    else:
        with log_path.open("w", encoding="utf-8") as handle:
            completed = subprocess.run(cmd, cwd=cwd, text=True, stdout=handle, stderr=subprocess.STDOUT)
    if completed.returncode not in accepted_codes:
        raise RuntimeError(f"command failed ({completed.returncode}): {shell_join(cmd)}")
    return completed


def stage_package(package: str, logs_dir: Path) -> dict[str, object]:
    cmd = [str(PYTHON_BIN), "tools/stage_pypi_release.py", package]
    result = run_logged(cmd, log_path=logs_dir / "stage.log", capture_stdout=True)
    return json.loads(result.stdout)


def count_bandit_results(path: Path) -> int:
    if not path.exists():
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return 0
    results = payload.get("results", [])
    return len(results) if isinstance(results, list) else 0


def count_pypi_vulns(path: Path) -> int:
    if not path.exists():
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return 0
    total = 0
    packages = payload.get("packages", [])
    if not isinstance(packages, list):
        return 0
    for item in packages:
        if isinstance(item, dict):
            vulns = item.get("vulnerabilities", [])
            if isinstance(vulns, list):
                total += len(vulns)
    return total


def count_pypi_lookup_errors(path: Path) -> int:
    if not path.exists():
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return 0
    errors = payload.get("lookup_errors", [])
    return len(errors) if isinstance(errors, list) else 0


def count_detect_secrets(path: Path) -> int:
    if not path.exists():
        return 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return 0
    results = payload.get("results", {})
    if not isinstance(results, dict):
        return 0
    total = 0
    for findings in results.values():
        if isinstance(findings, list):
            total += len(findings)
    return total


def build_report_overview(package: str, run_dir: Path, reports_dir: Path) -> dict[str, object]:
    overview = {
        "package": package,
        "run_dir": str(run_dir),
        "reports_dir": str(reports_dir),
        "counts": {
            "bandit_results": count_bandit_results(reports_dir / "bandit.json"),
            "pypi_vulns": count_pypi_vulns(reports_dir / "pypi-vulns.json"),
            "pypi_lookup_errors": count_pypi_lookup_errors(reports_dir / "pypi-vulns.json"),
            "detect_secrets_findings": count_detect_secrets(reports_dir / "detect-secrets.json"),
            "grep_matches": sum(1 for line in (reports_dir / "grep-findings.txt").open(encoding="utf-8")) if (reports_dir / "grep-findings.txt").exists() else 0,
            "file_inventory_entries": sum(1 for line in (reports_dir / "file-types.txt").open(encoding="utf-8")) if (reports_dir / "file-types.txt").exists() else 0,
            "resolved_dependencies": sum(1 for line in (reports_dir / "resolved-requirements.txt").open(encoding="utf-8") if line.strip() and not line.startswith("#")) if (reports_dir / "resolved-requirements.txt").exists() else 0,
        },
        "files": {
            "stage": str(reports_dir / "stage.json"),
            "uv_lock": str(run_dir / "resolution" / "uv.lock"),
            "resolved_requirements": str(reports_dir / "resolved-requirements.txt"),
            "pypi_vulns": str(reports_dir / "pypi-vulns.json"),
            "bandit": str(reports_dir / "bandit.json"),
            "detect_secrets": str(reports_dir / "detect-secrets.json"),
            "sbom": str(reports_dir / "sbom.json"),
            "grep_findings": str(reports_dir / "grep-findings.txt"),
            "file_types": str(reports_dir / "file-types.txt"),
        },
    }
    write_json(reports_dir / "report-overview.json", overview)
    return overview


def create_resolution_project(run_dir: Path, package: str) -> tuple[Path, Path]:
    project_dir = run_dir / "resolution"
    project_dir.mkdir(parents=True, exist_ok=True)
    pyproject = "\n".join(
        [
            "[project]",
            'name = "advisory-resolution"',
            'version = "0.0.0"',
            'requires-python = ">=3.14"',
            f"dependencies = [{json.dumps(package)}]",
            "",
        ]
    )
    (project_dir / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    return project_dir, project_dir / "uv.lock"


def run_resolution_lock(package: str, run_dir: Path, reports_dir: Path, logs_dir: Path) -> tuple[Path, Path]:
    project_dir, uv_lock_path = create_resolution_project(run_dir, package)
    run_logged(
        ["uv", "lock", "--project", str(project_dir)],
        log_path=logs_dir / "uv-lock.log",
    )
    resolved_requirements = reports_dir / "resolved-requirements.txt"
    run_logged(
        [
            "uv",
            "export",
            "--project",
            str(project_dir),
            "--frozen",
            "--no-header",
            "--no-hashes",
            "--no-emit-project",
            "--format",
            "requirements.txt",
            "--output-file",
            str(resolved_requirements),
        ],
        log_path=logs_dir / "uv-export.log",
    )
    return project_dir, uv_lock_path


def parse_resolved_requirements(path: Path) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = PINNED_LINE_RE.match(line)
        if match:
            item = (match.group(1), match.group(2))
            if item not in seen:
                seen.add(item)
                packages.append(item)
    return packages


def query_pypi_vulnerabilities(package: str, version: str) -> tuple[dict[str, object], dict[str, str] | None]:
    url = f"https://pypi.org/pypi/{quote(package, safe='')}/{quote(version, safe='')}/json"
    completed = subprocess.run(
        [
            "curl",
            "--connect-timeout",
            "5",
            "--max-time",
            "20",
            "--retry",
            "2",
            "--retry-delay",
            "1",
            "--retry-connrefused",
            "-fsSL",
            url,
        ],
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        return (
            {
                "package": package,
                "version": version,
                "vulnerabilities": [],
            },
            {
                "package": package,
                "version": version,
                "error": f"curl exited with {completed.returncode}",
            },
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return (
            {
                "package": package,
                "version": version,
                "vulnerabilities": [],
            },
            {
                "package": package,
                "version": version,
                "error": f"invalid PyPI JSON: {exc}",
            },
        )
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        vulnerabilities = []
    return (
        {
            "package": package,
            "version": version,
            "vulnerabilities": vulnerabilities,
        },
        None,
    )


def run_pypi_vulnerability_lookup(reports_dir: Path, logs_dir: Path) -> None:
    resolved_requirements = reports_dir / "resolved-requirements.txt"
    packages = parse_resolved_requirements(resolved_requirements)
    results: list[dict[str, object]] = []
    lookup_errors: list[dict[str, str]] = []
    for package, version in packages:
        result, error = query_pypi_vulnerabilities(package, version)
        results.append(result)
        if error:
            lookup_errors.append(error)
    payload = {
        "packages": results,
        "total_packages": len(results),
        "packages_with_vulns": sum(1 for item in results if item["vulnerabilities"]),
        "total_vulnerabilities": sum(len(item["vulnerabilities"]) for item in results),
        "lookup_errors": lookup_errors,
    }
    write_json(reports_dir / "pypi-vulns.json", payload)
    (logs_dir / "pypi-vulns.log").write_text(
        (
            f"queried {len(results)} resolved packages from PyPI JSON release endpoints\n"
            f"packages with vulnerabilities: {payload['packages_with_vulns']}\n"
            f"lookup errors: {len(lookup_errors)}\n"
        ),
        encoding="utf-8",
    )


def run_detect_secrets(artifacts_dir: Path, reports_dir: Path, logs_dir: Path) -> None:
    report_path = reports_dir / "detect-secrets.json"
    log_path = logs_dir / "detect-secrets.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as stdout_handle, log_path.open("w", encoding="utf-8") as stderr_handle:
        completed = subprocess.run(
            [str(DETECT_SECRETS_BIN), "scan", "--all-files", str(artifacts_dir)],
            cwd=WORKSPACE_DIR,
            text=True,
            stdout=stdout_handle,
            stderr=stderr_handle,
        )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed ({completed.returncode}): uv run detect-secrets scan --all-files {artifacts_dir}")


def run_grep_heuristics(artifacts_dir: Path, reports_dir: Path, logs_dir: Path) -> None:
    pattern = (
        r"exec\(|eval\(|compile\(|subprocess\.|os\.system|pty\.spawn|"
        r"requests\.|httpx\.|urllib\.request|socket\.socket|"
        r"pickle\.(load|loads)\(|marshal\.(load|loads)\(|"
        r"base64\.(b64decode|urlsafe_b64decode)\(|"
        r"ctypes\.(CDLL|PyDLL|WinDLL)|"
        r"importlib\.import_module|__import__\(|"
        r"/bin/sh|bash -c|powershell"
    )
    report_path = reports_dir / "grep-findings.txt"
    log_path = logs_dir / "grep.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as stdout_handle, log_path.open("w", encoding="utf-8") as stderr_handle:
        completed = subprocess.run(
            ["rg", "-n", "--no-heading", "--color", "never", pattern, str(artifacts_dir)],
            cwd=WORKSPACE_DIR,
            text=True,
            stdout=stdout_handle,
            stderr=stderr_handle,
        )
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"command failed ({completed.returncode}): rg heuristics")


def run_file_inventory(artifacts_dir: Path, reports_dir: Path, logs_dir: Path) -> None:
    report_path = reports_dir / "file-types.txt"
    log_path = logs_dir / "file-types.log"
    command = f"find {shlex.quote(str(artifacts_dir))} -type f -print0 | xargs -0 file"
    with report_path.open("w", encoding="utf-8") as stdout_handle, log_path.open("w", encoding="utf-8") as stderr_handle:
        completed = subprocess.run(
            ["/bin/sh", "-lc", command],
            cwd=WORKSPACE_DIR,
            text=True,
            stdout=stdout_handle,
            stderr=stderr_handle,
        )
    if completed.returncode not in {0, 123}:
        raise RuntimeError(f"command failed ({completed.returncode}): {command}")


def normalize_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            items.append(text)
    return items


def load_vulnerability_rows(reports_dir: Path) -> list[dict[str, str]]:
    payload = read_json(reports_dir / "pypi-vulns.json")
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for package_entry in payload.get("packages", []):
        if not isinstance(package_entry, dict):
            continue
        package_name = str(package_entry.get("package", "")).strip()
        package_version = str(package_entry.get("version", "")).strip()
        vulnerabilities = package_entry.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            aliases = [str(alias).strip() for alias in vulnerability.get("aliases", []) if str(alias).strip()]
            vuln_id = str(vulnerability.get("id", "")).strip()
            dedupe_key = (
                package_name,
                package_version,
                vuln_id or "|".join(aliases),
                str(vulnerability.get("link", "")).strip(),
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            details = str(vulnerability.get("summary") or vulnerability.get("details") or "No details provided.").strip()
            fixed_in = vulnerability.get("fixed_in", [])
            rows.append(
                {
                    "package": package_name,
                    "version": package_version,
                    "id": vuln_id or "Unlabeled advisory",
                    "aliases": ", ".join(aliases) if aliases else "None listed",
                    "fixed_in": ", ".join(str(item).strip() for item in fixed_in if str(item).strip()) if isinstance(fixed_in, list) and fixed_in else "Not listed",
                    "source": str(vulnerability.get("source", "unknown")).strip() or "unknown",
                    "link": str(vulnerability.get("link", "")).strip(),
                    "details": details,
                }
            )
    return rows


def render_html_list(items: list[str], empty_message: str) -> str:
    if not items:
        return f"<p class=\"muted\">{html_escape(empty_message)}</p>"
    return "<ul>" + "".join(f"<li>{html_escape(item)}</li>" for item in items) + "</ul>"


def render_metrics_cards(counts: dict[str, object]) -> str:
    cards = [
        ("Advisories", int(counts.get("pypi_vulns", 0))),
        ("Dependencies", int(counts.get("resolved_dependencies", 0))),
        ("Bandit Findings", int(counts.get("bandit_results", 0))),
        ("Secret Findings", int(counts.get("detect_secrets_findings", 0))),
        ("Heuristic Matches", int(counts.get("grep_matches", 0))),
        ("PyPI Lookup Errors", int(counts.get("pypi_lookup_errors", 0))),
    ]
    return "".join(
        (
            "<div class=\"metric-card\">"
            f"<div class=\"metric-value\">{value}</div>"
            f"<div class=\"metric-label\">{html_escape(label)}</div>"
            "</div>"
        )
        for label, value in cards
    )


def render_summary_rows(counts: dict[str, object]) -> str:
    rows = [
        ("Resolved dependencies", counts.get("resolved_dependencies", 0)),
        ("Known advisories", counts.get("pypi_vulns", 0)),
        ("Bandit findings", counts.get("bandit_results", 0)),
        ("Detect-secrets findings", counts.get("detect_secrets_findings", 0)),
        ("Heuristic grep matches", counts.get("grep_matches", 0)),
        ("File inventory entries", counts.get("file_inventory_entries", 0)),
    ]
    return "".join(
        f"<tr><th>{html_escape(label)}</th><td>{html_escape(value)}</td></tr>"
        for label, value in rows
    )


def render_signal_chart(counts: dict[str, object]) -> str:
    values = [
        ("Advisories", int(counts.get("pypi_vulns", 0)), "#8f172a"),
        ("Bandit", int(counts.get("bandit_results", 0)), "#9a5f10"),
        ("Secrets", int(counts.get("detect_secrets_findings", 0)), "#1c6b4a"),
        ("Heuristics", int(counts.get("grep_matches", 0)), "#375a7f"),
    ]
    max_value = max(1, *(value for _, value, _ in values))
    width = 320
    height = 38 * len(values) + 12
    parts = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" aria-label="Signal counts chart">']
    for index, (label, value, color) in enumerate(values):
        y = 10 + index * 38
        bar_width = 0 if value == 0 else max(12, int((value / max_value) * 178))
        parts.append(f'<text x="0" y="{y + 13}" class="chart-label">{html_escape(label)}</text>')
        parts.append(f'<rect x="110" y="{y}" width="190" height="18" rx="9" fill="#e8decb"></rect>')
        parts.append(f'<rect x="110" y="{y}" width="{bar_width}" height="18" rx="9" fill="{color}"></rect>')
        parts.append(f'<text x="306" y="{y + 13}" text-anchor="end" class="chart-value">{value}</text>')
    parts.append("</svg>")
    return "".join(parts)


def render_risk_meter(risk_level: str, decision: str) -> str:
    score = RISK_SCORES.get(risk_level, 50)
    color = {
        "allow": "#1c6b4a",
        "warn": "#9a5f10",
        "block": "#8f172a",
    }.get(decision, "#375a7f")
    return (
        '<svg viewBox="0 0 240 72" class="meter" role="img" aria-label="Risk level meter">'
        '<text x="0" y="18" class="meter-label">Risk posture</text>'
        '<rect x="0" y="30" width="240" height="16" rx="8" fill="#e8decb"></rect>'
        f'<rect x="0" y="30" width="{score * 2.4:.1f}" height="16" rx="8" fill="{color}"></rect>'
        f'<text x="238" y="18" text-anchor="end" class="meter-value">{html_escape(risk_level.title())}</text>'
        f'<text x="238" y="62" text-anchor="end" class="meter-caption">{score}/100</text>'
        "</svg>"
    )


def render_vulnerability_rows(vulnerabilities: list[dict[str, str]]) -> str:
    if not vulnerabilities:
        return '<tr><td colspan="6" class="muted">No known advisories were associated with the resolved dependency set.</td></tr>'
    rows = []
    for item in vulnerabilities:
        link_cell = html_escape(item["id"])
        if item["link"]:
            link_cell = f'<a href="{html_escape(item["link"])}">{html_escape(item["id"])}</a>'
        rows.append(
            "<tr>"
            f"<td><code>{html_escape(item['package'])}</code><div class=\"muted\">{html_escape(item['version'])}</div></td>"
            f"<td>{link_cell}<div class=\"muted small\">{html_escape(item['aliases'])}</div></td>"
            f"<td>{html_escape(item['fixed_in'])}</td>"
            f"<td>{html_escape(item['source'])}</td>"
            f"<td><details><summary>Details</summary><p>{html_escape(item['details'])}</p></details></td>"
            f"<td>{html_escape(truncate_text(item['details'], 120))}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_artifact_rows(run_dir: Path, reports_dir: Path) -> str:
    entries = [
        ("Run directory", str(run_dir)),
        ("Stage report", str(reports_dir / "stage.json")),
        ("Resolved requirements", str(reports_dir / "resolved-requirements.txt")),
        ("Advisories", str(reports_dir / "pypi-vulns.json")),
        ("Bandit", str(reports_dir / "bandit.json")),
        ("Detect-secrets", str(reports_dir / "detect-secrets.json")),
        ("SBOM", str(reports_dir / "sbom.json")),
        ("Summary markdown", str(reports_dir / "codex-summary.md")),
        ("Structured verdict", str(reports_dir / "codex-verdict.json")),
        ("Rendered HTML report", str(reports_dir / "report.html")),
    ]
    return "".join(
        f"<tr><th>{html_escape(label)}</th><td><code>{html_escape(path)}</code></td></tr>"
        for label, path in entries
    )


def normalize_verdict(raw_payload: object, package: str) -> dict[str, object]:
    if not isinstance(raw_payload, dict):
        raise RuntimeError("codex verdict was not a JSON object")
    decision = str(raw_payload.get("decision", "")).strip().lower()
    risk_level = str(raw_payload.get("risk_level", "")).strip().lower()
    confidence = str(raw_payload.get("confidence", "")).strip().lower()
    if decision not in DECISION_VALUES:
        raise RuntimeError(f"invalid codex decision: {decision!r}")
    if risk_level not in RISK_VALUES:
        raise RuntimeError(f"invalid codex risk level: {risk_level!r}")
    if confidence not in CONFIDENCE_VALUES:
        raise RuntimeError(f"invalid codex confidence: {confidence!r}")
    executive_summary = str(raw_payload.get("executive_summary", "")).strip()
    recommended_action = str(raw_payload.get("recommended_action", "")).strip()
    if not executive_summary:
        raise RuntimeError("codex verdict missing executive_summary")
    if not recommended_action:
        raise RuntimeError("codex verdict missing recommended_action")
    recommended_version_raw = raw_payload.get("recommended_version")
    recommended_version = None if recommended_version_raw in {None, "", "null"} else str(recommended_version_raw).strip()
    return {
        "package": package,
        "decision": decision,
        "risk_level": risk_level,
        "confidence": confidence,
        "malicious": bool(raw_payload.get("malicious", False)),
        "known_vulnerabilities": bool(raw_payload.get("known_vulnerabilities", False)),
        "executive_summary": executive_summary,
        "recommended_action": recommended_action,
        "recommended_version": recommended_version,
        "suspicious_behavior": normalize_string_list(raw_payload.get("suspicious_behavior")),
        "key_evidence": normalize_string_list(raw_payload.get("key_evidence")),
        "notes": normalize_string_list(raw_payload.get("notes")),
    }


def run_codex_verdict(package: str, run_dir: Path, reports_dir: Path, logs_dir: Path) -> Path:
    verdict_path = reports_dir / "codex-verdict.json"
    overview_path = reports_dir / "report-overview.json"
    template_guide = Path.home() / ".codex-home" / "skills" / "pip-package-security-checker" / "references" / "report-template.md"
    schema_path = WORKSPACE_DIR / "tools" / "verdict_schema.json"
    prompt = "\n".join(
        [
            "Use the pip-package-security-checker skill.",
            f"Analyze the staged package {package}.",
            f"The run directory is {run_dir}.",
            f"Start with {overview_path}.",
            f"Follow the structured report guidance at {template_guide}.",
            "Do not read full large JSON reports unless the overview shows a reason.",
            "Prefer jq, rg, head, and targeted file inspection over dumping entire report files.",
            "Review these local artifacts if present:",
            f"- {overview_path}",
            f"- {reports_dir / 'stage.json'}",
            f"- {run_dir / 'resolution' / 'uv.lock'}",
            f"- {reports_dir / 'resolved-requirements.txt'}",
            f"- {reports_dir / 'pypi-vulns.json'}",
            f"- {reports_dir / 'bandit.json'}",
            f"- {reports_dir / 'detect-secrets.json'}",
            f"- {reports_dir / 'sbom.json'}",
            f"- {reports_dir / 'grep-findings.txt'}",
            f"- {reports_dir / 'file-types.txt'}",
            "Decision policy:",
            "- allow: no material maliciousness or package-risk concern found",
            "- warn: package appears non-malicious but has vulnerabilities or risky patterns worth stopping for review",
            "- block: clearly malicious, deceptive, or unacceptably dangerous behavior is present",
            "Return valid JSON only and do not wrap it in markdown fences.",
            "The JSON object must have exactly these keys:",
            '{',
            '  "decision": "allow|warn|block",',
            '  "risk_level": "low|medium|high|critical",',
            '  "confidence": "low|medium|high",',
            '  "malicious": true,',
            '  "known_vulnerabilities": true,',
            '  "executive_summary": "short paragraph",',
            '  "recommended_action": "short paragraph",',
            '  "recommended_version": "string or null",',
            '  "suspicious_behavior": ["short bullet", "short bullet"],',
            '  "key_evidence": ["short bullet", "short bullet"],',
            '  "notes": ["short bullet", "short bullet"]',
            '}',
        ]
    )
    log_path = logs_dir / "codex.log"
    with log_path.open("w", encoding="utf-8") as handle:
        completed = subprocess.run(
            [
                str(Path.home() / ".local" / "bin" / "codex-pip-checker"),
                "exec",
                "--skip-git-repo-check",
                "--output-schema",
                str(schema_path),
                "--output-last-message",
                str(verdict_path),
                prompt,
            ],
            cwd=WORKSPACE_DIR,
            text=True,
            stdout=handle,
            stderr=subprocess.STDOUT,
        )
    if completed.returncode != 0:
        raise RuntimeError(f"codex verdict failed ({completed.returncode})")
    raw_text = strip_code_fences(read_text(verdict_path))
    try:
        raw_payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"codex verdict was not valid JSON: {exc}") from exc
    normalized = normalize_verdict(raw_payload, package)
    write_json(verdict_path, normalized)
    return verdict_path


def build_markdown_summary(
    package: str,
    verdict: dict[str, object],
    vulnerabilities: list[dict[str, str]],
    reports_dir: Path,
) -> Path:
    summary_path = reports_dir / "codex-summary.md"
    suspicious_behavior = verdict.get("suspicious_behavior", [])
    key_evidence = verdict.get("key_evidence", [])
    notes = verdict.get("notes", [])
    lines = [
        "## 1. Verdict",
        "",
        str(verdict["executive_summary"]),
        "",
        f"- Decision: `{verdict['decision']}`",
        f"- Risk level: `{verdict['risk_level']}`",
        f"- Confidence: `{verdict['confidence']}`",
        f"- Malicious: `{'yes' if verdict['malicious'] else 'no'}`",
        f"- Known vulnerabilities: `{'yes' if verdict['known_vulnerabilities'] else 'no'}`",
        "",
        "## 2. Known Vulnerabilities",
        "",
    ]
    if vulnerabilities:
        for item in vulnerabilities[:8]:
            lines.extend(
                [
                    f"- `{item['package']}=={item['version']}`: `{item['id']}`",
                    f"  Fixed in: {item['fixed_in']}",
                    f"  Source: {item['source']}",
                    f"  Details: {truncate_text(item['details'], 260)}",
                ]
            )
        if len(vulnerabilities) > 8:
            lines.append(f"- Additional advisories omitted from summary: {len(vulnerabilities) - 8}")
    else:
        lines.append("No known advisories were associated with the resolved dependency set.")
    lines.extend(["", "## 3. Suspicious Behavior", ""])
    if suspicious_behavior:
        lines.extend(f"- {item}" for item in suspicious_behavior)
    else:
        lines.append("No suspicious behavior identified.")
    lines.extend(["", "## 4. Key Evidence", ""])
    if key_evidence:
        lines.extend(f"- {item}" for item in key_evidence)
    else:
        lines.append("No additional evidence notes provided.")
    lines.extend(["", "## 5. Recommended Action", "", str(verdict["recommended_action"])])
    recommended_version = verdict.get("recommended_version")
    if recommended_version:
        lines.append("")
        lines.append(f"Recommended version target: `{recommended_version}`")
    if notes:
        lines.extend(["", "Notes:"])
        lines.extend(f"- {item}" for item in notes)
    lines.append("")
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    return summary_path


def render_html_report(
    job_id: str,
    package: str,
    verdict: dict[str, object],
    overview: dict[str, object],
    vulnerabilities: list[dict[str, str]],
    run_dir: Path,
    reports_dir: Path,
) -> Path:
    template_path = WORKSPACE_DIR / "tools" / "report_template.html"
    template = Template(template_path.read_text(encoding="utf-8"))
    counts = overview.get("counts", {})
    if not isinstance(counts, dict):
        counts = {}
    decision = str(verdict["decision"])
    risk_level = str(verdict["risk_level"])
    confidence = str(verdict["confidence"])
    recommended_version = verdict.get("recommended_version")
    html_report = template.safe_substitute(
        page_title=html_escape(f"{package} Security Dossier"),
        package_name=html_escape(package),
        job_id=html_escape(job_id),
        generated_at=html_escape(utc_now()),
        decision_class=html_escape(decision),
        decision_label=html_escape(decision.upper()),
        risk_class=html_escape(risk_level),
        risk_label=html_escape(risk_level.title()),
        confidence_label=html_escape(confidence.title()),
        malicious_label="Yes" if verdict["malicious"] else "No",
        known_vulnerabilities_label="Yes" if verdict["known_vulnerabilities"] else "No",
        executive_summary=html_escape(str(verdict["executive_summary"])),
        recommended_action=html_escape(str(verdict["recommended_action"])),
        recommended_version=html_escape(recommended_version or "None specified"),
        risk_meter_svg=render_risk_meter(risk_level, decision),
        signal_chart_svg=render_signal_chart(counts),
        metrics_cards=render_metrics_cards(counts),
        summary_rows=render_summary_rows(counts),
        suspicious_behavior=render_html_list(list(verdict.get("suspicious_behavior", [])), "No suspicious behavior identified."),
        key_evidence=render_html_list(list(verdict.get("key_evidence", [])), "No additional evidence notes provided."),
        notes=render_html_list(list(verdict.get("notes", [])), "No extra notes."),
        vulnerability_rows=render_vulnerability_rows(vulnerabilities),
        artifact_rows=render_artifact_rows(run_dir, reports_dir),
    )
    report_path = reports_dir / "report.html"
    report_path.write_text(html_report, encoding="utf-8")
    return report_path


def build_result(job_id: str, requested_package: str, package: str, run_dir: Path, job_dir: Path, verdict: dict[str, object]) -> dict[str, object]:
    reports_dir = run_dir / "reports"
    result = {
        "job_id": job_id,
        "requested_package": requested_package,
        "package": package,
        "resolved_package": package,
        "decision": verdict["decision"],
        "risk_level": verdict["risk_level"],
        "confidence": verdict["confidence"],
        "malicious": verdict["malicious"],
        "known_vulnerabilities": verdict["known_vulnerabilities"],
        "run_dir": str(run_dir),
        "reports_dir": str(reports_dir),
        "summary_path": str(reports_dir / "codex-summary.md"),
        "verdict_path": str(reports_dir / "codex-verdict.json"),
        "report_path": str(reports_dir / "report.html"),
        "status_path": str(job_dir / "status.json"),
        "result_path": str(job_dir / "result.json"),
        "artifacts": {
            "stage": str(reports_dir / "stage.json"),
            "report_overview": str(reports_dir / "report-overview.json"),
            "uv_lock": str(run_dir / "resolution" / "uv.lock"),
            "resolved_requirements": str(reports_dir / "resolved-requirements.txt"),
            "pypi_vulns": str(reports_dir / "pypi-vulns.json"),
            "bandit": str(reports_dir / "bandit.json"),
            "detect_secrets": str(reports_dir / "detect-secrets.json"),
            "sbom": str(reports_dir / "sbom.json"),
            "grep_findings": str(reports_dir / "grep-findings.txt"),
            "file_types": str(reports_dir / "file-types.txt"),
            "verdict": str(reports_dir / "codex-verdict.json"),
            "summary": str(reports_dir / "codex-summary.md"),
            "report_html": str(reports_dir / "report.html"),
        },
        "logs": {
            "stage": str(job_dir / "logs" / "stage.log"),
            "uv_lock": str(job_dir / "logs" / "uv-lock.log"),
            "uv_export": str(job_dir / "logs" / "uv-export.log"),
            "pypi_vulns": str(job_dir / "logs" / "pypi-vulns.log"),
            "bandit": str(job_dir / "logs" / "bandit.log"),
            "detect_secrets": str(job_dir / "logs" / "detect-secrets.log"),
            "sbom": str(job_dir / "logs" / "sbom.log"),
            "grep": str(job_dir / "logs" / "grep.log"),
            "file_types": str(job_dir / "logs" / "file-types.log"),
            "codex": str(job_dir / "logs" / "codex.log"),
        },
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a full package triage job inside the Daytona sandbox.")
    parser.add_argument("package", help="Pinned package, for example requests==2.19.0")
    parser.add_argument("--job-id", default=uuid.uuid4().hex[:12], help="Unique job identifier")
    args = parser.parse_args()

    requested_package = args.package.strip()
    job_id = args.job_id
    job_dir = JOBS_DIR / job_id
    logs_dir = job_dir / "logs"
    job_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    update_status(
        job_dir,
        job_id=job_id,
        requested_package=requested_package,
        package=requested_package,
        state="running",
        started_at=utc_now(),
        pid=os.getpid(),
        phase="staging",
    )

    try:
        stage_payload = stage_package(requested_package, logs_dir)
        package = str(stage_payload.get("resolved_package") or stage_payload.get("package") or requested_package)
        run_dir = Path(str(stage_payload["root"]))
        reports_dir = Path(str(stage_payload["reports_dir"]))
        artifacts_dir = Path(str(stage_payload["artifacts_dir"]))

        update_status(
            job_dir,
            phase="resolution",
            package=package,
            resolved_package=package,
            run_dir=str(run_dir),
            reports_dir=str(reports_dir),
        )
        run_resolution_lock(package, run_dir, reports_dir, logs_dir)
        update_status(job_dir, phase="pypi-vulns")
        run_pypi_vulnerability_lookup(reports_dir, logs_dir)
        update_status(job_dir, phase="bandit")
        run_logged(
            [str(BANDIT_BIN), "-r", str(artifacts_dir), "-f", "json", "-o", str(reports_dir / "bandit.json")],
            log_path=logs_dir / "bandit.log",
            accepted_codes={0, 1},
        )
        update_status(job_dir, phase="detect-secrets")
        run_detect_secrets(artifacts_dir, reports_dir, logs_dir)
        update_status(job_dir, phase="sbom")
        run_logged(
            [
                str(CYCLODX_BIN),
                "requirements",
                str(reports_dir / "resolved-requirements.txt"),
                "--output-reproducible",
                "--of",
                "JSON",
                "-o",
                str(reports_dir / "sbom.json"),
            ],
            log_path=logs_dir / "sbom.log",
        )
        update_status(job_dir, phase="heuristics")
        run_grep_heuristics(artifacts_dir, reports_dir, logs_dir)
        run_file_inventory(artifacts_dir, reports_dir, logs_dir)
        overview = build_report_overview(package, run_dir, reports_dir)
        vulnerabilities = load_vulnerability_rows(reports_dir)
        update_status(job_dir, phase="codex-verdict")
        verdict_path = run_codex_verdict(package, run_dir, reports_dir, logs_dir)
        verdict = normalize_verdict(read_json(verdict_path), package)
        write_json(verdict_path, verdict)
        update_status(job_dir, phase="report-render")
        summary_path = build_markdown_summary(package, verdict, vulnerabilities, reports_dir)
        report_path = render_html_report(job_id, package, verdict, overview, vulnerabilities, run_dir, reports_dir)

        result = build_result(job_id, requested_package, package, run_dir, job_dir, verdict)
        write_json(job_dir / "result.json", result)
        update_status(
            job_dir,
            state="completed",
            completed_at=utc_now(),
            phase="completed",
            run_dir=str(run_dir),
            reports_dir=str(reports_dir),
            summary_path=str(summary_path),
            verdict_path=str(verdict_path),
            report_path=str(report_path),
            result_path=str(job_dir / "result.json"),
            requested_package=requested_package,
            package=package,
            resolved_package=package,
            decision=verdict["decision"],
            risk_level=verdict["risk_level"],
            confidence=verdict["confidence"],
            malicious=verdict["malicious"],
            known_vulnerabilities=verdict["known_vulnerabilities"],
        )
        return 0
    except Exception as exc:
        error_payload = {
            "job_id": job_id,
            "requested_package": requested_package,
            "package": requested_package,
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "failed_at": utc_now(),
        }
        write_json(job_dir / "error.json", error_payload)
        update_status(
            job_dir,
            state="failed",
            failed_at=error_payload["failed_at"],
            error=str(exc),
            error_path=str(job_dir / "error.json"),
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
