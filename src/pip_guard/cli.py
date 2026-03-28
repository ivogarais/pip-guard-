from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import shutil
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request

from rich import box
from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.prompt import Confirm
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from pip_guard import __version__

DEFAULT_SANDBOX = os.environ.get("PIP_GUARD_SANDBOX", "pip-package-security-checker")
DEFAULT_DAYTONA_API_URL = os.environ.get("PIP_GUARD_DAYTONA_API_URL") or os.environ.get("DAYTONA_API_URL") or "https://app.daytona.io/api"
DEFAULT_SERVICE_START = "/home/daytona/.local/bin/start-pip-package-security-checker"
PHASE_TIMEOUT_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 1800
DEFAULT_POLL_INTERVAL = 2.0
DISPLAY_STAGES = [
    ("sandbox", "Sandbox ready", "Wake the Daytona worker and expose the scan API."),
    ("staging", "Stage package", "Fetch the exact release artifacts and unpack them for review."),
    ("resolution", "Resolve dependencies", "Pin the dependency graph with uv before checking advisories."),
    ("advisories", "Collect advisories", "Associate known vulnerabilities with the resolved package set."),
    ("analysis", "Static analysis", "Run code, secrets, SBOM, and heuristic checks inside the sandbox."),
    ("review", "Analyst review", "Reason over the gathered evidence and choose allow, warn, or block."),
    ("report", "Build report", "Render the final HTML dossier and bundle the machine-readable verdict."),
]
STAGE_KEYS = [key for key, _, _ in DISPLAY_STAGES]
PHASE_TO_STAGE = {
    "queued": "staging",
    "staging": "staging",
    "resolution": "resolution",
    "pypi-vulns": "advisories",
    "bandit": "analysis",
    "detect-secrets": "analysis",
    "sbom": "analysis",
    "heuristics": "analysis",
    "codex-verdict": "review",
    "report-render": "report",
    "completed": "report",
}
PHASE_LABELS = {
    "queued": "Queued in Daytona",
    "staging": "Staging the exact package release",
    "resolution": "Resolving the dependency graph with uv",
    "pypi-vulns": "Matching resolved packages to advisory data",
    "bandit": "Running Python code security checks",
    "detect-secrets": "Scanning for secrets and suspicious tokens",
    "sbom": "Generating a dependency inventory",
    "heuristics": "Inspecting file types and suspicious strings",
    "codex-verdict": "Analyst review is reasoning over the evidence",
    "report-render": "Rendering the HTML report and verdict bundle",
    "completed": "Scan completed",
}
DECISION_INSTALL_STATE = {
    "allow": "install",
    "warn": "confirm",
    "block": "deny",
}
DECISION_STYLES = {
    "allow": "green",
    "warn": "yellow",
    "block": "red",
}


class PipGuardError(RuntimeError):
    pass


@dataclass
class WrapperConfig:
    package: str
    sandbox: str
    api_url: str
    service_start: str
    preview_expires: int
    timeout: int
    poll_interval: float
    daytona_bin: str
    python: str
    installer: str
    pip_args: list[str]
    yes: bool
    force: bool
    open_report: bool
    install_mode: bool


@dataclass
class ScanArtifacts:
    base_url: str
    job_id: str
    status_url: str
    result_url: str
    summary_url: str
    verdict_url: str
    report_url: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pip-guard",
        description="Send package triage to the dedicated Daytona sandbox before installation.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = add_common_scan_args(subparsers.add_parser("install", help="scan a package in Daytona, then install the exact scanned version if allowed"))
    install_parser.set_defaults(install_mode=True)

    scan_parser = add_common_scan_args(subparsers.add_parser("scan", help="scan a package in Daytona and print the verdict without installing"))
    scan_parser.set_defaults(install_mode=False)
    return parser


def add_common_scan_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("package", help="Package requirement to analyze, for example requests or requests==2.32.0")
    parser.add_argument("--sandbox", default=DEFAULT_SANDBOX, help=f"Daytona sandbox name or id (default: {DEFAULT_SANDBOX})")
    parser.add_argument("--daytona-api-url", default=DEFAULT_DAYTONA_API_URL, help=f"Daytona API URL (default: {DEFAULT_DAYTONA_API_URL})")
    parser.add_argument("--service-start", default=DEFAULT_SERVICE_START, help="Command to start the scan service inside the sandbox")
    parser.add_argument("--preview-expires", type=int, default=3600, help="Signed preview URL lifetime in seconds")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="Maximum scan time in seconds")
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL, help="Polling interval in seconds while waiting for the scan")
    parser.add_argument("--daytona-bin", default=os.environ.get("PIP_GUARD_DAYTONA_BIN", "daytona"), help="Daytona CLI executable")
    parser.add_argument("--open-report", action="store_true", help="Open the HTML report in the default browser when the scan completes")
    parser.add_argument("--yes", action="store_true", help="Automatically accept warn-level installs without prompting")
    parser.add_argument("--force", action="store_true", help="Allow installation even when the verdict is block")
    parser.add_argument("--python", default=sys.executable, help="Target Python interpreter for installation (default: current interpreter)")
    parser.add_argument("--installer", choices=("auto", "pip", "uv"), default="auto", help="Installer backend for the local install step")
    return parser


def args_to_config(args: argparse.Namespace) -> WrapperConfig:
    return WrapperConfig(
        package=args.package.strip(),
        sandbox=args.sandbox,
        api_url=args.daytona_api_url,
        service_start=args.service_start,
        preview_expires=args.preview_expires,
        timeout=args.timeout,
        poll_interval=args.poll_interval,
        daytona_bin=args.daytona_bin,
        python=args.python,
        installer=args.installer,
        pip_args=list(getattr(args, "pip_args", [])),
        yes=args.yes,
        force=args.force,
        open_report=args.open_report,
        install_mode=args.install_mode,
    )


def cli_env(api_url: str) -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("DAYTONA_API_URL", api_url)
    return env


def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    capture_output: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        text=True,
        capture_output=capture_output,
        env=env,
    )
    if check and completed.returncode != 0:
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        detail = stderr or stdout or f"command exited with code {completed.returncode}"
        raise PipGuardError(f"{shlex.join(command)} failed: {detail}")
    return completed


def run_daytona(config: WrapperConfig, *args: str, capture_output: bool = True) -> subprocess.CompletedProcess[str]:
    return run_command(
        [config.daytona_bin, *args],
        env=cli_env(config.api_url),
        capture_output=capture_output,
    )


def run_daytona_json(config: WrapperConfig, *args: str) -> dict[str, Any]:
    completed = run_daytona(config, *args)
    stdout = completed.stdout.strip()
    if not stdout:
        return {}
    return json.loads(stdout)


def http_json(url: str, *, method: str = "GET", payload: dict[str, Any] | None = None, timeout: int = 30) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(url, data=data, method=method)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise PipGuardError(f"{method} {url} failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise PipGuardError(f"{method} {url} failed: {exc.reason}") from exc


def join_url(base_url: str, path: str) -> str:
    return parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def ensure_sandbox_started(console: Console, config: WrapperConfig) -> dict[str, Any]:
    info = run_daytona_json(config, "info", config.sandbox, "-f", "json")
    state = str(info.get("state", "unknown"))
    if state == "started":
        console.log(f"Sandbox [bold]{config.sandbox}[/] is already running.")
        return info

    console.log(f"Starting Daytona sandbox [bold]{config.sandbox}[/].")
    run_daytona(config, "start", config.sandbox)
    deadline = time.monotonic() + PHASE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        info = run_daytona_json(config, "info", config.sandbox, "-f", "json")
        state = str(info.get("state", "unknown"))
        if state == "started":
            console.log(f"Sandbox [bold]{config.sandbox}[/] is ready.")
            return info
        time.sleep(1)
    raise PipGuardError(f"Sandbox {config.sandbox!r} did not reach started state within {PHASE_TIMEOUT_SECONDS} seconds.")


def ensure_service_ready(console: Console, config: WrapperConfig) -> str:
    console.log("Ensuring the Daytona scan worker is listening on port 3001.")
    run_daytona(config, "exec", config.sandbox, "--", config.service_start)
    base_url = run_daytona(config, "preview-url", config.sandbox, "-p", "3001", "--expires", str(config.preview_expires)).stdout.strip()
    deadline = time.monotonic() + PHASE_TIMEOUT_SECONDS
    health_url = join_url(base_url, "/health")
    while time.monotonic() < deadline:
        try:
            health = http_json(health_url, timeout=10)
        except PipGuardError:
            time.sleep(1)
            continue
        if health.get("status") == "ok":
            console.log(f"Scan worker is healthy at [link={base_url}]{base_url}[/link].")
            return base_url
        time.sleep(1)
    raise PipGuardError(f"Scan service did not become healthy within {PHASE_TIMEOUT_SECONDS} seconds.")


def submit_scan(console: Console, base_url: str, package: str) -> ScanArtifacts:
    console.log(f"Submitting [bold]{package}[/] to the Daytona sandbox.")
    payload = http_json(join_url(base_url, "/scan"), method="POST", payload={"package": package}, timeout=30)
    job_id = str(payload["job_id"])
    return ScanArtifacts(
        base_url=base_url,
        job_id=job_id,
        status_url=join_url(base_url, str(payload["status_url"])),
        result_url=join_url(base_url, str(payload["result_url"])),
        summary_url=join_url(base_url, str(payload["summary_url"])),
        verdict_url=join_url(base_url, str(payload["verdict_url"])),
        report_url=join_url(base_url, str(payload["report_url"])),
    )


def stage_state(stage_key: str, current_phase: str, state: str) -> str:
    current_stage = PHASE_TO_STAGE.get(current_phase, "staging")
    current_idx = STAGE_KEYS.index(current_stage)
    stage_idx = STAGE_KEYS.index(stage_key)
    if state == "failed":
        if stage_idx < current_idx:
            return "done"
        if stage_idx == current_idx:
            return "failed"
        return "pending"
    if state == "completed":
        return "done"
    if stage_idx < current_idx:
        return "done"
    if stage_idx == current_idx:
        return "running"
    return "pending"


def stage_indicator(state: str) -> RenderableType:
    if state == "done":
        return Text.assemble(("● ", "green bold"), ("complete", "green"))
    if state == "running":
        return Spinner("dots", text=Text(" active", style="bold cyan"), style="cyan", speed=1.15)
    if state == "failed":
        return Text.assemble(("✕ ", "red bold"), ("failed", "red"))
    return Text.assemble(("○ ", "grey50"), ("queued", "dim"))


def animated_stage_fraction(started_at: float) -> float:
    pulse = (math.sin((time.monotonic() - started_at) * 3.1) + 1) / 2
    return 0.24 + (pulse * 0.5)


def overall_progress(current_phase: str, state: str, started_at: float) -> float:
    current_stage = PHASE_TO_STAGE.get(current_phase, "staging")
    current_idx = STAGE_KEYS.index(current_stage)
    if state == "completed":
        return float(len(STAGE_KEYS))
    if state == "failed":
        return float(current_idx)
    return float(current_idx) + animated_stage_fraction(started_at)


def scan_border_style(state: str) -> str:
    if state == "completed":
        return "green"
    if state == "failed":
        return "red"
    return "bright_blue"


def active_phase_render(current_phase: str, state: str) -> RenderableType:
    label = PHASE_LABELS.get(current_phase, current_phase)
    if state == "completed":
        return Text.assemble(("● ", "green bold"), (label, "bold green"))
    if state == "failed":
        return Text.assemble(("✕ ", "red bold"), (label, "bold red"))
    return Spinner("arc", text=Text(label, style="bold cyan"), style="cyan", speed=1.1)


def elapsed_text(started_at: float) -> str:
    elapsed = max(0, int(time.monotonic() - started_at))
    minutes, seconds = divmod(elapsed, 60)
    return f"{minutes:02d}:{seconds:02d}"


def render_progress_view(
    *,
    config: WrapperConfig,
    job: ScanArtifacts,
    status_payload: dict[str, Any],
    started_at: float,
) -> RenderableType:
    current_phase = str(status_payload.get("phase", "queued"))
    state = str(status_payload.get("state", "queued"))
    current_stage = PHASE_TO_STAGE.get(current_phase, "staging")
    package_label = str(status_payload.get("requested_package") or config.package)
    resolved_package = status_payload.get("resolved_package") or status_payload.get("package")
    overview = Table.grid(expand=True)
    overview.add_column(ratio=2)
    overview.add_column(justify="right")
    overview.add_row(
        Group(
            Text("pip-guard", style="bold #f2f0e8 on #1e3b38"),
            Text(str(package_label), style="bold"),
        ),
        Text.assemble(
            ("Sandbox ", "dim"),
            (config.sandbox, "bold"),
            ("  Job ", "dim"),
            (job.job_id, "bold"),
            ("  Elapsed ", "dim"),
            (elapsed_text(started_at), "bold"),
        ),
    )

    if resolved_package:
        package_line = Text.assemble(
            ("Exact version under review: ", "dim"),
            (str(resolved_package), "bold"),
        )
    else:
        package_line = Text("Waiting for the sandbox to resolve the exact release.", style="dim")

    progress_bar = ProgressBar(
        total=len(STAGE_KEYS),
        completed=overall_progress(current_phase, state, started_at),
        pulse=state not in {"completed", "failed"},
        animation_time=time.monotonic(),
        complete_style="bright_blue",
        finished_style="green",
        pulse_style="cyan",
    )

    settled_count = sum(1 for stage_key, _, _ in DISPLAY_STAGES if stage_state(stage_key, current_phase, state) == "done")
    activity_panel = Panel(
        Group(
            active_phase_render(current_phase, state),
            Text(),
            package_line,
            Text(f"Settled phases: {settled_count}/{len(STAGE_KEYS)}", style="dim"),
            progress_bar,
        ),
        title="Live Activity",
        border_style=scan_border_style(state),
        padding=(1, 2),
    )

    job_panel = Panel(
        Group(
            Text.assemble(("Current state: ", "dim"), (state, "bold")),
            Text.assemble(("Current stage: ", "dim"), (current_stage, "bold cyan" if state != "failed" else "bold red")),
            Text.from_markup(f"[dim]Verdict URL[/]: [link={job.verdict_url}]{job.verdict_url}[/link]"),
            Text.from_markup(f"[dim]Report URL[/]: [link={job.report_url}]{job.report_url}[/link]"),
        ),
        title="Job",
        border_style="grey50",
        padding=(1, 2),
    )

    details = Table(box=box.SIMPLE_HEAD, expand=True, show_header=False, pad_edge=False)
    details.add_column(width=12, no_wrap=True)
    details.add_column(width=20)
    details.add_column(ratio=4)
    for stage_key, label, description in DISPLAY_STAGES:
        state_label = stage_state(stage_key, current_phase, state)
        description_text = description
        label_text = Text(label, style="bold")
        if PHASE_TO_STAGE.get(current_phase) == stage_key:
            description_text = PHASE_LABELS.get(current_phase, description)
            label_text = Text(label, style="bold cyan")
        elif state_label == "done":
            label_text = Text(label, style="bold green")
        elif state_label == "failed":
            label_text = Text(label, style="bold red")
        details.add_row(stage_indicator(state_label), label_text, description_text)

    pipeline_panel = Panel(details, title="Pipeline", border_style="grey50", padding=(1, 2))

    footer = Text(PHASE_LABELS.get(current_phase, current_phase), style="cyan" if state != "failed" else "red")
    if state == "failed":
        footer.append(f"\n{status_payload.get('error', 'Unknown scan failure.')}", style="red")

    return Panel(
        Group(overview, Text(), Columns([activity_panel, job_panel], expand=True), Text(), pipeline_panel, Rule(style="grey50"), footer),
        border_style=scan_border_style(state),
        padding=(1, 2),
        title="Daytona Scan",
    )


def poll_scan(console: Console, config: WrapperConfig, job: ScanArtifacts) -> tuple[dict[str, Any], dict[str, Any]]:
    started_at = time.monotonic()
    deadline = started_at + config.timeout
    latest_status: dict[str, Any] = {"state": "queued", "phase": "queued"}
    with Live(render_progress_view(config=config, job=job, status_payload=latest_status, started_at=started_at), console=console, refresh_per_second=8) as live:
        while time.monotonic() < deadline:
            latest_status = http_json(job.status_url, timeout=30)
            live.update(render_progress_view(config=config, job=job, status_payload=latest_status, started_at=started_at))
            state = str(latest_status.get("state", "queued"))
            if state == "completed":
                result = http_json(job.result_url, timeout=30)
                return latest_status, result
            if state == "failed":
                message = latest_status.get("error") or latest_status.get("error_path") or "The Daytona worker reported a failed scan."
                raise PipGuardError(str(message))
            time.sleep(config.poll_interval)
    raise PipGuardError(f"Timed out waiting for scan completion after {config.timeout} seconds.")


def fetch_verdict(job: ScanArtifacts) -> dict[str, Any]:
    return http_json(job.verdict_url, timeout=30)


def decision_style(decision: str) -> str:
    return DECISION_STYLES.get(decision, "white")


def render_verdict_panel(result: dict[str, Any], verdict: dict[str, Any], job: ScanArtifacts) -> Panel:
    decision = str(verdict.get("decision", result.get("decision", "unknown")))
    style = decision_style(decision)
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold", justify="right")
    summary.add_column(ratio=1)
    summary.add_row("Requested", str(result.get("requested_package") or ""))
    summary.add_row("Resolved", str(result.get("package") or ""))
    summary.add_row("Decision", f"[{style}]{decision.upper()}[/]")
    summary.add_row("Risk", str(verdict.get("risk_level", result.get("risk_level", "unknown"))))
    summary.add_row("Confidence", str(verdict.get("confidence", result.get("confidence", "unknown"))))
    summary.add_row("Malicious", "yes" if verdict.get("malicious") else "no")
    summary.add_row("Known vulns", "yes" if verdict.get("known_vulnerabilities") else "no")
    summary.add_row("Report", f"[link={job.report_url}]{job.report_url}[/link]")

    message = str(verdict.get("executive_summary") or "No executive summary returned.")
    recommendation = str(verdict.get("recommended_action") or "No recommendation returned.")
    body = Group(
        summary,
        Rule(style="grey50"),
        Text(message),
        Text(),
        Text(f"Recommended action: {recommendation}", style="bold"),
    )
    return Panel(body, title="Scan Verdict", border_style=style, padding=(1, 2))


def should_install(console: Console, config: WrapperConfig, result: dict[str, Any], verdict: dict[str, Any]) -> bool:
    decision = str(verdict.get("decision", result.get("decision", "block"))).lower()
    install_state = DECISION_INSTALL_STATE.get(decision, "deny")
    package = str(result.get("package") or config.package)
    if not config.install_mode:
        return False
    if install_state == "install":
        console.print(f"[green]Installing the exact scanned release:[/] [bold]{package}[/bold]")
        return True
    if install_state == "confirm":
        if config.yes:
            console.print(f"[yellow]Warning accepted automatically.[/] Proceeding with [bold]{package}[/bold].")
            return True
        if not sys.stdin.isatty():
            raise PipGuardError(
                f"Verdict is WARN for {package}, but pip-guard is running non-interactively. Re-run with --yes to accept the warning."
            )
        accepted = Confirm.ask(f"Verdict is WARN for {package}. Install anyway?", default=False, console=console)
        if not accepted:
            console.print("[yellow]Installation skipped.[/]")
        return accepted
    if config.force:
        console.print(f"[red]Block override enabled.[/] Proceeding with [bold]{package}[/bold].")
        return True
    console.print(f"[red]Installation blocked.[/] Re-run with [bold]--force[/] if you want to override this decision.")
    return False


def run_install(console: Console, config: WrapperConfig, result: dict[str, Any]) -> int:
    package = str(result.get("package") or config.package)
    command = resolve_install_command(console, config, package)
    console.print(Rule("Install"))
    console.print(f"[dim]Command[/]: {shlex.join(command)}")
    started_at = time.monotonic()
    with console.status(f"[bold cyan]Installing[/] {package}", spinner="dots"):
        completed = run_command(command, capture_output=True, check=False)
    duration = time.monotonic() - started_at
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        stdout = completed.stdout.strip()
        details = stderr or stdout or "pip did not return any output."
        console.print(Panel(details, title="pip install failed", border_style="red"))
        return completed.returncode
    console.print(Panel(f"Installed [bold]{package}[/bold] in {duration:.1f}s.", title="Install complete", border_style="green"))
    return 0


def resolve_install_command(console: Console, config: WrapperConfig, package: str) -> list[str]:
    if config.installer in {"auto", "pip"}:
        if pip_available(config.python):
            return pip_install_command(config, package)
        if bootstrap_pip(console, config.python):
            return pip_install_command(config, package)
        if config.installer == "pip":
            raise PipGuardError(f"pip is not available for interpreter {config.python!r} and could not be bootstrapped with ensurepip.")

    uv_bin = shutil.which("uv")
    if not uv_bin:
        raise PipGuardError(
            f"pip is unavailable for interpreter {config.python!r}, ensurepip did not restore it, and uv is not on PATH."
        )
    console.print(f"[yellow]Falling back to uv pip install for interpreter[/] [bold]{config.python}[/bold].")
    return [uv_bin, "pip", "install", "--python", config.python, package, *config.pip_args]


def pip_install_command(config: WrapperConfig, package: str) -> list[str]:
    return [
        config.python,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        package,
        *config.pip_args,
    ]


def pip_available(python_executable: str) -> bool:
    completed = subprocess.run(
        [python_executable, "-m", "pip", "--version"],
        text=True,
        capture_output=True,
    )
    return completed.returncode == 0


def bootstrap_pip(console: Console, python_executable: str) -> bool:
    console.print(f"[yellow]pip is missing for[/] [bold]{python_executable}[/bold][yellow]. Bootstrapping with ensurepip.[/]")
    with console.status(f"[bold cyan]Bootstrapping pip[/] for {python_executable}", spinner="dots"):
        completed = subprocess.run(
            [python_executable, "-m", "ensurepip", "--upgrade"],
            text=True,
            capture_output=True,
        )
    if completed.returncode != 0:
        return False
    return pip_available(python_executable)


def maybe_open_report(console: Console, report_url: str, enabled: bool) -> None:
    if not enabled:
        return
    opened = webbrowser.open(report_url)
    if opened:
        console.log(f"Opened HTML report in the default browser: [link={report_url}]{report_url}[/link]")
    else:
        console.log(f"Could not auto-open the report. Use this URL instead: [link={report_url}]{report_url}[/link]")


def execute_flow(console: Console, config: WrapperConfig) -> int:
    ensure_sandbox_started(console, config)
    base_url = ensure_service_ready(console, config)
    job = submit_scan(console, base_url, config.package)
    _, result = poll_scan(console, config, job)
    verdict = fetch_verdict(job)
    console.print()
    console.print(render_verdict_panel(result, verdict, job))
    maybe_open_report(console, job.report_url, config.open_report)

    if not should_install(console, config, result, verdict):
        return 0 if not config.install_mode else 2
    return run_install(console, config, result)


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if "--" in raw_args:
        split_at = raw_args.index("--")
        wrapper_args = raw_args[:split_at]
        pip_args = raw_args[split_at + 1 :]
    else:
        wrapper_args = raw_args
        pip_args = []
    parser = build_parser()
    args = parser.parse_args(wrapper_args)
    args.pip_args = pip_args
    config = args_to_config(args)
    console = Console()
    try:
        return execute_flow(console, config)
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted.[/]")
        return 130
    except PipGuardError as exc:
        console.print(Panel(str(exc), title="pip-guard error", border_style="red"))
        return 1
