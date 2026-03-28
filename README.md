# pip-guard

Scan a Python package in a dedicated Daytona sandbox before installing it locally.

## Flow

`pip-guard install <package>` does this:

1. Starts the `pip-package-security-checker` Daytona sandbox if needed.
2. Ensures the sandbox scan service is running.
3. Sends the package request to the sandbox.
4. Lets the sandbox resolve the exact version, run the scanners, and have Codex produce the verdict.
5. Shows a Rich terminal UI with the major scan stages.
6. Prints a summary and the clickable HTML report URL.
7. Installs the exact scanned version only if the verdict allows it, or if you explicitly accept a warning.

## Usage

Scan without installing:

```sh
uv run pip-guard scan requests
```

Scan and install:

```sh
uv run pip-guard install requests
```

Install into a specific interpreter:

```sh
uv run pip-guard install requests --python /path/to/python
```

Pass extra pip arguments after `--`:

```sh
uv run pip-guard install requests -- --index-url https://pypi.org/simple
```

Auto-accept warning-level installs:

```sh
uv run pip-guard install requests --yes
```

Override a blocked verdict:

```sh
uv run pip-guard install requests --force
```

Open the HTML report automatically:

```sh
uv run pip-guard install requests --open-report
```

## Defaults

- Sandbox name: `pip-package-security-checker`
- Daytona API URL: `https://app.daytona.io/api`
- Scan service start command: `/home/daytona/.local/bin/start-pip-package-security-checker`
- Install target: the Python interpreter running `pip-guard`, unless `--python` is supplied
- Installer backend: `auto` by default. `pip-guard` tries `python -m pip`, bootstraps `pip` with `ensurepip` if needed, then falls back to `uv pip` only as a last resort.

You can override the defaults with:

- `--sandbox`
- `--daytona-api-url`
- `--service-start`
- `--python`
- `--installer`
- `PIP_GUARD_SANDBOX`
- `PIP_GUARD_DAYTONA_API_URL`
- `PIP_GUARD_DAYTONA_BIN`

## Decision Handling

- `allow`: install proceeds automatically
- `warn`: `pip-guard` asks whether to continue
- `block`: install is refused unless you pass `--force`

The wrapper installs the exact resolved version that the sandbox scanned, not just the loose package name you typed.

## Architecture Report

A short technical architecture report for the runtime flow lives under [visuals/architecture](/Users/ivogarais/pip-guard-/visuals/architecture).

Primary artifact:

- [pip-guard-architecture-report.html](/Users/ivogarais/pip-guard-/visuals/architecture/output/pip-guard-architecture-report.html)

Optional supporting visuals still live under [visuals/architecture](/Users/ivogarais/pip-guard-/visuals/architecture), but the report above is the main architecture document.

To edit or rerender the optional visuals:

```sh
uv sync --extra visuals
./visuals/architecture/render.sh PipGuardArchitectureAnimation h
```
