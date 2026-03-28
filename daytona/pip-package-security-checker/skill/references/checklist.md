# Quick Triage

## High-signal files

- `setup.py`
- `setup.cfg`
- `pyproject.toml`
- `MANIFEST.in`
- `*.pth`
- package `__init__.py`
- console entry point modules

## Grep targets

Run targeted searches with `rg -n` over the unpacked `artifacts/` tree:

- `exec\\(|eval\\(|compile\\(`
- `pickle\\.(load|loads)\\(|marshal\\.(load|loads)\\(`
- `subprocess\\.|os\\.system|pty\\.spawn`
- `requests\\.|httpx\\.|urllib\\.request|socket\\.socket`
- `base64\\.(b64decode|urlsafe_b64decode)\\(`
- `ctypes\\.(CDLL|PyDLL|WinDLL)`
- `importlib\\.import_module|__import__\\(`
- `/bin/sh|bash -c|powershell`
- `\\.pth`

## Minimal command set

```sh
uv run python tools/stage_pypi_release.py <package==version>
uv lock --project <resolution_dir>
uv export --project <resolution_dir> --frozen --no-header --no-hashes --no-emit-project --format requirements.txt --output-file <reports/resolved-requirements.txt>
uv run python - <<'PY'
import json, re, urllib.request
from pathlib import Path
pins = []
for line in Path("<reports/resolved-requirements.txt>").read_text().splitlines():
    match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)", line)
    if match:
        name, version = match.groups()
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=20) as resp:
            payload = json.load(resp)
        pins.append({"package": name, "version": version, "vulnerabilities": payload.get("vulnerabilities", [])})
Path("<reports/pypi-vulns.json>").write_text(json.dumps({"packages": pins}, indent=2) + "\n")
PY
uv run bandit -r <artifacts_dir> -f json -o <reports/bandit.json>
uv run detect-secrets scan --all-files <artifacts_dir> > <reports/detect-secrets.json>
uv run cyclonedx-py requirements <reports/resolved-requirements.txt> --of JSON -o <reports/sbom.json>
jq '.packages[] | select(.vulnerabilities | length > 0)' <reports/pypi-vulns.json>
rg -n 'exec\\(|eval\\(|compile\\(|subprocess\\.|os\\.system|urllib\\.request|requests\\.|pickle\\.(load|loads)\\(|marshal\\.(load|loads)\\(|base64\\.(b64decode|urlsafe_b64decode)\\(|ctypes\\.(CDLL|PyDLL|WinDLL)' <artifacts_dir>
find <artifacts_dir> -type f -print0 | xargs -0 file
```

## Review heuristics

- Treat install-time or import-time network access as suspicious unless clearly justified.
- Treat hidden binaries, packed archives, or long encoded blobs as suspicious until explained.
- Distinguish insecure code from malicious code. A vulnerable package is not automatically malicious.
- Favor evidence from the unpacked release artifacts over assumptions from package metadata alone.
