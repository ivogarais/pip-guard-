---
name: pip-package-security-checker
description: Use when Codex is asked to inspect a pip or PyPI package for malicious behavior, suspicious installer logic, supply-chain risk, or known vulnerabilities inside the dedicated Daytona sandbox. This skill is for the pip-package-security-checker sandbox and tells Codex how to stage a pinned release, run the local uv-based security toolchain, inspect suspicious files, and return an evidence-based risk summary.
---

# Pip Package Security Checker

Use this skill only inside the dedicated Daytona sandbox named `pip-package-security-checker`.

## Environment

- `CODEX_HOME` must stay pointed at persistent sandbox storage.
- Work from `/home/daytona/pip-package-security-checker`.
- Use the repo-local toolchain via `uv run ...`. Do not install target packages into the tool environment.
- Stage the target release with `uv run python tools/stage_pypi_release.py <package==version>`.

## Workflow

1. Resolve the target to an exact version before analysis. If the incoming request is not pinned, normalize it first and analyze the exact resolved release.
2. Stage the release artifacts. This writes a run directory under `runs/` containing:
   - downloaded wheel and/or sdist
   - unpacked source trees under `artifacts/`
   - a `requirements.txt` containing only the pinned target
   - `reports/stage.json` with the resolved paths
3. Resolve transitive dependencies in a throwaway project, then run the standard toolchain:
   - `uv lock --project <resolution_dir>`
   - `uv export --project <resolution_dir> --frozen --no-header --no-hashes --no-emit-project --format requirements.txt --output-file <reports/resolved-requirements.txt>`
   - Query PyPI release JSON for each exact dependency from `<reports/resolved-requirements.txt>` and write the combined results to `<reports/pypi-vulns.json>`
   - `uv run bandit -r <artifacts_dir> -f json -o <reports/bandit.json>`
   - `uv run detect-secrets scan --all-files <artifacts_dir> > <reports/detect-secrets.json>`
   - `uv run cyclonedx-py requirements <reports/resolved-requirements.txt> --of JSON -o <reports/sbom.json>`
4. Manually inspect for package abuse patterns with terminal tools:
   - `rg` for installer hooks, subprocess use, network calls, `exec`, `eval`, `pickle`, `marshal`, `base64`, `ctypes`, credential access, and shell execution.
   - `find ... -type f | xargs file` to spot binaries, archives, and compiled payloads.
   - `strings -a` on suspicious binaries or wheels when native artifacts are present.
   - `jq` to inspect the JSON reports instead of reading them raw.
5. Prioritize build/install surfaces:
   - `setup.py`
   - `setup.cfg`
   - `pyproject.toml`
   - package `__init__` or import side effects
   - console entry points and install hooks
6. Separate two classes of findings in the final answer:
   - known advisories or CVEs from the resolved dependency set
   - suspicious behavior that may indicate malicious or risky package design

## Output Standard

- Cite the exact file paths and commands used.
- Call out whether the suspicious behavior is proven, plausible, or just worth review.
- State clearly if a package appears benign but still has known vulnerabilities.
- If the tool results are noisy, say so and explain what you manually validated.

## Reference

Read `references/checklist.md` when you need the quick triage checklist and high-signal grep targets.
Read `references/report-template.md` when you need the structured verdict format consumed by the HTML report renderer.
