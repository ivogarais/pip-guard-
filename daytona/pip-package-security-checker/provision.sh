#!/usr/bin/env bash
set -euo pipefail

workspace_dir="${WORKSPACE_DIR:-$HOME/pip-package-security-checker}"
codex_home="${CODEX_HOME:-$HOME/.codex-home}"
skill_dir="$codex_home/skills/pip-package-security-checker"

mkdir -p "$workspace_dir/tools"
mkdir -p "$workspace_dir/jobs"
mkdir -p "$workspace_dir/logs"
mkdir -p "$workspace_dir/runtime"
mkdir -p "$skill_dir/references"
mkdir -p "$HOME/.local/bin"

if [ ! -f "$workspace_dir/pyproject.toml" ]; then
  uv init "$workspace_dir" \
    --name pip-package-security-checker \
    --app \
    --no-package \
    --python 3.14 \
    --no-description \
    --no-readme \
    --vcs none
fi

cd "$workspace_dir"

uv add bandit cyclonedx-bom detect-secrets packaging
uv sync

if ! command -v codex >/dev/null 2>&1; then
  npm install -g @openai/codex
fi

printf 'Workspace: %s\n' "$workspace_dir"
printf 'CODEX_HOME: %s\n' "$codex_home"
printf 'Launcher: %s\n' "$HOME/.local/bin/codex-pip-checker"
printf 'Worker start script: %s\n' "$HOME/.local/bin/start-pip-package-security-checker"
printf 'Next: copy tools/stage_pypi_release.py into %s/tools and install the skill into %s\n' "$workspace_dir" "$skill_dir"
