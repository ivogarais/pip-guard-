#!/usr/bin/env bash
set -euo pipefail

export CODEX_HOME="${CODEX_HOME:-$HOME/.codex-home}"
export CODEX_SCAN_MODEL="${CODEX_SCAN_MODEL:-gpt-5.4-mini}"
exec codex -m "$CODEX_SCAN_MODEL" --dangerously-bypass-approvals-and-sandbox -C /home/daytona/pip-package-security-checker "$@"
