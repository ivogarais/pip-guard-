#!/usr/bin/env bash
set -euo pipefail

workspace_dir="${WORKSPACE_DIR:-$HOME/pip-package-security-checker}"
runtime_dir="$workspace_dir/runtime"
log_dir="$workspace_dir/logs"
pid_file="$runtime_dir/scan-service.pid"
log_file="$log_dir/scan-service.log"
python_bin="$workspace_dir/.venv/bin/python"

mkdir -p "$runtime_dir" "$log_dir"

if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
  echo "scan service already running with pid $(cat "$pid_file")"
  exit 0
fi

nohup "$python_bin" "$workspace_dir/tools/scan_service.py" --host 0.0.0.0 --port 3001 >>"$log_file" 2>&1 &
echo $! >"$pid_file"
echo "scan service started on port 3001 with pid $(cat "$pid_file")"
