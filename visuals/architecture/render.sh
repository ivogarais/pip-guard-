#!/usr/bin/env bash
set -euo pipefail

scene="${1:-PipGuardArchitectureAnimation}"
quality="${2:-h}"

uv run manim -q"${quality}" visuals/architecture/pip_guard_architecture.py "${scene}"
