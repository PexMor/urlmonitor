#!/usr/bin/env bash
set -euo pipefail

# Run PyInstaller via uv from the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/.."
cd "${PROJECT_ROOT}"

uv run pyinstaller -F urlmonitor.py


