#!/usr/bin/env bash
# CyberSuite launcher for Linux/macOS.
# run: ./run.sh
set -e
cd "$(dirname "$0")"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
command -v "$PY" >/dev/null 2>&1 || { echo "Python 3 is required."; exit 1; }

# Warn early if tkinter is missing.
if ! "$PY" -c "import tkinter" >/dev/null 2>&1; then
  echo "NOTE: tkinter is not installed, so the GUI cannot start."
  echo "  Debian/Ubuntu: sudo apt install python3-tk"
  echo "  Fedora:        sudo dnf install python3-tkinter"
  echo "Falling back to CLI mode..."
  exec "$PY" -m cybersuite --cli "$@"
fi

exec "$PY" -m cybersuite "$@"
