#!/usr/bin/env bash
# Build a .deb from the project. Requires: dpkg-dev, debhelper, dh-python,
# python3-all, python3-setuptools (Debian/Ubuntu:
#   sudo apt install dpkg-dev debhelper dh-python python3-all python3-setuptools).
# Resulting .deb is copied to the repo root.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# Assemble a clean source tree with debian/ at its top level.
work="$(mktemp -d)"
build="$work/cybersuite"
mkdir -p "$build"
cp -r "$root/cybersuite" \
      "$root/pyproject.toml" \
      "$root/README.md" \
      "$root/LICENSE" \
      "$root/requirements.txt" \
      "$root/packaging" \
      "$build/"
cp -r "$here/debian" "$build/debian"
chmod +x "$build/debian/rules"

echo ">> running dpkg-buildpackage"
( cd "$build" && dpkg-buildpackage -us -uc -b )

find "$work" -maxdepth 1 -name 'cybersuite_*.deb' -exec cp -v {} "$root/" \;
echo ">> .deb copied to $root"
