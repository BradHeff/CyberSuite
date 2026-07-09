#!/usr/bin/env bash
# Build an RPM from the project. Requires: rpmbuild, python3-build,
# pyproject-rpm-macros (Fedora: sudo dnf install rpm-build python3-devel
# pyproject-rpm-macros python3-build). Resulting .rpm is copied to the repo root.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
ver="$(python3 -c 'import sys; sys.path.insert(0, "'"$root"'"); import cybersuite; print(cybersuite.__version__)')"

cd "$root"
echo ">> building sdist"
python3 -m build --sdist

top="$(mktemp -d)"
mkdir -p "$top"/{SOURCES,SPECS,BUILD,BUILDROOT,RPMS,SRPMS}
cp "dist/cybersuite-${ver}.tar.gz" "$top/SOURCES/"
cp "$here/cybersuite.spec" "$top/SPECS/"

echo ">> running rpmbuild"
rpmbuild --define "_topdir $top" -ba "$top/SPECS/cybersuite.spec"

find "$top/RPMS" "$top/SRPMS" -name '*.rpm' -exec cp -v {} "$root/" \;
echo ">> RPM(s) copied to $root"
