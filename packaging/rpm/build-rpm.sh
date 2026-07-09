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
# Plain rpmbuild only CHECKS build deps (it won't install the dynamic ones that
# %pyproject_buildrequires generates, e.g. setuptools>=61). If it fails on
# "Failed build dependencies", install them first with:
#     sudo dnf builddep packaging/rpm/cybersuite.spec
if ! rpmbuild --define "_topdir $top" -ba "$top/SPECS/cybersuite.spec"; then
    echo >&2
    echo "ERROR: rpmbuild failed. If it was 'Failed build dependencies', run:" >&2
    echo "    sudo dnf builddep $here/cybersuite.spec" >&2
    echo "  (or: sudo dnf install python3-setuptools python3-wheel python3-pip)" >&2
    echo "then re-run 'make rpm'." >&2
    exit 1
fi

find "$top/RPMS" "$top/SRPMS" -name '*.rpm' -exec cp -v {} "$root/" \;
echo ">> RPM(s) copied to $root"
