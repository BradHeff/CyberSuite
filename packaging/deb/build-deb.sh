#!/usr/bin/env bash
# Build a .deb WITHOUT the Debian toolchain (no debhelper / dh-python / pybuild).
#
# CyberSuite is a pure-Python package, so the .deb is just a file tree plus a
# control file assembled with dpkg-deb. This works anywhere dpkg-deb exists,
# including Fedora:  sudo dnf install dpkg   (dpkg-deb ships in that package).
#
# The finished .deb is copied to the repository root.
#
# For an idiomatic source-package build ON a Debian/Ubuntu host, use the
# packaging in debian/ instead:  (cd <srctree> && dpkg-buildpackage -us -uc -b)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "ERROR: dpkg-deb not found." >&2
    echo "  Fedora:        sudo dnf install dpkg" >&2
    echo "  Debian/Ubuntu: sudo apt install dpkg" >&2
    exit 1
fi

ver="$(python3 -c 'import sys; sys.path.insert(0, "'"$root"'"); import cybersuite; print(cybersuite.__version__)')"
arch="all"
pkgdir="$(mktemp -d)/cybersuite_${ver}_${arch}"

# --- Debian install layout -------------------------------------------------
# Pure-Python code lives in dist-packages (on the system python3 path in Debian).
sitedir="$pkgdir/usr/lib/python3/dist-packages"
mkdir -p "$pkgdir/DEBIAN" \
         "$sitedir" \
         "$pkgdir/usr/bin" \
         "$pkgdir/usr/share/applications" \
         "$pkgdir/usr/share/icons/hicolor/scalable/apps" \
         "$pkgdir/usr/share/doc/cybersuite"

echo ">> staging application code"
cp -r "$root/cybersuite" "$sitedir/"
find "$sitedir/cybersuite" -name '__pycache__' -type d -prune -exec rm -rf {} +

echo ">> launchers"
cat > "$pkgdir/usr/bin/cybersuite" <<'SH'
#!/bin/sh
exec python3 -m cybersuite "$@"
SH
chmod 0755 "$pkgdir/usr/bin/cybersuite"
cp "$pkgdir/usr/bin/cybersuite" "$pkgdir/usr/bin/cybersuite-gui"

echo ">> desktop entry, icon, docs"
install -Dm0644 "$root/packaging/linux/cybersuite.desktop" "$pkgdir/usr/share/applications/cybersuite.desktop"
install -Dm0644 "$root/packaging/linux/cybersuite.svg"     "$pkgdir/usr/share/icons/hicolor/scalable/apps/cybersuite.svg"
install -Dm0644 "$root/README.md"                          "$pkgdir/usr/share/doc/cybersuite/README.md"
install -Dm0644 "$here/debian/copyright"                   "$pkgdir/usr/share/doc/cybersuite/copyright"

installed_size="$(du -ks "$pkgdir/usr" | cut -f1)"

echo ">> control file"
cat > "$pkgdir/DEBIAN/control" <<EOF
Package: cybersuite
Version: ${ver}
Section: admin
Priority: optional
Architecture: ${arch}
Maintainer: Brad Heffernan <brad.heffernan83@outlook.com>
Installed-Size: ${installed_size}
Depends: python3 (>= 3.9), python3-tk
Recommends: python3-ttkbootstrap
Homepage: https://github.com/bheffernan/CyberSuite
Description: one-click network security auditor (GUI + CLI)
 CyberSuite is a zero-dependency, cross-platform network security auditor for a
 solo administrator running checks over their own network. It scans this machine
 and the local network for common security holes and prints concrete
 recommendations to fix each finding.
 .
 Checks include local host hardening, host firewall status, network discovery,
 TCP port scanning, insecure-service auditing, banner-based CVE matching, TLS
 certificate/protocol auditing, and opt-in internal gateway/router tests
 (hard-limited to private RFC1918 addresses).
 .
 It ships a one-click tkinter GUI and a headless CLI for scheduled runs.
EOF

# Best-effort byte-compilation and desktop DB refresh on the target (Debian tools).
cat > "$pkgdir/DEBIAN/postinst" <<'SH'
#!/bin/sh
set -e
if command -v py3compile >/dev/null 2>&1; then
    py3compile -p cybersuite || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
exit 0
SH
cat > "$pkgdir/DEBIAN/prerm" <<'SH'
#!/bin/sh
set -e
if command -v py3clean >/dev/null 2>&1; then
    py3clean -p cybersuite || true
fi
exit 0
SH
chmod 0755 "$pkgdir/DEBIAN/postinst" "$pkgdir/DEBIAN/prerm"

echo ">> building package"
out="$root/cybersuite_${ver}_${arch}.deb"
dpkg-deb --root-owner-group --build "$pkgdir" "$out"

echo ">> contents:"
dpkg-deb --contents "$out" | awk '{print "   " $6}'
echo ">> done: $out"
command -v lintian >/dev/null 2>&1 && { echo ">> lintian:"; lintian "$out" || true; }
