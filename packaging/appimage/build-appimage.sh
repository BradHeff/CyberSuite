#!/usr/bin/env bash
# Build CyberSuite-<ver>-x86_64.AppImage.
#
# Requirements on the build host: bash, python3, python3-pip, curl (to fetch
# appimagetool if it is not already on PATH). The resulting AppImage still relies
# on the target having python3 + Tk; ttkbootstrap is bundled inside.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
ver="$(python3 -c 'import sys; sys.path.insert(0, "'"$root"'"); import cybersuite; print(cybersuite.__version__)')"

appdir="$here/AppDir"
rm -rf "$appdir"
mkdir -p "$appdir/usr/lib/cybersuite" \
         "$appdir/usr/bin" \
         "$appdir/usr/share/applications" \
         "$appdir/usr/share/icons/hicolor/scalable/apps"

echo ">> copying application code"
cp -r "$root/cybersuite" "$appdir/usr/lib/cybersuite/"

echo ">> bundling ttkbootstrap (best-effort, for the themed GUI)"
python3 -m pip install --quiet --target "$appdir/usr/lib/cybersuite" "ttkbootstrap>=1.10" \
    || echo "   WARN: could not bundle ttkbootstrap; the AppImage will use the plain-ttk fallback."

echo ">> writing AppRun and launcher"
install -Dm0755 "$here/AppRun" "$appdir/AppRun"
cat > "$appdir/usr/bin/cybersuite" <<'SH'
#!/bin/sh
exec python3 -m cybersuite "$@"
SH
chmod +x "$appdir/usr/bin/cybersuite"

echo ">> installing desktop entry and icon"
cp "$root/packaging/linux/cybersuite.desktop" "$appdir/usr/share/applications/"
cp "$root/packaging/linux/cybersuite.svg"     "$appdir/usr/share/icons/hicolor/scalable/apps/"
# appimagetool expects a .desktop and an icon at the AppDir root.
cp "$root/packaging/linux/cybersuite.desktop" "$appdir/cybersuite.desktop"
cp "$root/packaging/linux/cybersuite.svg"     "$appdir/cybersuite.svg"
cp "$root/packaging/linux/cybersuite.svg"     "$appdir/.DirIcon"

echo ">> locating appimagetool"
tool="$here/appimagetool-x86_64.AppImage"
if command -v appimagetool >/dev/null 2>&1; then
    ATOOL="appimagetool"
else
    if [ ! -x "$tool" ]; then
        echo "   downloading appimagetool..."
        curl -fsSL -o "$tool" \
            "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
        chmod +x "$tool"
    fi
    ATOOL="$tool"
fi

echo ">> building AppImage"
out="$root/CyberSuite-${ver}-x86_64.AppImage"
ARCH=x86_64 "$ATOOL" "$appdir" "$out"
echo ">> done: $out"
