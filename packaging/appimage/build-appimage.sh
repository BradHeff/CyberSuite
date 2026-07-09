#!/usr/bin/env bash
# Build CyberSuite-<ver>-x86_64.AppImage.
#
# Requirements on the build host: bash, python3, python3-pip, curl (to fetch
# appimagetool if it is not already present). The resulting AppImage still relies
# on the target having python3 + Tk; ttkbootstrap is bundled inside.
#
# IMPORTANT: everything is staged and run in a TEMP dir on an exec-capable
# filesystem (/tmp), NOT in the repo. AppImages need exec bits on AppRun and the
# bundled launchers, which an NTFS/exFAT/fuseblk drive cannot store. Only the
# finished .AppImage is copied back into the repo root for uploading.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
ver="$(python3 -c 'import sys; sys.path.insert(0, "'"$root"'"); import cybersuite; print(cybersuite.__version__)')"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
appdir="$work/AppDir"
mkdir -p "$appdir/usr/lib/cybersuite" \
         "$appdir/usr/bin" \
         "$appdir/usr/share/applications" \
         "$appdir/usr/share/icons/hicolor/scalable/apps"

echo ">> staging application code (in $work)"
cp -r "$root/cybersuite" "$appdir/usr/lib/cybersuite/"
find "$appdir/usr/lib/cybersuite/cybersuite" -name '__pycache__' -type d -prune -exec rm -rf {} +

echo ">> bundling ttkbootstrap (best-effort, for the themed GUI)"
python3 -m pip install --quiet --target "$appdir/usr/lib/cybersuite" "ttkbootstrap>=1.10" \
    || echo "   WARN: could not bundle ttkbootstrap; the AppImage will use the plain-ttk fallback."

echo ">> AppRun and launcher (exec bits set on /tmp, so they survive into the image)"
install -Dm0755 "$here/AppRun" "$appdir/AppRun"
cat > "$appdir/usr/bin/cybersuite" <<'SH'
#!/bin/sh
exec python3 -m cybersuite "$@"
SH
chmod 0755 "$appdir/usr/bin/cybersuite"

echo ">> desktop entry and icon"
cp "$root/packaging/linux/cybersuite.desktop" "$appdir/usr/share/applications/"
cp "$root/packaging/linux/cybersuite.svg"     "$appdir/usr/share/icons/hicolor/scalable/apps/"
# appimagetool expects a .desktop and an icon at the AppDir root.
cp "$root/packaging/linux/cybersuite.desktop" "$appdir/cybersuite.desktop"
cp "$root/packaging/linux/cybersuite.svg"     "$appdir/cybersuite.svg"
cp "$root/packaging/linux/cybersuite.svg"     "$appdir/.DirIcon"

echo ">> locating appimagetool"
# Accept appimagetool from PATH, this dir, or the repo root (any *.AppImage
# name). Because those locations may be on a non-exec drive, copy it into the
# temp workdir and set +x there before running.
src=""
if command -v appimagetool >/dev/null 2>&1; then
    src="$(command -v appimagetool)"
else
    for cand in "$here"/appimagetool*.AppImage "$root"/appimagetool*.AppImage; do
        [ -f "$cand" ] && { src="$cand"; break; }
    done
fi
atool="$work/appimagetool"
if [ -n "$src" ]; then
    echo "   using: $src"
    cp "$src" "$atool"
else
    echo "   downloading appimagetool..."
    curl -fsSL -o "$atool" \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
fi
chmod 0755 "$atool"

echo ">> building AppImage"
# APPIMAGE_EXTRACT_AND_RUN lets appimagetool (itself an AppImage) run without
# FUSE/libfuse2, which is often not configured on Fedora.
tmpout="$work/CyberSuite-${ver}-x86_64.AppImage"
( cd "$work" && ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$atool" "$appdir" "$tmpout" )

out="$root/CyberSuite-${ver}-x86_64.AppImage"
cp "$tmpout" "$out"
echo ">> done: $out"
echo "   (to test it, copy to an exec-capable location first, e.g. ~/ , then run it)"
