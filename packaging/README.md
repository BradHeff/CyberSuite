# Packaging CyberSuite

CyberSuite is a pure-Python (standard-library) application, so every package is
architecture-independent (`noarch` / `all`). The only runtime requirements are
**Python 3** and **Tk** (`python3-tkinter` / `python3-tk`). `ttkbootstrap` is
optional and only enables the modern themed GUI — without it the GUI falls back
to plain `ttk`.

All build scripts drop their output in the **repository root**.

| Target    | Command                            | Build host needs |
|-----------|------------------------------------|------------------|
| Source    | `make sdist`                       | `python3-build` (`pip install build`) |
| RPM (DNF) | `make rpm`                         | Fedora/RHEL: `rpm-build python3-devel pyproject-rpm-macros python3-build` |
| DEB       | `make deb`                         | just `dpkg` (`dpkg-deb`) — works on Fedora too |
| AppImage  | `make appimage`                    | `python3 python3-pip curl` (fetches `appimagetool`) |

## RPM (DNF / Fedora, RHEL, openSUSE)

```bash
sudo dnf install rpm-build python3-devel pyproject-rpm-macros python3-build
# rpmbuild does not auto-install the dynamically-generated build deps
# (setuptools>=61, wheel, ...). Let dnf resolve them from the spec:
sudo dnf builddep packaging/rpm/cybersuite.spec
make rpm            # -> ./cybersuite-1.0.0-1.<dist>.noarch.rpm
sudo dnf install ./cybersuite-1.0.0-1.*.noarch.rpm
```

Spec file: `packaging/rpm/cybersuite.spec`. It uses the modern
`pyproject-rpm-macros`, pulls in `python3-tkinter` as a hard dependency, and
recommends `python3-ttkbootstrap`. It also installs the `.desktop` entry and the
scalable icon.

## DEB (Debian, Ubuntu, Mint — and buildable from Fedora)

Because CyberSuite is pure Python, the `.deb` is assembled directly with
`dpkg-deb` — no `debhelper`, `dh-python`, or `pybuild` required. This means you
can build the `.deb` **on Fedora** (where the Debian toolchain isn't available),
needing only the `dpkg` package:

```bash
sudo dnf install dpkg        # Fedora (provides dpkg-deb)
# or: sudo apt install dpkg  # Debian/Ubuntu
make deb                     # -> ./cybersuite_1.0.0_all.deb
```

Install the result on a Debian/Ubuntu machine:

```bash
sudo apt install ./cybersuite_1.0.0_all.deb
```

The builder (`packaging/deb/build-deb.sh`) stages the package into
`/usr/lib/python3/dist-packages/`, adds `/usr/bin/cybersuite(-gui)` launchers,
the desktop entry and icon, and a control file declaring `Depends: python3
(>= 3.9), python3-tk` and `Recommends: python3-ttkbootstrap`. A `postinst`
byte-compiles the modules on the target.

### Idiomatic source-package build (on a real Debian/Ubuntu host)

If you are on Debian/Ubuntu and prefer the standard toolchain, the `debian/`
metadata is also provided (native package, built with `pybuild`):

```bash
sudo apt install dpkg-dev debhelper dh-python python3-all python3-setuptools
# from a source tree that has debian/ at its top level:
dpkg-buildpackage -us -uc -b
```

## AppImage (portable, distro-agnostic)

```bash
make appimage       # -> ./CyberSuite-1.0.0-x86_64.AppImage
chmod +x CyberSuite-1.0.0-x86_64.AppImage
./CyberSuite-1.0.0-x86_64.AppImage
```

The AppImage bundles the application **and** `ttkbootstrap`, so the themed GUI
works out of the box. Because CPython's `tkinter` cannot be pip-bundled, the
target machine must still have `python3` and Tk installed; if Tk is missing the
AppImage automatically falls back to CLI mode. Files: `packaging/appimage/`.

## What gets installed (RPM/DEB)

- The `cybersuite` Python package into the system `site-packages`.
- `/usr/bin/cybersuite` and `/usr/bin/cybersuite-gui` launchers.
- `/usr/share/applications/cybersuite.desktop` (menu entry).
- `/usr/share/icons/hicolor/scalable/apps/cybersuite.svg` (icon).

After install, launch from your application menu or run `cybersuite` (GUI) /
`cybersuite --cli` (terminal).
