# CyberSuite build targets.
#
#   make sdist      -> dist/cybersuite-<ver>.tar.gz (+ wheel)
#   make rpm        -> .rpm  (Fedora/RHEL; needs rpm-build + pyproject-rpm-macros)
#   make deb        -> .deb  (Debian/Ubuntu; needs debhelper + dh-python)
#   make appimage   -> CyberSuite-<ver>-x86_64.AppImage
#   make install    -> pip install into the current environment
#   make clean

VERSION := $(shell python3 -c 'import cybersuite; print(cybersuite.__version__)')

.PHONY: all sdist wheel rpm deb appimage install clean

all: sdist

sdist:
	python3 -m build

wheel:
	python3 -m build --wheel

rpm:
	packaging/rpm/build-rpm.sh

deb:
	packaging/deb/build-deb.sh

appimage:
	packaging/appimage/build-appimage.sh

install:
	python3 -m pip install '.[gui]'

clean:
	rm -rf build dist *.egg-info cybersuite.egg-info \
	       packaging/appimage/AppDir packaging/appimage/appimagetool-*.AppImage \
	       *.rpm *.deb *.AppImage
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
