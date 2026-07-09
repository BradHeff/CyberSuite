%global pypi_name cybersuite

Name:           cybersuite
Version:        1.0.0
Release:        1%{?dist}
Summary:        One-click network security auditor (GUI + CLI)

License:        GPL-3.0-or-later
URL:            https://github.com/bheffernan/CyberSuite
Source0:        %{pypi_name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  desktop-file-utils

Requires:       python3
Requires:       python3-tkinter
# Optional: enables the modern themed GUI. The GUI falls back to plain ttk
# without it, so it is a Recommends rather than a hard Requires.
Recommends:     python3-ttkbootstrap

%description
CyberSuite is a zero-dependency, cross-platform network security auditor for a
solo administrator running checks over their own network. It scans this machine
and the local network for common security holes (open/insecure services, weak
TLS, missing firewall, banner-based CVEs, exposed gateway management planes) and
prints concrete recommendations to fix each finding. It has a one-click tkinter
GUI and a headless CLI suitable for scheduled runs.

%prep
%autosetup -n %{pypi_name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files %{pypi_name}

install -Dm0644 packaging/linux/%{name}.desktop \
    %{buildroot}%{_datadir}/applications/%{name}.desktop
install -Dm0644 packaging/linux/%{name}.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/%{name}.svg

desktop-file-validate %{buildroot}%{_datadir}/applications/%{name}.desktop

%check
%pyproject_check_import

%files -f %{pyproject_files}
%license LICENSE
%doc README.md
%{_bindir}/cybersuite
%{_bindir}/cybersuite-gui
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/scalable/apps/%{name}.svg

%changelog
* Thu Jul 09 2026 Brad Heffernan <brad.heffernan83@outlook.com> - 1.0.0-1
- Initial RPM packaging of CyberSuite.
