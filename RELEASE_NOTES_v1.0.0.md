# CyberSuite v1.0.0

**One-click network security auditor for your own machine and LAN.** CyberSuite
scans this computer and your local network for common security holes and prints
a concrete fix for every issue it finds — no agents, no cloud, no dependencies
beyond Python itself.

> ⚠️ **Authorised use only.** Scan networks and devices you own or are explicitly
> authorised to test. The internal/gateway vulnerability tests are hard-limited
> to private (RFC1918) addresses and your own gateways; public addresses are
> refused automatically.

---

## Highlights

- **Zero dependencies** — pure Python standard library. If you have Python 3, it runs.
- **Cross-platform** — Linux, Windows, and macOS.
- **One click** — a GUI with a big *Run Security Scan* button and a live, colour-coded log.
- **Summary at a glance** — on completion, a *Scan Complete — N Issues Found*
  window lists every action item with its fix.
- **Actionable** — every finding carries a severity (Info · Low · Medium · High ·
  Critical) and a specific remediation step.
- **Exportable** — save a self-contained HTML or text report for your records.
- **Scriptable** — a headless CLI with a non-zero exit code on High/Critical
  findings, ideal for scheduled runs.

## What it checks

| Check | Looks for |
|-------|-----------|
| Local host hardening | OS/patch level, listening ports, SMBv1, RDP exposure, SSH root/password login, world-writable system files, guest account |
| Host firewall | Whether Windows Firewall / ufw / firewalld / nftables / iptables is enabled |
| Network discovery | Live devices on your subnet(s) — spot rogue/unknown hosts |
| TCP port scan | Open ports on each live host (connect scan; no exploit payloads) |
| Service risk audit | Insecure services: Telnet, FTP, SNMP, exposed databases (Redis/Mongo/SQL), VNC, SMB, etc. |
| CVE vulnerability scan | Identifies service versions from banners and matches known CVEs (offline DB, optional online enrichment) |
| TLS / certificate audit | Expired / self-signed / soon-to-expire certs, weak TLS 1.0/1.1 |
| Internal & gateway tests *(opt-in, internal only)* | Router/firewall weaknesses: Telnet/HTTP admin, default SNMP community strings, open recursive DNS, TR-069, SMB on the gateway |

---

## Downloads & installation

### AppImage (any Linux distro)
```bash
chmod +x CyberSuite-1.0.0-x86_64.AppImage
./CyberSuite-1.0.0-x86_64.AppImage
```
Bundles `ttkbootstrap` for the themed GUI. Requires `python3` + Tk on the host;
falls back to CLI automatically if Tk is missing.

### Fedora / RHEL / openSUSE (RPM)
```bash
sudo dnf install ./cybersuite-1.0.0-1.*.noarch.rpm
cybersuite
```

### Debian / Ubuntu / Mint (DEB)
```bash
sudo apt install ./cybersuite_1.0.0_all.deb
cybersuite
```

### From source (no install)
```bash
git clone https://github.com/BradHeff/CyberSuite
cd CyberSuite
./run.sh            # Linux/macOS   (run.bat on Windows)
```

## Requirements

- **Python 3.9+**
- **Tk** for the GUI — `python3-tkinter` (Fedora) / `python3-tk` (Debian/Ubuntu).
  Without it, the tool runs in CLI mode.
- **ttkbootstrap** *(optional)* — enables the modern themed GUI; the GUI falls
  back to plain `ttk` (same palette) without it.

## Command-line usage

```bash
cybersuite --cli                         # terminal scan of this machine + LAN
cybersuite --cli --internal              # include gateway/router tests
cybersuite --cli --subnet 192.168.4.0/24 --subnet 10.10.60.0/24
cybersuite --cli --report scan.html      # write an HTML report
cybersuite --cli --online                # enable online CVE lookups (opt-in)
```
Exit code is non-zero if any **High/Critical** issue is found — handy for cron.

## Notes & known limitations

- The port/service scan is a **TCP connect scan** — it opens a normal connection
  and reads a banner. It sends **no exploit payloads**.
- The CVE scan infers vulnerability from **version banners**. Linux distros often
  *backport* fixes without changing the version string, so a match may be a false
  positive — always confirm against your actual patch level.
- **Online CVE lookup is off by default.** When enabled it sends detected
  product/version strings to the public CIRCL CVE API. Leave it off on air-gapped
  or privacy-sensitive networks.
- Some local checks (pending updates, firewall state) are more complete when run
  as Administrator / with sudo, but the tool never requires it. Review any code
  before running a security tool with elevated privileges.
- The AppImage bundles `ttkbootstrap` but not Python/Tk (CPython's tkinter cannot
  be bundled) — the host still needs `python3` + Tk. Running any AppImage may
  require FUSE, or use `--appimage-extract-and-run`.

---

*First public release. Built for a solo IT administrator auditing their own
school network. Licensed under GPL-3.0-or-later.*
