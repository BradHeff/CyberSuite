# 🛡 CyberSuite

A **network security auditor** for a solo IT admin running checks over
their **own** network. Built for a Horizon Christian School, 
it scans this machine and your local network for common security
holes and prints **recommendations to fix issues**.

- **Zero dependencies** — pure Python standard library. If you have Python, it runs.
- **Cross-platform** — Linux and Windows (and macOS).
- **One click** — a GUI with a big *Run Security Scan* button and a live, color-coded output window.
- **Actionable** — every issue comes with a severity and a concrete fix.
- **Exportable** — save a self-contained HTML or text report for your records.

> ⚠️ **Authorised use only.** Scan networks and devices you own or are
> explicitly authorised to test. The internal/gateway vulnerability tests are
> hard-limited to private (RFC1918) addresses and your own gateways.

---

## Quick start

### Windows
1. Install [Python 3](https://www.python.org/downloads/) and tick **“Add Python to PATH”**.
2. Double-click **`run.bat`**.

### Linux / macOS
```bash
./run.sh
```
If the GUI won't start, install Tk:
- Debian/Ubuntu: `sudo apt install python3-tk`
- Fedora: `sudo dnf install python3-tkinter`

The launcher falls back to CLI mode automatically if Tk is missing.

---

## What it checks

| Check | What it looks for |
|-------|-------------------|
| **Local host hardening** | OS/patch level, listening ports, SMBv1, RDP exposure, SSH root/password login, world-writable system files, guest account |
| **Host firewall** | Whether Windows Firewall / ufw / firewalld / nftables / iptables is enabled |
| **Network discovery** | Live devices on your subnet(s) — spot rogue/unknown devices |
| **TCP port scan** | Open ports on each live host (connect scan; no exploits) |
| **Service risk audit** | Insecure services: Telnet, FTP, SNMP, exposed databases (Redis/Mongo/SQL), VNC, SMB, etc. |
| **CVE vulnerability scan** | Identifies service versions from banners and matches them to known CVEs (offline database, optional online enrichment) |
| **TLS / certificate audit** | Expired / self-signed certs, certs expiring soon, weak TLS 1.0/1.1 |
| **Internal network & gateway tests** *(opt-in, internal only)* | Router/firewall management-plane weaknesses: Telnet/HTTP admin, default SNMP community strings, open recursive DNS, TR-069, SMB on the gateway |

Findings are graded **Info · Low · Medium · High · Critical**. Anything Medium or
above appears as an **action item** in the report with a fix.

---

## Command-line usage (headless / scheduled)

```bash
python3 -m cybersuite --cli                         # terminal scan of this machine + LAN
python3 -m cybersuite --cli --internal              # include gateway/router tests
python3 -m cybersuite --cli --subnet 192.168.4.0/24 --subnet 10.10.60.0/24 # multiple subnets
python3 -m cybersuite --cli --report scan.html      # write an HTML report
python3 -m cybersuite --cli --online                # enable online CVE lookups (opt-in)
```
Exit code is non-zero if any **High/Critical** issue is found — handy for a
scheduled task or cron job that emails you on failure.

Full options: `python3 -m cybersuite --help`

---

## Notes on accuracy & safety

- The port/service scan is a **TCP connect scan** — it opens a normal connection
  and reads a banner. It sends **no exploit payloads**.
- The CVE scan infers vulnerability from **version banners**. Linux distros often
  *backport* security fixes without changing the version string, so a match may
  be a false positive, always confirm against your actual patch level.
- **Online CVE lookup** is **off by default**. When enabled it sends detected
  product/version strings to the public CIRCL CVE API. Leave it off on
  air-gapped or privacy-sensitive networks.
- Some local checks (pending updates, firewall state) are more complete when run
  **as Administrator / with sudo**, but the tool never requires it.

> ⚠️ **PLEASE NOTE:** Analyze the code base before running any scripts or source based projects as SUDO / Administrator.
>
>*Safe Code Practice To Always Remember, Thanks*

## Project layout

```
CyberSuite/
├─ run.sh / run.bat           # one-click launchers
├─ README.md                  # This document
└─ cybersuite/
   ├─ __main__.py             # GUI + CLI entry point
   ├─ gui.py                  # tkinter one-click interface
   ├─ runner.py               # orchestrates all checks
   ├─ model.py                # Finding / Severity / ScanContext
   ├─ config.py               # port catalog + service risk knowledge base
   ├─ cvedb.py                # offline CVE signatures + version parsing
   ├─ cve_online.py           # optional CIRCL online enrichment
   ├─ scope.py                # internal-only scope guard + gateway discovery
   ├─ netutil.py              # cross-platform network helpers
   ├─ reporting.py            # HTML / text report rendering
   └─ checks/                 
      ├─ base.py              # Base class & shared check module
      ├─ cve_scan.py          # match product/version against CVE knowledge base
      ├─ firewall.py          # check for a present and enabled firewall
      ├─ gateway_audit.py     # gateway vulnerability tests
      ├─ local_host.py        # Hardening checks for host machine
      ├─ network_discovery.py # scan common ports and list connected machines  
      ├─ port_scan.py         # port scan of every live host found by discovery
      ├─ service_audit.py     # Turn open ports into risk findings using the SERVICE_RISKS knowledge base
      └─ tls_audit.py         # Inspect TLS certificates and protocol versions on TLS ports
```
