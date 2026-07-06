"""Hardening checks for the machine CyberSuite is running on.

Cross-platform, best-effort, and read-only. Covers listening services, OS
update posture, and a few high-value account/config hygiene checks.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket

from .. import netutil
from ..model import Severity
from .base import Check


class LocalHostAudit(Check):
    name = "localhost"
    title = "Local host hardening"
    description = "Audits the machine running CyberSuite (updates, accounts, listeners)."

    def run(self):
        self.add(
            "System information",
            Severity.INFO,
            detail=f"Host: {socket.gethostname()}\n"
                   f"OS:   {platform.system()} {platform.release()} ({platform.version()})\n"
                   f"User: {getpass.getuser()}\n"
                   f"Arch: {platform.machine()}",
            target=socket.gethostname(),
        )

        if netutil.is_windows():
            self._windows()
        else:
            self._posix()
        return self.findings

    # ------------------------------------------------------------------ Windows
    def _windows(self):
        # Listening ports on this machine.
        rc, out = netutil.run_cmd(["netstat", "-ano", "-p", "TCP"])
        if rc == 0 and out:
            listeners = [ln for ln in out.splitlines() if "LISTENING" in ln]
            self.add("Local listening TCP ports", Severity.INFO,
                     detail="\n".join(listeners[:40]) or "None",
                     recommendation="Close or firewall any listener you do not recognise.")

        # SMBv1 (EternalBlue / WannaCry).
        rc, out = netutil.run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "(Get-SmbServerConfiguration).EnableSMB1Protocol"])
        if rc == 0 and "true" in out.lower():
            self.add("SMBv1 is enabled", Severity.CRITICAL,
                     detail="SMBv1 is the protocol exploited by WannaCry (MS17-010).",
                     recommendation="Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")

        # RDP exposure.
        rc, out = netutil.run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server')"
             ".fDenyTSConnections"])
        if rc == 0 and out.strip() == "0":
            self.add("Remote Desktop (RDP) is enabled", Severity.MEDIUM,
                     detail="RDP is accepting connections on this host.",
                     recommendation="Ensure Network Level Authentication is on, account "
                                    "lockout is configured, and RDP is not reachable from "
                                    "student/guest networks or the internet.")

        # Pending Windows updates (best-effort; may be slow, so keep it light).
        rc, out = netutil.run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "(New-Object -ComObject Microsoft.Update.Session)."
             "CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count"], timeout=25)
        if rc == 0 and out.strip().isdigit():
            n = int(out.strip())
            if n > 0:
                self.add(f"{n} Windows update(s) pending", Severity.HIGH,
                         detail="Missing OS patches are a leading cause of compromise.",
                         recommendation="Apply pending updates and enable automatic updates.")
            else:
                self.add("Windows is up to date", Severity.INFO,
                         detail="No pending updates reported.")

        # Guest account.
        rc, out = netutil.run_cmd(["net", "user", "Guest"])
        if rc == 0 and "active" in out.lower() and "yes" in out.lower():
            self.add("Guest account is active", Severity.MEDIUM,
                     detail="An active Guest account weakens access control.",
                     recommendation="net user Guest /active:no")

    # -------------------------------------------------------------------- POSIX
    def _posix(self):
        # Listening ports.
        rc, out = netutil.run_cmd(["ss", "-tulpn"])
        if rc != 0 or not out:
            rc, out = netutil.run_cmd(["netstat", "-tulpn"])
        if rc == 0 and out:
            listeners = [ln for ln in out.splitlines() if "LISTEN" in ln]
            self.add("Local listening ports", Severity.INFO,
                     detail="\n".join(listeners[:40]) or "None",
                     recommendation="Close or firewall any listener you do not recognise.")

        # Root SSH login.
        sshd = "/etc/ssh/sshd_config"
        if os.path.isfile(sshd):
            try:
                with open(sshd, "r", errors="replace") as fh:
                    cfg = fh.read().lower()
                lines = [l.strip() for l in cfg.splitlines()
                         if l.strip().startswith("permitrootlogin")]
                if any("yes" in l for l in lines):
                    self.add("SSH permits root login", Severity.HIGH,
                             detail=f"{sshd}: PermitRootLogin yes",
                             recommendation="Set 'PermitRootLogin no' and use sudo; restart sshd.")
                if any(l.startswith("passwordauthentication yes") for l in
                       [l.strip() for l in cfg.splitlines()]):
                    self.add("SSH allows password authentication", Severity.MEDIUM,
                             detail=f"{sshd}: PasswordAuthentication yes",
                             recommendation="Prefer key-based auth: set 'PasswordAuthentication no' "
                                            "once keys are deployed, to stop brute-force logins.")
            except OSError:
                pass

        # Pending package updates.
        if os.path.exists("/usr/bin/apt") or os.path.exists("/usr/bin/apt-get"):
            rc, out = netutil.run_cmd(["apt-get", "-s", "upgrade"], timeout=25)
            if rc == 0 and out:
                count = sum(1 for l in out.splitlines() if l.startswith("Inst "))
                if count:
                    self.add(f"{count} package update(s) available (apt)", Severity.HIGH,
                             detail="Missing patches are a leading cause of compromise.",
                             recommendation="sudo apt-get update && sudo apt-get upgrade")
        elif os.path.exists("/usr/bin/dnf"):
            rc, out = netutil.run_cmd(["dnf", "-q", "check-update"], timeout=30)
            # dnf returns 100 when updates are available.
            if rc == 100:
                count = sum(1 for l in out.splitlines() if l and not l.startswith(" "))
                self.add(f"~{count} package update(s) available (dnf)", Severity.HIGH,
                         detail="Missing patches are a leading cause of compromise.",
                         recommendation="sudo dnf upgrade")

        # World-writable check on a couple of sensitive files.
        for path in ("/etc/passwd", "/etc/shadow"):
            try:
                mode = os.stat(path).st_mode
                if mode & 0o002:
                    self.add(f"World-writable {path}", Severity.CRITICAL,
                             detail=f"{path} is writable by any user.",
                             recommendation=f"chmod o-w {path}")
            except OSError:
                pass
