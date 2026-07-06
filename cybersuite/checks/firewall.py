"""Check that a host firewall is present and enabled (Windows & Linux)."""

from __future__ import annotations

from .. import netutil
from ..model import Severity
from .base import Check


class FirewallAudit(Check):
    name = "firewall"
    title = "Host firewall status"
    description = "Verifies a local firewall is enabled on this machine."

    def run(self):
        if netutil.is_windows():
            self._windows()
        else:
            self._posix()
        return self.findings

    def _windows(self):
        rc, out = netutil.run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if rc != 0 or not out:
            self.add("Could not read firewall state", Severity.LOW,
                     detail="netsh advfirewall did not return data (admin rights may be needed).")
            return
        states = [l.strip() for l in out.splitlines() if l.strip().lower().startswith("state")]
        off = [s for s in states if "off" in s.lower()]
        if off:
            self.add("Windows Firewall is OFF for one or more profiles", Severity.HIGH,
                     detail="\n".join(states),
                     recommendation="netsh advfirewall set allprofiles state on")
        else:
            self.add("Windows Firewall is enabled", Severity.INFO,
                     detail="\n".join(states) or "All profiles ON.")

    def _posix(self):
        # ufw
        rc, out = netutil.run_cmd(["ufw", "status"])
        if rc == 0 and out:
            if "inactive" in out.lower():
                self.add("ufw firewall is inactive", Severity.HIGH,
                         detail=out.strip()[:200],
                         recommendation="sudo ufw enable  (set default-deny inbound first).")
            else:
                self.add("ufw firewall is active", Severity.INFO, detail=out.strip()[:400])
            return

        # firewalld
        rc, out = netutil.run_cmd(["firewall-cmd", "--state"])
        if rc == 0 and "running" in out.lower():
            self.add("firewalld is running", Severity.INFO, detail=out.strip())
            return

        # nftables / iptables fallback: any rules at all?
        rc, out = netutil.run_cmd(["nft", "list", "ruleset"])
        if rc == 0 and out.strip():
            self.add("nftables ruleset present", Severity.INFO,
                     detail="A firewall ruleset is loaded via nftables.")
            return
        rc, out = netutil.run_cmd(["iptables", "-S"])
        if rc == 0 and out:
            has_rules = any(l.startswith("-A") for l in out.splitlines())
            if has_rules:
                self.add("iptables rules present", Severity.INFO,
                         detail="Custom iptables rules are loaded.")
            else:
                self.add("No host firewall rules detected", Severity.HIGH,
                         detail="iptables has only default policies and no rules; ufw/firewalld "
                                "appear absent.",
                         recommendation="Enable ufw or firewalld and default-deny inbound.")
            return

        self.add("No host firewall detected", Severity.MEDIUM,
                 detail="Could not find ufw, firewalld, nftables, or iptables rules.",
                 recommendation="Install and enable a host firewall (ufw is simplest on Debian/Ubuntu).")
