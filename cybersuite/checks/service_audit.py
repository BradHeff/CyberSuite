"""Turn open ports into risk findings using the SERVICE_RISKS knowledge base.

Where cheap and safe, grabs a service banner to sharpen the finding (e.g. an
unauthenticated Redis, or an FTP server that advertises anonymous login).
"""

from __future__ import annotations

from .. import netutil
from ..config import EXPECTED_OK, SERVICE_RISKS
from ..model import Severity
from .base import Check


class ServiceAudit(Check):
    name = "services"
    title = "Service risk audit"
    description = "Flags risky/insecure services on open ports and how to fix them."

    def _probe_redis(self, ip: str) -> bool | None:
        """Return True if Redis answers PING without auth (open), False if auth
        required, None if unknown."""
        resp = netutil.grab_banner(ip, 6379, self.ctx.tcp_timeout, send=b"PING\r\n")
        if not resp:
            return None
        if "PONG" in resp.upper():
            return True
        if "NOAUTH" in resp.upper() or "AUTH" in resp.upper():
            return False
        return None

    def _probe_ftp(self, ip: str) -> str:
        return netutil.grab_banner(ip, 21, self.ctx.tcp_timeout)

    def run(self):
        open_ports: dict[str, list[int]] = self.shared.get("open_ports", {})
        my_ips = self.shared.get("my_ips", set())

        if not open_ports:
            self.add("No services to audit", Severity.INFO,
                     detail="No open ports were found by the port scan.")
            return self.findings

        risky_count = 0
        for ip, ports in open_ports.items():
            where = f"{ip}{' (this machine)' if ip in my_ips else ''}"
            for port in ports:
                if self.cancelled():
                    return self.findings
                risk = SERVICE_RISKS.get(port)
                if not risk:
                    if port in EXPECTED_OK:
                        self.add(
                            f"{EXPECTED_OK[port]} open on {ip}:{port}",
                            Severity.INFO,
                            detail="Common service — verify it is patched and access-controlled.",
                            target=f"{ip}:{port}",
                        )
                    continue

                severity: Severity = risk["severity"]
                detail = risk["why"]
                fix = risk["fix"]

                # Sharpen a few high-value cases with a safe banner probe.
                if port == 6379:
                    state = self._probe_redis(ip)
                    if state is True:
                        severity = Severity.CRITICAL
                        detail += "\nCONFIRMED: server answered PING with no authentication."
                elif port == 21:
                    banner = self._probe_ftp(ip)
                    if banner:
                        detail += f"\nBanner: {banner[:120]}"
                elif port in (22, 23, 25):
                    banner = netutil.grab_banner(ip, port, self.ctx.tcp_timeout)
                    if banner:
                        detail += f"\nBanner: {banner[:120]}"

                risky_count += 1
                self.add(
                    f"{risk['name']} exposed on {ip}:{port}",
                    severity,
                    detail=f"{where}\n{detail}",
                    recommendation=fix,
                    target=f"{ip}:{port}",
                )

        if risky_count == 0:
            self.add("No risky services detected", Severity.LOW,
                     detail="Open ports mapped only to expected/encrypted services.")
        return self.findings
