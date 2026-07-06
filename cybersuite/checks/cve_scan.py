"""Version-based CVE vulnerability scan.

For each open port, grab a service banner, identify the product + version, and
match it against the offline CVE knowledge base (and, if enabled, the online
CIRCL enrichment). Produces one finding per matched CVE with remediation.

This is a *version-inference* scanner: it does not exploit anything. A match
means "this version is known to be affected" — always confirm against your
actual build/patch level, since backported distro fixes can make a banner look
vulnerable when it is not.
"""

from __future__ import annotations

from .. import cve_online, cvedb, netutil
from ..config import TLS_PORTS
from ..model import Severity
from .base import Check

# Ports where an HTTP GET tends to yield a useful Server: header.
_HTTP_PORTS = {80, 8000, 8080, 3000, 9000}
_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: scan\r\nUser-Agent: CyberSuite\r\n\r\n"


class CveScan(Check):
    name = "cve"
    title = "CVE vulnerability scan"
    description = "Identifies service versions and matches them to known CVEs."

    def _banner_for(self, ip: str, port: int) -> str:
        send = _HTTP_PROBE if port in _HTTP_PORTS else None
        banner = netutil.grab_banner(ip, port, self.ctx.tcp_timeout, send=send)
        return banner

    def run(self):
        open_ports: dict[str, list[int]] = self.shared.get("open_ports", {})
        online = self.ctx.intrusive and self.shared.get("cve_online", False)

        if not open_ports:
            self.add("No services to check for CVEs", Severity.INFO,
                     detail="No open ports were found by the port scan.")
            return self.findings

        online_ok = cve_online.available() if online else False
        if online and not online_ok:
            self.add("Online CVE enrichment unavailable", Severity.INFO,
                     detail="Could not reach the CIRCL CVE API; using the offline database only.")

        identified = 0
        matched = 0
        for ip, ports in open_ports.items():
            for port in ports:
                if self.cancelled():
                    return self.findings
                # Skip pure-TLS ports for banner grabbing (handled by TLS audit);
                # still probe 8443 lightly via plain read in case of redirect banners.
                if port in TLS_PORTS and port not in _HTTP_PORTS:
                    continue
                banner = self._banner_for(ip, port)
                if not banner:
                    continue
                products = cvedb.identify(banner)
                if not products:
                    continue
                identified += 1
                for product, version in products:
                    tgt = f"{ip}:{port}"
                    self.log(f"{tgt} -> {product} {version}")

                    for sig in cvedb.match_cves(product, version):
                        matched += 1
                        self.add(
                            f"{sig['cve']} — {product} {version} on {tgt}",
                            sig["severity"],
                            detail=f"{sig['summary']}\nDetected banner: {banner[:140]}",
                            recommendation=sig["fix"],
                            target=tgt,
                        )

                    if online_ok:
                        for hit in cve_online.lookup(product, version):
                            if not hit.get("cve"):
                                continue
                            matched += 1
                            cvss = f" (CVSS {hit['cvss']})" if hit.get("cvss") else ""
                            self.add(
                                f"{hit['cve']} — {product} {version} on {tgt}{cvss}",
                                Severity.MEDIUM,
                                detail=f"{hit['summary']}\n(Source: CIRCL online CVE database)",
                                recommendation=f"Review {hit['cve']} and update {product} to a fixed release.",
                                target=tgt,
                            )

        if identified == 0:
            self.add("No service versions could be identified", Severity.INFO,
                     detail="Banners did not reveal recognisable product/version strings. "
                            "Version-hiding is good practice, but confirm patch levels manually.")
        elif matched == 0:
            self.add("No known CVEs matched detected versions", Severity.LOW,
                     detail=f"Identified {identified} service banner(s); none matched a known-vulnerable "
                            "version in the database. Keep systems patched and re-scan periodically.")
        return self.findings
