"""Threaded TCP-connect port scan of every live host found by discovery.

Writes shared['open_ports'] = { ip: [port, ...] } for the service/TLS audits.
This is a connect() scan only — it never sends exploit payloads.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import netutil
from ..config import DEFAULT_PORTS
from ..model import Severity
from .base import Check


class PortScan(Check):
    name = "portscan"
    title = "TCP port scan"
    description = "Checks each live host for open TCP ports."

    def run(self):
        hosts = self.shared.get("live_hosts", [])
        ports = self.ctx.ports or DEFAULT_PORTS
        open_ports: dict[str, list[int]] = {}

        if not hosts:
            self.add(
                "No hosts to port-scan",
                Severity.INFO,
                detail="Discovery found no live hosts.",
            )
            self.shared["open_ports"] = open_ports
            return self.findings

        jobs = [(ip, port) for ip in hosts for port in ports]
        total = len(jobs) or 1
        done = 0
        self.log(f"scanning {len(ports)} ports on {len(hosts)} host(s) = {total} probes")

        def probe(job):
            ip, port = job
            return job, netutil.tcp_connect(ip, port, self.ctx.tcp_timeout)

        with ThreadPoolExecutor(max_workers=self.ctx.max_threads) as pool:
            futs = [pool.submit(probe, j) for j in jobs]
            for fut in as_completed(futs):
                if self.cancelled():
                    break
                done += 1
                if done % 25 == 0 or done == total:
                    self.ctx.progress(done / total, f"portscan {done}/{total}")
                try:
                    (ip, port), is_open = fut.result()
                except Exception:
                    continue
                if is_open:
                    open_ports.setdefault(ip, []).append(port)

        for ip in open_ports:
            open_ports[ip].sort()

        self.shared["open_ports"] = open_ports

        if not open_ports:
            self.add(
                "No open ports detected",
                Severity.INFO,
                detail="None of the scanned ports responded on any live host.",
            )
        else:
            for ip in sorted(open_ports, key=lambda x: tuple(int(o) for o in x.split("."))):
                plist = ", ".join(str(p) for p in open_ports[ip])
                host = netutil.reverse_dns(ip)
                self.add(
                    f"Open ports on {ip}",
                    Severity.INFO,
                    detail=f"{host + '  ' if host else ''}Open: {plist}",
                    target=ip,
                )
        return self.findings
