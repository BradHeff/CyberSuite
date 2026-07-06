"""Discover live hosts on the local subnet(s).

Uses a fast threaded TCP-connect sweep against a handful of very common ports,
falling back to ICMP ping. Hosts found are written to shared['live_hosts'] for
the port scanner to consume.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import netutil
from ..model import Severity
from .base import Check

# Ports pinged during discovery: if any answers, the host is "up".
DISCOVERY_PORTS = [443, 80, 445, 22, 3389, 139, 53, 8080]


class NetworkDiscovery(Check):
    name = "discovery"
    title = "Network host discovery"
    description = "Finds live devices on your local subnet(s)."

    def _probe_host(self, ip: str) -> bool:
        for port in DISCOVERY_PORTS:
            if self.cancelled():
                return False
            if netutil.tcp_connect(ip, port, min(self.ctx.tcp_timeout, 0.4)):
                return True
        return netutil.ping(ip, timeout_ms=500)

    def run(self):
        subnets = self.ctx.subnets or netutil.guess_local_subnets()
        my_ips = set(netutil.local_ipv4_addresses())

        if not subnets:
            self.add(
                "Could not determine local subnet",
                Severity.INFO,
                detail="No non-loopback IPv4 interface was found.",
                recommendation="Ensure you are connected to the network you want to scan.",
            )
            self.shared["live_hosts"] = []
            return self.findings

        self.add(
            "Scanning from this host",
            Severity.INFO,
            detail=f"Local addresses: {', '.join(sorted(my_ips)) or 'unknown'}\n"
                   f"Target subnet(s): {', '.join(subnets)}",
            target=", ".join(subnets),
        )

        targets: list[str] = []
        for cidr in subnets:
            targets.extend(netutil.hosts_in_subnet(cidr))
        # De-dup while preserving order.
        seen: set[str] = set()
        targets = [t for t in targets if not (t in seen or seen.add(t))]

        live: list[str] = []
        total = len(targets) or 1
        done = 0
        self.log(f"probing {total} addresses across {len(subnets)} subnet(s)")

        with ThreadPoolExecutor(max_workers=self.ctx.max_threads) as pool:
            futs = {pool.submit(self._probe_host, ip): ip for ip in targets}
            for fut in as_completed(futs):
                if self.cancelled():
                    break
                ip = futs[fut]
                done += 1
                self.ctx.progress(done / total, f"discovery {done}/{total}")
                try:
                    if fut.result():
                        live.append(ip)
                except Exception:  # a probe failing should never kill the sweep
                    continue

        live.sort(key=lambda x: tuple(int(o) for o in x.split(".")))
        self.shared["live_hosts"] = live
        self.shared["my_ips"] = my_ips

        detail_lines = []
        for ip in live:
            host = netutil.reverse_dns(ip)
            tag = " (this machine)" if ip in my_ips else ""
            detail_lines.append(f"  {ip}{f'  {host}' if host else ''}{tag}")

        self.add(
            f"{len(live)} live host(s) found",
            Severity.INFO,
            detail="\n".join(detail_lines) if detail_lines else "No responsive hosts.",
            recommendation=(
                "Confirm every device above is one you recognise. Unknown devices on "
                "a school network should be investigated — they may be rogue APs, "
                "personal devices, or unauthorised equipment."
            ),
            target=", ".join(subnets),
        )
        return self.findings
