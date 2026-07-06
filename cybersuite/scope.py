"""
Scope guard:
Gateway and firewall vulnerability probes are only.
Only authorised equipment you own on your own LAN.
"""

from __future__ import annotations

import ipaddress

from . import netutil


def is_internal_ip(ip: str) -> bool:
    """True only for RFC1918 / link-local / CGNAT / loopback addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return True
    # 100.64.0.0/10 carrier-grade NAT is also "internal" for our purposes.
    return addr in ipaddress.ip_network("100.64.0.0/10")


def is_internal_subnet(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return is_internal_ip(str(net.network_address))


def filter_internal(targets: list[str]) -> tuple[list[str], list[str]]:
    """Split targets into (internal, rejected_public)."""
    internal, public = [], []
    for t in targets:
        (internal if is_internal_ip(t) else public).append(t)
    return internal, public


def default_gateways() -> list[str]:
    """Discover default-gateway IP(s) cross-platform, internal ones only."""
    gws: set[str] = set()

    if netutil.is_windows():
        rc, out = netutil.run_cmd(["ipconfig"])
        if rc == 0:
            for line in out.splitlines():
                if "Default Gateway" in line:
                    part = line.split(":", 1)[-1].strip()
                    if part and part not in ("", "::"):
                        gws.add(part)
        rc, out = netutil.run_cmd(["route", "print", "0.0.0.0"])
        if rc == 0:
            for line in out.splitlines():
                cols = line.split()
                if len(cols) >= 3 and cols[0] == "0.0.0.0":
                    gws.add(cols[2])
    else:
        rc, out = netutil.run_cmd(["ip", "route"])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if "via" in parts:
                        gws.add(parts[parts.index("via") + 1])
        if not gws:
            rc, out = netutil.run_cmd(["route", "-n"])
            if rc == 0:
                for line in out.splitlines():
                    cols = line.split()
                    if len(cols) >= 2 and cols[0] == "0.0.0.0":
                        gws.add(cols[1])

    # Only ever return internal gateways.
    clean = []
    for g in gws:
        g = g.strip()
        if is_internal_ip(g):
            clean.append(g)
    return sorted(set(clean))
