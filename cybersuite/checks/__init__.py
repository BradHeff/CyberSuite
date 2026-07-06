"""Security checks. Each module exposes a Check subclass; ALL_CHECKS lists them."""

from __future__ import annotations

from .base import Check
from .network_discovery import NetworkDiscovery
from .port_scan import PortScan
from .service_audit import ServiceAudit
from .cve_scan import CveScan
from .tls_audit import TlsAudit
from .gateway_audit import GatewayAudit
from .local_host import LocalHostAudit
from .firewall import FirewallAudit

# Order matters: discovery feeds the scans that follow it.
ALL_CHECKS: list[type[Check]] = [
    LocalHostAudit,
    FirewallAudit,
    NetworkDiscovery,
    PortScan,
    ServiceAudit,
    CveScan,
    TlsAudit,
    GatewayAudit,
]

__all__ = ["Check", "ALL_CHECKS"]
