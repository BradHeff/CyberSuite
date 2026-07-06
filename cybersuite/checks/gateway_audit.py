"""Internal network & gateway vulnerability tests.

SCOPE SAFETY: every target here is validated by scope.is_internal_ip() before a
single probe is sent. Public/routable addresses are refused outright. These
tests are for equipment you own on your own LAN — routers, firewalls, switches,
APs — and are only enabled when the operator opts in via the GUI/CLI.

Tests performed against the default gateway and internal hosts:
  * Insecure management planes (Telnet, cleartext HTTP admin, SNMP).
  * Default/guessable SNMP community strings (read-only GET, non-destructive).
  * UPnP/SSDP exposure on the LAN.
  * Open recursive DNS resolvers (DNS amplification risk).
  * Reachable SMB/NetBIOS on the gateway (should never be open on a router).
"""

from __future__ import annotations

import socket
import struct

from .. import netutil, scope
from ..model import Severity
from .base import Check

# Common router/firewall/switch management + risk ports.
_GW_ADMIN_PORTS = {
    23: "Telnet management",
    80: "HTTP admin (cleartext)",
    443: "HTTPS admin",
    22: "SSH management",
    8080: "HTTP admin (alt)",
    8443: "HTTPS admin (alt)",
    161: "SNMP",
    1900: "UPnP/SSDP",
    53: "DNS",
    445: "SMB",
    139: "NetBIOS",
    7547: "TR-069 CWMP (ISP remote mgmt)",
}

_DEFAULT_COMMUNITIES = ["public", "private", "cisco", "admin"]


class GatewayAudit(Check):
    name = "gateway"
    title = "Internal network & gateway vulnerability tests"
    description = "Probes your gateway/router and LAN for management-plane weaknesses (internal only)."

    # ------------------------------------------------------------ SNMP helpers
    def _snmp_get_sysdescr(self, ip: str, community: str) -> str | None:
        """Send a minimal SNMPv1 GET for sysDescr.0 (OID 1.3.6.1.2.1.1.1.0).

        Returns a response string if the device answers (i.e. the community is
        valid), else None. Read-only; sends no SET.
        """
        # Hand-built SNMPv1 GET request PDU for 1.3.6.1.2.1.1.1.0.
        comm = community.encode()
        oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"  # 1.3.6.1.2.1.1.1.0 encoded
        varbind = b"\x30" + bytes([len(oid) + 4]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
        varbinds = b"\x30" + bytes([len(varbind)]) + varbind
        # PDU: request-id=1, error-status=0, error-index=0
        pdu_body = (b"\x02\x01\x01" b"\x02\x01\x00" b"\x02\x01\x00" + varbinds)
        pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
        body = (b"\x02\x01\x00"  # version 1 (0)
                b"\x04" + bytes([len(comm)]) + comm + pdu)
        packet = b"\x30" + bytes([len(body)]) + body

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.ctx.tcp_timeout * 2)
            s.sendto(packet, (ip, 161))
            data, _ = s.recvfrom(2048)
            s.close()
            # A response arriving at all means the community was accepted.
            printable = bytes(b if 32 <= b < 127 else 0x2E for b in data).decode("latin-1")
            return printable
        except OSError:
            return None

    def _dns_recursion_open(self, ip: str) -> bool:
        """Ask the resolver to recurse for a name it isn't authoritative for."""
        # Minimal DNS query for example.com A with RD=1.
        txid = b"\x13\x37"
        flags = b"\x01\x00"  # standard query, recursion desired
        qdcount = b"\x00\x01"
        header = txid + flags + qdcount + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
        qname = b"".join(bytes([len(p)]) + p.encode() for p in ("example", "com")) + b"\x00"
        question = qname + b"\x00\x01" + b"\x00\x01"
        packet = header + question
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.ctx.tcp_timeout * 2)
            s.sendto(packet, (ip, 53))
            data, _ = s.recvfrom(1024)
            s.close()
            if len(data) < 8:
                return False
            ancount = struct.unpack(">H", data[6:8])[0]
            ra = bool(data[3] & 0x80)  # recursion-available bit
            return ra and ancount > 0
        except OSError:
            return False

    # ----------------------------------------------------------------- gateway
    def _audit_gateway(self, gw: str):
        if not scope.is_internal_ip(gw):
            return  # scope guard — never probe a public address here
        self.log(f"auditing gateway {gw}")
        found_admin = []
        for port, label in _GW_ADMIN_PORTS.items():
            if self.cancelled():
                return
            proto_udp = port in (161, 1900, 53)
            is_open = (not proto_udp) and netutil.tcp_connect(gw, port, self.ctx.tcp_timeout)

            if port == 23 and is_open:
                self.add(f"Telnet management open on gateway {gw}", Severity.CRITICAL,
                         detail="The gateway exposes Telnet — credentials cross the LAN in clear text.",
                         recommendation="Disable Telnet on the router/firewall and use SSH/HTTPS admin only.",
                         target=f"{gw}:23")
                found_admin.append(label)
            elif port == 80 and is_open:
                self.add(f"Cleartext HTTP admin on gateway {gw}", Severity.HIGH,
                         detail="Router admin over plain HTTP exposes the admin password to sniffing.",
                         recommendation="Use HTTPS admin only; disable HTTP or force a redirect; "
                                        "restrict admin to a management VLAN.",
                         target=f"{gw}:80")
                found_admin.append(label)
            elif port in (445, 139) and is_open:
                self.add(f"SMB/NetBIOS reachable on gateway {gw}:{port}", Severity.HIGH,
                         detail="A router/firewall should not expose file-sharing ports.",
                         recommendation="Investigate — this may indicate the device is misconfigured "
                                        "or is actually a host acting as a gateway. Firewall it off.",
                         target=f"{gw}:{port}")
                found_admin.append(label)
            elif port == 7547 and is_open:
                self.add(f"TR-069 (CWMP) open on gateway {gw}", Severity.MEDIUM,
                         detail="Port 7547 is the ISP remote-management protocol; historically abused "
                                "(e.g. the Mirai/Deutsche Telekom outage).",
                         recommendation="If you manage this device yourself, disable TR-069/remote "
                                        "management or firewall it to the ISP only.",
                         target=f"{gw}:7547")
                found_admin.append(label)
            elif is_open:
                found_admin.append(f"{label} ({port})")

        if found_admin:
            self.add(f"Gateway {gw} management surface", Severity.INFO,
                     detail="Reachable services: " + ", ".join(found_admin),
                     recommendation="Keep the router/firmware fully patched, change default admin "
                                    "credentials, and restrict management to a trusted VLAN.",
                     target=gw)

        # SNMP default community strings (read-only).
        for community in _DEFAULT_COMMUNITIES:
            if self.cancelled():
                return
            resp = self._snmp_get_sysdescr(gw, community)
            if resp is not None:
                self.add(f"SNMP answers default community '{community}' on {gw}", Severity.HIGH,
                         detail="The device responded to a well-known SNMP community string, exposing "
                                "configuration and (if writable) allowing changes.\n"
                                f"sysDescr excerpt: {resp[-120:].strip()}",
                         recommendation="Change SNMP community strings, or move to SNMPv3 with "
                                        "authentication+privacy, or disable SNMP if unused.",
                         target=f"{gw}:161")
                break  # one confirmation is enough

        # Open recursive DNS.
        if self._dns_recursion_open(gw):
            self.add(f"Gateway {gw} is an open recursive DNS resolver", Severity.MEDIUM,
                     detail="It recursively resolved an external name. Open resolvers are abused for "
                            "DNS amplification DDoS.",
                     recommendation="Restrict recursion to internal clients only, or point clients at "
                                    "a dedicated internal/upstream resolver.",
                     target=f"{gw}:53")

    # ------------------------------------------------------------ LAN-wide test
    def _audit_lan_dns(self):
        """Flag any internal host answering as an open recursive resolver."""
        hosts = [h for h in self.shared.get("live_hosts", []) if scope.is_internal_ip(h)]
        open_ports = self.shared.get("open_ports", {})
        for ip in hosts:
            if self.cancelled():
                return
            if 53 in open_ports.get(ip, []):
                if self._dns_recursion_open(ip):
                    self.add(f"Open recursive DNS resolver at {ip}", Severity.MEDIUM,
                             detail="Host recursively resolved an external name for us.",
                             recommendation="Disable open recursion; restrict to internal clients.",
                             target=f"{ip}:53")

    def run(self):
        if not self.ctx.internal_tests:
            self.add("Internal/gateway vulnerability tests skipped", Severity.INFO,
                     detail="These tests are disabled. Enable 'Internal network & gateway tests' to "
                            "audit your router/firewall (internal networks only).")
            return self.findings

        gateways = scope.default_gateways()
        # Also honour explicit internal subnets' gateway convention (.1) if detected.
        extra = []
        for cidr in (self.ctx.subnets or []):
            if scope.is_internal_subnet(cidr):
                base = cidr.split("/")[0].rsplit(".", 1)[0]
                cand = f"{base}.1"
                if scope.is_internal_ip(cand):
                    extra.append(cand)
        gateways = sorted(set(gateways) | set(extra))

        if not gateways:
            self.add("No internal gateway found to test", Severity.INFO,
                     detail="Could not identify an internal default gateway.")
        else:
            self.add("Gateway(s) selected for internal testing", Severity.INFO,
                     detail="\n".join(gateways),
                     recommendation="Confirm these are devices you administer before proceeding.",
                     target=", ".join(gateways))
            for gw in gateways:
                if self.cancelled():
                    break
                self._audit_gateway(gw)

        self._audit_lan_dns()
        return self.findings
