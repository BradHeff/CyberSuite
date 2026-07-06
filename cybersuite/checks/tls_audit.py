"""Inspect TLS certificates and protocol versions on TLS-capable open ports.

Flags: expired / not-yet-valid certs, certs expiring soon, self-signed certs,
and servers that still negotiate legacy TLS 1.0/1.1 (or SSLv3).
"""

from __future__ import annotations

import datetime
import socket
import ssl

from ..config import TLS_PORTS
from ..model import Severity
from .base import Check

_EXPIRY_WARN_DAYS = 30


def _parse_cert_time(value: str) -> datetime.datetime | None:
    # OpenSSL format e.g. 'Jun  1 12:00:00 2026 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


class TlsAudit(Check):
    name = "tls"
    title = "TLS / certificate audit"
    description = "Checks certificates for expiry, self-signing, and weak protocols."

    def _fetch_cert(self, ip: str, port: int):
        """Return (cert_dict, negotiated_version). cert_dict may be {} for self-signed."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE          # we inspect, we don't trust-gate
        try:
            with socket.create_connection((ip, port), timeout=self.ctx.tcp_timeout * 3) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                    return tls.getpeercert(binary_form=False) or {}, tls.version()
        except (ssl.SSLError, OSError):
            return None, None

    def _check_weak_protocols(self, ip: str, port: int) -> list[str]:
        weak = []
        # Probing TLS 1.0/1.1 individually; skipped unless 'intrusive' to limit handshakes.
        candidates = [
            (ssl.TLSVersion.TLSv1, "TLS 1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        ]
        for ver, label in candidates:
            if self.cancelled():
                break
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            try:
                c.minimum_version = ver
                c.maximum_version = ver
            except ValueError:
                continue  # this Python/OpenSSL build refuses to speak it — good
            try:
                with socket.create_connection((ip, port), timeout=self.ctx.tcp_timeout * 3) as s:
                    with c.wrap_socket(s, server_hostname=ip):
                        weak.append(label)
            except (ssl.SSLError, OSError):
                pass
        return weak

    def run(self):
        open_ports: dict[str, list[int]] = self.shared.get("open_ports", {})
        targets = [(ip, p) for ip, ports in open_ports.items() for p in ports if p in TLS_PORTS]

        if not targets:
            self.add("No TLS services found", Severity.INFO,
                     detail="No TLS-capable open ports were discovered.")
            return self.findings

        now = datetime.datetime.utcnow()
        for ip, port in targets:
            if self.cancelled():
                return self.findings
            tgt = f"{ip}:{port}"
            cert, version = self._fetch_cert(ip, port)
            if version is None:
                self.add(f"TLS handshake failed on {tgt}", Severity.LOW,
                         detail="Port is open but no TLS handshake completed.", target=tgt)
                continue

            if version in ("SSLv3", "TLSv1", "TLSv1.1"):
                self.add(
                    f"Weak TLS protocol on {tgt}", Severity.HIGH,
                    detail=f"Server negotiated {version}, which is deprecated and broken.",
                    recommendation="Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+ (ideally 1.3).",
                    target=tgt,
                )

            if not cert:
                self.add(
                    f"Self-signed / untrusted certificate on {tgt}", Severity.MEDIUM,
                    detail="The server presented a certificate with no verifiable chain.",
                    recommendation="Install a certificate from a trusted CA (or your internal PKI). "
                                   "Self-signed certs train users to click through warnings.",
                    target=tgt,
                )
            else:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                cn = subject.get("commonName", "?")
                not_after = _parse_cert_time(cert.get("notAfter", ""))
                not_before = _parse_cert_time(cert.get("notBefore", ""))

                if subject == issuer:
                    self.add(f"Self-signed certificate on {tgt}", Severity.MEDIUM,
                             detail=f"Subject equals issuer (CN={cn}).",
                             recommendation="Replace with a CA-issued certificate.", target=tgt)

                if not_after:
                    days = (not_after - now).days
                    if days < 0:
                        self.add(f"EXPIRED certificate on {tgt}", Severity.HIGH,
                                 detail=f"CN={cn} expired {abs(days)} day(s) ago ({cert.get('notAfter')}).",
                                 recommendation="Renew/replace this certificate immediately.", target=tgt)
                    elif days <= _EXPIRY_WARN_DAYS:
                        self.add(f"Certificate expiring soon on {tgt}", Severity.MEDIUM,
                                 detail=f"CN={cn} expires in {days} day(s) ({cert.get('notAfter')}).",
                                 recommendation="Schedule renewal now to avoid an outage.", target=tgt)
                    else:
                        self.add(f"Valid certificate on {tgt}", Severity.INFO,
                                 detail=f"CN={cn}, valid for {days} more day(s). Protocol {version}.",
                                 target=tgt)
                if not_before and not_before > now:
                    self.add(f"Certificate not yet valid on {tgt}", Severity.MEDIUM,
                             detail=f"CN={cn} becomes valid {cert.get('notBefore')}.",
                             recommendation="Check the server clock and certificate validity dates.",
                             target=tgt)

            if self.ctx.intrusive:
                for label in self._check_weak_protocols(ip, port):
                    self.add(f"Legacy {label} accepted on {tgt}", Severity.HIGH,
                             detail=f"Server completed a {label} handshake.",
                             recommendation=f"Disable {label} on this service.", target=tgt)
        return self.findings
