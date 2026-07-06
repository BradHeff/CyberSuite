"""Cross-platform network helper functions (pure standard library)."""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import sys


def is_windows() -> bool:
    return sys.platform.startswith("win")


def local_ipv4_addresses() -> list[str]:
    """Best-effort list of this machine's own IPv4 addresses (non-loopback)."""
    addrs: set[str] = set()

    # Trick: a UDP socket "connected" to a public IP reveals the outbound
    # interface address without sending any packets.
    for probe in ("8.8.8.8", "1.1.1.1", "192.168.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((probe, 80))
            addrs.add(s.getsockname()[0])
            s.close()
        except OSError:
            continue

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                addrs.add(ip)
    except OSError:
        pass

    return sorted(a for a in addrs if not a.startswith("127."))


def guess_local_subnets(prefix: int = 24) -> list[str]:
    """Derive /24 (by default) CIDR subnets from our own interface addresses."""
    nets: set[str] = set()
    for ip in local_ipv4_addresses():
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            nets.add(str(net))
        except ValueError:
            continue
    return sorted(nets)


def hosts_in_subnet(cidr: str, cap: int = 1024) -> list[str]:
    """Enumerate usable host addresses in a CIDR, capped for safety."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    hosts = []
    for i, host in enumerate(net.hosts()):
        if i >= cap:
            break
        hosts.append(str(host))
    return hosts


def tcp_connect(ip: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to ip:port succeeds within timeout."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def grab_banner(ip: str, port: int, timeout: float, send: bytes | None = None) -> str:
    """Open a socket and read a short banner. Returns '' on failure."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return ""
            if send:
                try:
                    s.sendall(send)
                except OSError:
                    pass
            data = s.recv(256)
            return data.decode("latin-1", "replace").strip()
    except OSError:
        return ""


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    """Return a hostname for an IP, or '' if none resolves."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""
    finally:
        socket.setdefaulttimeout(old)


def ping(ip: str, timeout_ms: int = 700) -> bool:
    """ICMP ping via the OS 'ping' binary (works without raw-socket privileges)."""
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # -W is seconds on Linux; round up to at least 1.
        secs = max(1, round(timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(secs), ip]
    try:
        res = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_ms / 1000 + 2
        )
        return res.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def run_cmd(cmd: list[str], timeout: float = 10.0) -> tuple[int, str]:
    """Run a command, return (returncode, combined stdout+stderr). Never raises."""
    try:
        res = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, text=True, errors="replace",
        )
        return res.returncode, res.stdout or ""
    except FileNotFoundError:
        return 127, ""
    except (subprocess.SubprocessError, OSError) as exc:
        return 1, str(exc)
