"""Static configuration: port catalog and risk knowledge base.

Keeping this data-driven means adding a new "known bad service" is a one-line
edit rather than a code change.
"""

from __future__ import annotations

from .model import Severity

# Common ports worth probing on a school/office LAN. Kept deliberately small so
# a full-subnet sweep stays fast on modest hardware.
DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143, 161,
    389, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 3000,
    3306, 3389, 4444, 5432, 5900, 5985, 5986, 6379, 8000, 8080,
    8443, 9000, 9200, 11211, 27017,
]

# TLS-capable ports we should attempt a certificate handshake on.
TLS_PORTS: set[int] = {443, 465, 993, 995, 8443, 5986, 636}

# Knowledge base: port -> (service, severity-if-open, why, how-to-fix).
# Severity here is the *default* risk of the service being reachable on a LAN;
# individual checks may upgrade it (e.g. exposed DB with no auth).
SERVICE_RISKS: dict[int, dict] = {
    21: {
        "name": "FTP",
        "severity": Severity.HIGH,
        "why": "FTP transmits credentials and files in clear text; trivially sniffed.",
        "fix": "Disable FTP. Use SFTP (over SSH) or FTPS. If it must stay, restrict "
               "by firewall to specific management hosts.",
    },
    23: {
        "name": "Telnet",
        "severity": Severity.CRITICAL,
        "why": "Telnet sends usernames, passwords and all data unencrypted.",
        "fix": "Disable Telnet everywhere and use SSH instead. On switches/APs, turn "
               "off the Telnet management plane.",
    },
    25: {
        "name": "SMTP",
        "severity": Severity.LOW,
        "why": "An open SMTP relay can be abused to send spam in your school's name.",
        "fix": "Confirm the server is not an open relay; require auth + TLS (587).",
    },
    110: {
        "name": "POP3 (cleartext)",
        "severity": Severity.MEDIUM,
        "why": "Cleartext mail retrieval exposes mailbox credentials.",
        "fix": "Disable plain POP3; use POP3S (995) or IMAPS (993).",
    },
    135: {
        "name": "MS RPC",
        "severity": Severity.MEDIUM,
        "why": "Windows RPC endpoint mapper; a common lateral-movement target.",
        "fix": "Block 135 at the network edge and between VLANs; keep Windows patched.",
    },
    137: {
        "name": "NetBIOS",
        "severity": Severity.MEDIUM,
        "why": "Legacy NetBIOS name service leaks host info and enables spoofing.",
        "fix": "Disable NetBIOS over TCP/IP on modern networks.",
    },
    139: {
        "name": "NetBIOS/SMB",
        "severity": Severity.HIGH,
        "why": "Legacy SMB transport; often indicates SMBv1 is enabled (WannaCry).",
        "fix": "Disable SMBv1; ensure only SMBv3 on 445 with signing required.",
    },
    143: {
        "name": "IMAP (cleartext)",
        "severity": Severity.MEDIUM,
        "why": "Cleartext mail access exposes credentials.",
        "fix": "Disable plain IMAP; require IMAPS (993).",
    },
    161: {
        "name": "SNMP",
        "severity": Severity.HIGH,
        "why": "SNMP v1/v2c uses a plaintext 'community string' (often 'public') that "
               "reveals device config and can allow changes.",
        "fix": "Use SNMPv3 with auth+priv, change default community strings, or "
               "disable SNMP if unused.",
    },
    389: {
        "name": "LDAP (cleartext)",
        "severity": Severity.MEDIUM,
        "why": "Unencrypted directory traffic can expose account data.",
        "fix": "Require LDAPS (636) / StartTLS; restrict who can query the directory.",
    },
    445: {
        "name": "SMB",
        "severity": Severity.HIGH,
        "why": "File sharing port; a top ransomware and lateral-movement vector if "
               "SMBv1 is on or signing is off.",
        "fix": "Disable SMBv1, require SMB signing, and firewall 445 so it is not "
               "reachable between VLANs or from student networks.",
    },
    1433: {
        "name": "MS SQL Server",
        "severity": Severity.HIGH,
        "why": "Database directly reachable on the network; brute-force / injection target.",
        "fix": "Firewall the DB to only its application servers; enforce strong SA "
               "password; enable encryption.",
    },
    1521: {
        "name": "Oracle DB",
        "severity": Severity.HIGH,
        "why": "Database listener exposed on the network.",
        "fix": "Restrict by firewall to app servers; patch the listener; strong creds.",
    },
    2049: {
        "name": "NFS",
        "severity": Severity.HIGH,
        "why": "Network file shares often export with weak host-based trust.",
        "fix": "Restrict exports to specific hosts, use NFSv4 with Kerberos, firewall it.",
    },
    3306: {
        "name": "MySQL/MariaDB",
        "severity": Severity.HIGH,
        "why": "Database reachable on the network; brute-force / data-exposure target.",
        "fix": "Bind to localhost or firewall to app servers only; strong root password.",
    },
    3389: {
        "name": "RDP",
        "severity": Severity.HIGH,
        "why": "Remote Desktop is a leading ransomware entry point when exposed.",
        "fix": "Never expose RDP to the internet; require a VPN, enable NLA, MFA, and "
               "account lockout; restrict by firewall to admin hosts.",
    },
    4444: {
        "name": "Metasploit/backdoor default",
        "severity": Severity.CRITICAL,
        "why": "Port 4444 is a very common default for remote-access malware/backdoors.",
        "fix": "Investigate this host immediately for compromise; isolate and scan it.",
    },
    5432: {
        "name": "PostgreSQL",
        "severity": Severity.HIGH,
        "why": "Database reachable on the network.",
        "fix": "Bind to localhost or firewall to app servers; enforce SSL + strong creds.",
    },
    5900: {
        "name": "VNC",
        "severity": Severity.HIGH,
        "why": "VNC often has weak/no authentication and no encryption.",
        "fix": "Tunnel VNC over SSH/VPN, set a strong password, or disable it.",
    },
    6379: {
        "name": "Redis",
        "severity": Severity.CRITICAL,
        "why": "Redis defaults to NO authentication and is a well-known instant-compromise "
               "target when exposed.",
        "fix": "Bind to localhost, set 'requirepass', enable protected-mode, firewall it.",
    },
    9200: {
        "name": "Elasticsearch",
        "severity": Severity.CRITICAL,
        "why": "Elasticsearch often ships with no auth; a common data-breach source.",
        "fix": "Enable security/auth, bind to localhost, and firewall the port.",
    },
    11211: {
        "name": "Memcached",
        "severity": Severity.HIGH,
        "why": "Open memcached leaks data and is abused for DDoS amplification.",
        "fix": "Bind to localhost, disable UDP, and firewall the port.",
    },
    27017: {
        "name": "MongoDB",
        "severity": Severity.CRITICAL,
        "why": "MongoDB historically shipped with no auth; a frequent data-breach source.",
        "fix": "Enable authentication, bind to localhost/app-net, and firewall the port.",
    },
}

# Ports open, encrypted is normal/expected.
EXPECTED_OK = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S"}
