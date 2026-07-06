"""Curated, offline CVE knowledge base plus banner/version parsing.

A full CVE feed has hundreds of thousands of entries and needs a live database;
that is out of scope for a zero-dependency tool. Instead this ships a curated
set of high-impact, still-commonly-seen vulnerabilities that map to services a
school LAN actually exposes. Optional online enrichment (see cve_online.py) can
augment this when the operator opts in.

Each signature matches a detected (product, version) and yields a CVE finding.
Version predicates are expressed as callables over a parsed (major, minor,
patch...) tuple so we avoid pulling in packaging libraries.
"""

from __future__ import annotations

import re

from .model import Severity


def parse_version(text: str) -> tuple[int, ...]:
    """Extract the first dotted-number version from arbitrary banner text."""
    m = re.search(r"(\d+(?:\.\d+){1,3})", text)
    if not m:
        return ()
    return tuple(int(p) for p in m.group(1).split("."))


def _lt(ver: tuple[int, ...], *bound: int) -> bool:
    return bool(ver) and ver < bound


def _between(ver, low, high) -> bool:
    return bool(ver) and low <= ver < high


# Each entry: product-key -> list of dicts.
#   match(version_tuple) -> bool
#   cve, severity, summary, fix
CVE_SIGNATURES: dict[str, list[dict]] = {
    "openssh": [
        {
            "match": lambda v: _lt(v, 9, 8),
            "cve": "CVE-2024-6387 (regreSSHion)",
            "severity": Severity.CRITICAL,
            "summary": "OpenSSH < 9.8p1 has a signal-handler race giving unauthenticated RCE as root on glibc Linux.",
            "fix": "Upgrade OpenSSH to 9.8p1+ (or your distro's patched build); as interim mitigation set LoginGraceTime 0.",
        },
        {
            "match": lambda v: _between(v, (8, 5), (9, 8)),
            "cve": "CVE-2023-38408 / hardening advisory",
            "severity": Severity.MEDIUM,
            "summary": "Older OpenSSH releases carry agent-forwarding and other advisories.",
            "fix": "Upgrade to the latest OpenSSH and disable agent forwarding unless required.",
        },
    ],
    "apache": [
        {
            "match": lambda v: _between(v, (2, 4, 49), (2, 4, 51)),
            "cve": "CVE-2021-41773 / CVE-2021-42013",
            "severity": Severity.CRITICAL,
            "summary": "Apache httpd 2.4.49/2.4.50 path traversal leading to file disclosure and RCE.",
            "fix": "Upgrade Apache httpd to 2.4.51 or later immediately.",
        },
        {
            "match": lambda v: _lt(v, 2, 4, 62),
            "cve": "Multiple httpd advisories",
            "severity": Severity.MEDIUM,
            "summary": "Apache httpd below 2.4.62 is missing recent security fixes.",
            "fix": "Upgrade Apache httpd to the current 2.4.x release.",
        },
    ],
    "nginx": [
        {
            "match": lambda v: _lt(v, 1, 22),
            "cve": "Multiple nginx advisories",
            "severity": Severity.MEDIUM,
            "summary": "nginx below 1.22 is missing several security fixes (incl. resolver/mp4 issues).",
            "fix": "Upgrade nginx to a current stable release (1.24+).",
        },
    ],
    "openssl": [
        {
            "match": lambda v: _between(v, (1, 0, 1), (1, 0, 1, 7)),
            "cve": "CVE-2014-0160 (Heartbleed)",
            "severity": Severity.CRITICAL,
            "summary": "OpenSSL 1.0.1 before 1.0.1g leaks memory (private keys, sessions) via Heartbleed.",
            "fix": "Upgrade OpenSSL to 1.0.1g+ and rotate any keys/certs that were exposed.",
        },
        {
            "match": lambda v: _between(v, (3, 0), (3, 0, 7)),
            "cve": "CVE-2022-3602 / CVE-2022-3786",
            "severity": Severity.HIGH,
            "summary": "OpenSSL 3.0.x before 3.0.7 has X.509 email punycode buffer overflows.",
            "fix": "Upgrade OpenSSL to 3.0.7 or later.",
        },
    ],
    "vsftpd": [
        {
            "match": lambda v: v[:3] == (2, 3, 4),
            "cve": "CVE-2011-2523 (vsftpd 2.3.4 backdoor)",
            "severity": Severity.CRITICAL,
            "summary": "vsftpd 2.3.4 shipped a malicious backdoor granting a root shell.",
            "fix": "Replace this vsftpd binary immediately and treat the host as compromised.",
        },
    ],
    "proftpd": [
        {
            "match": lambda v: _between(v, (1, 3, 3), (1, 3, 3, 6)),
            "cve": "CVE-2015-3306",
            "severity": Severity.HIGH,
            "summary": "ProFTPD mod_copy allows unauthenticated file read/write.",
            "fix": "Upgrade ProFTPD and disable mod_copy if unused.",
        },
    ],
    "exim": [
        {
            "match": lambda v: _lt(v, 4, 92),
            "cve": "CVE-2019-10149 / CVE-2019-15846",
            "severity": Severity.CRITICAL,
            "summary": "Exim before 4.92 has remotely exploitable RCE flaws.",
            "fix": "Upgrade Exim to 4.92+ (ideally the latest).",
        },
    ],
    "microsoft-iis": [
        {
            "match": lambda v: _lt(v, 8, 0),
            "cve": "Legacy IIS advisories",
            "severity": Severity.MEDIUM,
            "summary": "IIS 7.x and older run on end-of-life Windows Server versions.",
            "fix": "Migrate to a supported Windows Server / IIS version.",
        },
    ],
}

# Regexes to pull a product key + version out of a raw banner or HTTP Server line.
_PRODUCT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("openssh", re.compile(r"openssh[_/ -]*([\d.]+)", re.I)),
    ("apache", re.compile(r"apache(?:/| )([\d.]+)", re.I)),
    ("nginx", re.compile(r"nginx/([\d.]+)", re.I)),
    ("openssl", re.compile(r"openssl/([\d.a-z]+)", re.I)),
    ("vsftpd", re.compile(r"vsftpd ([\d.]+)", re.I)),
    ("proftpd", re.compile(r"proftpd ([\d.]+)", re.I)),
    ("exim", re.compile(r"exim ([\d.]+)", re.I)),
    ("microsoft-iis", re.compile(r"microsoft-iis/([\d.]+)", re.I)),
]


def identify(banner: str) -> list[tuple[str, str]]:
    """Return list of (product_key, version_string) found in a banner."""
    found = []
    for key, pat in _PRODUCT_PATTERNS:
        m = pat.search(banner or "")
        if m:
            found.append((key, m.group(1)))
    return found


def match_cves(product: str, version_str: str) -> list[dict]:
    """Return CVE signature dicts whose predicate matches this version."""
    sigs = CVE_SIGNATURES.get(product, [])
    ver = parse_version(version_str)
    if not ver:
        return []
    return [s for s in sigs if s["match"](ver)]
