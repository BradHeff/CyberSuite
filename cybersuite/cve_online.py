"""Optional online CVE enrichment via the public CIRCL CVE-Search API.

This is OFF by default and only runs when the operator explicitly enables it,
because it sends detected product/version strings to a third party service.
Everything here fails soft: no internet, a slow API, or an unexpected response
gives no extra findings, the offline knowledge base still applies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

_API = "https://cve.circl.lu/api/search/{vendor}/{product}"
_TIMEOUT = 6.0

# Map our internal product keys to (vendor, product) as CIRCL indexes them.
_VENDOR_PRODUCT = {
    "openssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "openssl": ("openssl", "openssl"),
    "vsftpd": ("beasts", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "exim": ("exim", "exim"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
}


def available(host: str = "cve.circl.lu") -> bool:
    """Quick reachability probe so the UI can warn if offline."""
    try:
        req = urllib.request.Request(f"https://{host}/", method="HEAD")
        urllib.request.urlopen(req, timeout=3.0)
        return True
    except Exception:
        return False


def lookup(product_key: str, version: str, limit: int = 5) -> list[dict]:
    """Return a list of {'cve','summary','cvss'} for a product/version, best-effort."""
    vp = _VENDOR_PRODUCT.get(product_key)
    if not vp:
        return []
    url = _API.format(vendor=vp[0], product=vp[1])
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberSuite/1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        return []

    # CIRCL responses have varied over time; handle both list and {'data':[...]}.
    entries = data.get("data") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        return []

    out = []
    vtuple = version.split(".")
    for e in entries:
        if not isinstance(e, dict):
            continue
        cve_id = e.get("id") or e.get("cve") or ""
        summary = e.get("summary") or e.get("description") or ""
        cvss = e.get("cvss") or e.get("cvss3") or ""
        # Loose relevance filter: mention of the version's major.minor helps cut noise.
        vv = ".".join(vtuple[:2])
        if vv and summary and vv not in summary and version not in summary:
            continue
        out.append({"cve": cve_id, "summary": summary[:240], "cvss": cvss})
        if len(out) >= limit:
            break
    return out
