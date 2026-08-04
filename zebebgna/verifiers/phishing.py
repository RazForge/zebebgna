"""URL-level phishing and lookalike-domain heuristics."""

import difflib
import re
from urllib.parse import urlparse

KNOWN_BANK_DOMAINS = [
    "cbe.com.et",
    "apps.cbe.com.et",
    "dashensuperapp.com",
    "receipt.dashensuperapp.com",
    "awashbank.com",
    "awashpay.awashbank.com",
    "bankofabyssinia.com",
    "cs.bankofabyssinia.com",
    "zemenbank.com",
    "share.zemenbank.com",
    "ethiotelecom.et",
    "transactioninfo.ethiotelecom.et",
]

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "rb.gy",
    "cutt.ly", "shorturl.at", "ow.ly",
}

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PUNYCODE_RE = re.compile(r"^xn--")

LOOKALIKE_THRESHOLD = 0.72


_MULTI_TLDS = {"com.et", "co.et", "org.et", "net.et", "gov.et", "edu.et"}


def _registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def audit_url(url, report):
    """Run URL-level phishing heuristics against ``url`` and record findings."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port

    if scheme != "https":
        report.add_finding(
            "critical", "transport",
            f"URL uses insecure scheme '{scheme}'; bank receipts must be "
            "served over HTTPS",
        )

    if not host:
        report.add_finding("error", "url", "URL has no hostname")
        return

    if IP_HOST_RE.match(host):
        report.add_finding(
            "critical", "url",
            f"Host is a raw IP address ({host}); legitimate bank receipt "
            "endpoints use DNS names",
        )

    if PUNYCODE_RE.match(host):
        report.add_finding(
            "warn", "url",
            f"Host uses punycode (IDN) encoding: {host}",
        )

    if port and port != 443:
        report.add_finding(
            "warn", "url",
            f"Non-standard HTTPS port {port} in use",
        )

    if host in SHORTENERS:
        report.add_finding(
            "warn", "url",
            f"URL shortener domain ({host}) obfuscates the real destination",
        )

    for known in KNOWN_BANK_DOMAINS:
        if host == known or host.endswith("." + known):
            continue
        ratio = difflib.SequenceMatcher(
            None, _registered_domain(host), _registered_domain(known)
        ).ratio()
        if ratio >= LOOKALIKE_THRESHOLD:
            report.add_finding(
                "warn", "phishing",
                f"Host '{host}' closely resembles known bank domain "
                f"'{known}' (similarity {ratio:.0%}); possible lookalike/"
                "phishing domain",
            )
            break
