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
    "cutt.ly", "shorturl.at", "ow.ly", "buff.ly", "db.tt", "v.gd",
    "tiny.cc", "lnkd.in", "snurl.com", "soo.gd", "clck.ru", "t.ly",
    "short.to", "doiop.com", "縮短网.com", "bc.vc", "adf.ly",
    "j.mp", "wp.me", "ift.tt", "rebrand.ly", "cort.as",
}

# TLDs commonly used in phishing but never by legitimate Ethiopian banks.
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".work", ".click", ".download", ".racing", ".win", ".bid",
    ".stream", ".date", ".review", ".party", ".trade", ".accountant",
    ".science", ".cricket", ".faith", ".loan", ".men", ".hair",
    ".mom", ".ireland", ".tokyo", ".surf", ".cfd", ".cyou", ".sbs",
}

# Only syntactically valid IPv4 literals (each octet 0-255) are flagged.
IP_HOST_RE = re.compile(
    r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
)
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
            "critical", "url",
            f"Host uses punycode (IDN) encoding: {host}; "
            "IDN homograph attacks use this to impersonate bank domains",
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

    # Check for suspicious TLDs not used by legitimate Ethiopian banks
    tld_part = "." + host.rsplit(".", 1)[-1] if "." in host else ""
    if tld_part in SUSPICIOUS_TLDS:
        report.add_finding(
            "critical", "phishing",
            f"Host uses suspicious TLD '{tld_part}'; legitimate Ethiopian "
            "bank endpoints use .com.et, .com, or .et TLDs",
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
