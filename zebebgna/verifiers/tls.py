"""TLS certificate and transport-layer security audit."""

import datetime
import socket
import ssl
from urllib.parse import urlparse


def _parse_ascii_time(value):
    return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def audit_tls(url, report):
    """Connect to the URL's host over TLS and audit the presented certificate."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        report.add_finding("error", "tls", "Cannot audit TLS: URL has no hostname")
        return
    port = parsed.port or 443

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
    except ssl.SSLCertVerificationError as exc:
        report.add_finding(
            "critical", "tls",
            f"Certificate chain verification failed: "
            f"{getattr(exc, 'verify_message', None) or exc}",
        )
        return
    except (socket.timeout, OSError) as exc:
        report.add_finding(
            "error", "tls",
            f"Could not establish TLS connection to {host}:{port}: {exc}",
        )
        return

    if not cert:
        report.add_finding("error", "tls", "Server did not present a certificate")
        return

    try:
        not_before = _parse_ascii_time(cert["notBefore"])
        not_after = _parse_ascii_time(cert["notAfter"])
    except (KeyError, ValueError):
        report.add_finding(
            "error", "tls", "Certificate validity dates could not be parsed"
        )
        return

    now = datetime.datetime.utcnow()
    if now > not_after:
        report.add_finding(
            "critical", "tls",
            f"Certificate is EXPIRED (notAfter: {cert['notAfter']})",
        )
    else:
        days_left = (not_after - now).days
        if days_left < 30:
            report.add_finding(
                "warn", "tls",
                f"Certificate expires soon: {cert['notAfter']} "
                f"({days_left} days remaining)",
            )
        else:
            report.add_finding(
                "info", "tls",
                f"Certificate valid until {cert['notAfter']} "
                f"({days_left} days remaining)",
            )

    san = cert.get("subjectAltName", [])
    names = [value for entry_type, value in san if entry_type == "DNS"]
    if names and host not in names and not any(host.endswith("." + n) for n in names):
        report.add_finding(
            "critical", "tls",
            f"Certificate does not cover hostname '{host}' (SAN: {names or 'none'})",
        )

    issuer = dict(part[0] for part in cert.get("issuer", []))
    report.add_finding(
        "info", "tls",
        f"TLS {protocol} - issued by: {issuer.get('organizationName', 'unknown')}",
    )
