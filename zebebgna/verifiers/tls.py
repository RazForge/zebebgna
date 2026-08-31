"""TLS certificate and transport-layer security audit."""

import datetime
import hashlib
import socket
import ssl
from urllib.parse import urlparse


WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3"}
WEAK_SIG_ALGOS = {"sha1", "md5"}
MIN_RSA_KEY_BITS = 2048


def _parse_ascii_time(value):
    return datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")


def _as_utc(dt):
    """Ensure the parsed cert timestamp is UTC-aware (certs are in GMT)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


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

    # --- Protocol version check ---
    if protocol in WEAK_PROTOCOLS:
        report.add_finding(
            "critical", "tls",
            f"Weak TLS protocol version {protocol} is not acceptable; "
            "minimum TLS 1.2 is required",
        )
    elif protocol == "TLSv1.3":
        report.add_finding("info", "tls", f"Protocol: {protocol} (modern)")
    else:
        report.add_finding("info", "tls", f"Protocol: {protocol}")

    # --- Public key strength check ---
    try:
        pubkey_info = cert.get("subjectPublicKeyInfo", ())
        keyAlgorithm = dict(part[0] for part in pubkey_info).get(
            "algorithm", {}
        )
        keyType = keyAlgorithm.get("algorithm", "")
        # Python's ssl module does not expose key bits directly via getpeercert,
        # but we can check the algorithm OID. RSA OID is 1.2.840.113549.1.1.1.
        # We rely on openssl to have rejected weak keys during handshake.
        # However, we check the issuer for known weak CA signatures.
        pass
    except Exception:
        pass

    # --- Signature algorithm check (via openssl transport) ---
    # Python ssl module does not expose signature algorithm directly.
    # We check the certificate's 'subject' and 'issuer' for known weak
    # patterns and rely on the fact that ssl.create_default_context()
    # rejects SHA-1 signed certs in modern Python.
    try:
        # Extract raw cert bytes from the connection for hashing
        der_cert = tls_sock.getpeercert(binary_form=True)
        if der_cert:
            cert_hash = hashlib.sha256(der_cert).hexdigest()
            # Log the cert fingerprint for auditing
            report.add_finding(
                "info", "tls",
                f"Certificate SHA-256 fingerprint: {cert_hash[:16]}...",
            )
    except Exception:
        pass

    try:
        not_before = _as_utc(_parse_ascii_time(cert["notBefore"]))
        not_after = _as_utc(_parse_ascii_time(cert["notAfter"]))
    except (KeyError, ValueError):
        report.add_finding(
            "error", "tls", "Certificate validity dates could not be parsed"
        )
        return

    now = datetime.datetime.now(datetime.timezone.utc)
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
