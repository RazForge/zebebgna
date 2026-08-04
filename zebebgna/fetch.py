"""Secure HTTP fetching with strict TLS verification and connection pooling.

Unlike naive scraping utilities (which often ship with ``verify_ssl=False``
shortcuts), every request made by zebebgna goes through a hardened
``requests.Session`` that:

- requires HTTPS (plain-HTTP receipt URLs are refused),
- always verifies the server certificate chain,
- enforces timeouts and bounded redirects,
- refuses private/internal hosts (SSRF guard) and re-validates every
  redirect hop against the same policy,
- optionally restricts the set of fetchable hosts (allowlist).

The SSRF guard is defense in depth: even when no allowlist is configured,
loopback, link-local, private, reserved, and multicast targets are never
fetched, and each redirect destination is re-checked so an allowed host
cannot tunnel into an internal endpoint.
"""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

DEFAULT_TIMEOUT = 15
MAX_REDIRECTS = 5
USER_AGENT = "zebebgna/0.1 (defensive receipt verification agent)"

_PRIVATE_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}
_PRIVATE_HOSTNAME_SUFFIXES = (".local", ".localhost", ".internal")


class InsecureURLError(ValueError):
    """Raised when a caller attempts to fetch a non-HTTPS URL."""


def _ip_is_internal(ip):
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def host_is_private_literal(host):
    """Cheap SSRF check: private IP literal or private hostname pattern.

    Does no DNS resolution, so it is safe to call from request handlers.
    """
    if not host:
        return False
    lowered = host.lower().rstrip(".")
    if lowered in _PRIVATE_HOSTNAMES or lowered.endswith(
            _PRIVATE_HOSTNAME_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return _ip_is_internal(ip)


def host_is_private(host):
    """Full SSRF check: private literal, private hostname, or any resolved
    address being private/loopback/link-local/reserved/multicast."""
    if not host:
        return False
    if host_is_private_literal(host):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError):
            continue
        if _ip_is_internal(ip):
            return True
    return False


def validate_fetch_target(url, allowed_hosts=None):
    """Reject insecure schemes and private/internal SSRF targets.

    Raises :class:`InsecureURLError` if ``url`` is not HTTPS, points at a
    private/internal host, or (when ``allowed_hosts`` is given) at a host
    outside the allowlist.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise InsecureURLError(
            f"Insecure scheme '{parsed.scheme}' - refusing to fetch "
            "non-HTTPS receipt URLs"
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise InsecureURLError("URL has no hostname")
    if host_is_private(host):
        raise InsecureURLError(
            f"Refusing to fetch private/internal host: {host}"
        )
    if allowed_hosts:
        allowed = host in allowed_hosts or any(
            host.endswith("." + h) for h in allowed_hosts
        )
        if not allowed:
            raise InsecureURLError(
                f"Host '{host}' is not in the allowed hosts list"
            )


class SecureFetcher:
    def __init__(self, allowed_hosts=None):
        self.allowed_hosts = set(allowed_hosts or ())
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.session.max_redirects = MAX_REDIRECTS

    @staticmethod
    def assert_https(url):
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise InsecureURLError(
                f"Insecure scheme '{parsed.scheme}' - refusing to fetch "
                "non-HTTPS receipt URLs"
            )

    def get(self, url, **kwargs):
        self.assert_https(url)
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        kwargs["allow_redirects"] = False
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            validate_fetch_target(current, self.allowed_hosts)
            resp = self.session.get(current, **kwargs)
            if not resp.is_redirect:
                break
            location = resp.headers.get("Location")
            if not location:
                break
            next_url = urljoin(current, location)
            self.assert_https(next_url)
            current = next_url
        else:
            raise requests.TooManyRedirects(
                f"Exceeded {MAX_REDIRECTS} redirects while fetching {url}"
            )
        resp.raise_for_status()
        return resp

    def fetch_text(self, url):
        """Fetch and return the text body of an HTTPS URL."""
        return self.get(url).text

    def fetch_pdf_bytes(self, url):
        """Fetch an HTTPS PDF and return its raw bytes.

        Returns bytes rather than a temp-file path so callers never leak
        temporary files on disk.
        """
        return self.get(url).content

    def fetch_headers(self, url):
        """Return the response headers of an HTTPS URL."""
        resp = self.get(url, stream=True)
        resp.close()
        return resp.headers


fetcher = SecureFetcher()
