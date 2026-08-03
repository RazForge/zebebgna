"""Secure HTTP fetching with strict TLS verification and connection pooling.

Unlike naive scraping utilities (which often ship with ``verify_ssl=False``
shortcuts), every request made by zebebgna goes through a hardened
``requests.Session`` that:

- requires HTTPS (plain-HTTP receipt URLs are refused),
- always verifies the server certificate chain,
- enforces timeouts and bounded redirects.
"""

import tempfile
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 15
MAX_REDIRECTS = 5
USER_AGENT = "zebebgna/0.1 (defensive receipt verification agent)"


class InsecureURLError(ValueError):
    """Raised when a caller attempts to fetch a non-HTTPS URL."""


class SecureFetcher:
    def __init__(self):
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
        resp = self.session.get(url, **kwargs)
        resp.raise_for_status()
        return resp

    def fetch_text(self, url):
        """Fetch and return the text body of an HTTPS URL."""
        return self.get(url).text

    def fetch_pdf(self, url):
        """Download an HTTPS PDF to a temp file and return its path."""
        resp = self.get(url)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(resp.content)
            return tmp.name

    def fetch_headers(self, url):
        """Return the response headers of an HTTPS URL."""
        resp = self.get(url, stream=True)
        resp.close()
        return resp.headers


fetcher = SecureFetcher()
