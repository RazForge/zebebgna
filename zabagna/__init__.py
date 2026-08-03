"""zabagna - defensive verification of Ethiopian bank receipts.

Public API:
    verify_receipt(bank, url_or_id) -> VerificationReport
    audit_receipt_url(url)         -> VerificationReport
"""

from .extractors import EXTRACTORS
from .fetch import InsecureURLError, SecureFetcher, fetcher
from .report import Finding, VerificationReport

__version__ = "0.1.0"

__all__ = [
    "verify_receipt",
    "audit_receipt_url",
    "VerificationReport",
    "Finding",
    "InsecureURLError",
    "SecureFetcher",
]


def verify_receipt(bank, url_or_id):
    """Fetch, extract, and verify a receipt's authenticity and security.

    Args:
        bank (str): one of cbe, dashen, awash, boa, zemen, tele.
        url_or_id (str): receipt URL, or a bare Telebirr receipt ID.

    Returns:
        VerificationReport: extracted data plus severity-tagged findings.
    """
    bank = (bank or "").lower()
    if bank not in EXTRACTORS:
        raise ValueError(f"Unsupported bank: {bank}")

    if not url_or_id:
        raise ValueError("A receipt URL or ID is required")

    url = url_or_id
    if not url.startswith("http"):
        if bank != "tele":
            raise ValueError("A full URL is required for this bank")
        url = f"https://transactioninfo.ethiotelecom.et/receipt/{url_or_id}"

    fetcher.assert_https(url)

    data = EXTRACTORS[bank](url)
    report = VerificationReport(url=url, bank=bank, data=data)

    from .verifiers import run_verifiers

    run_verifiers(report)
    return report


def audit_receipt_url(url):
    """Run a transport/URL-level security audit without extracting receipt data.

    Args:
        url (str): receipt endpoint URL.

    Returns:
        VerificationReport: URL, TLS, and headers findings only.
    """
    report = VerificationReport(url=url)

    from .verifiers import headers as headers_verifier
    from .verifiers import phishing, tls

    fetcher.assert_https(url)
    phishing.audit_url(url, report)
    tls.audit_tls(url, report)
    try:
        fetched_headers = fetcher.fetch_headers(url)
    except Exception as exc:
        report.add_finding("error", "fetch", f"Could not fetch endpoint: {exc}")
        fetched_headers = None
    headers_verifier.audit_headers(fetched_headers, report)
    return report
