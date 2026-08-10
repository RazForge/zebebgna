"""zebebgna - defensive verification of Ethiopian bank receipts.

Public API:
    verify_receipt(bank, url_or_id) -> VerificationReport
    audit_receipt_url(url)         -> VerificationReport
    verify_extracted_data(bank, data, source) -> VerificationReport
    verify_file(bank, path)        -> VerificationReport
"""

import os

from .extractors import EXTRACTORS
from .fetch import InsecureURLError, SecureFetcher, fetcher
from .fusion import Correlation, ThreatAssessment, assess
from .report import Finding, VerificationReport

__version__ = "0.2.0"

__all__ = [
    "verify_receipt",
    "verify_extracted_data",
    "verify_file",
    "audit_receipt_url",
    "VerificationReport",
    "Finding",
    "ThreatAssessment",
    "Correlation",
    "assess",
    "InsecureURLError",
    "SecureFetcher",
]


def verify_receipt(bank, url_or_id, feedback=None):
    """Fetch, extract, and verify a receipt's authenticity and security.

    Args:
        bank (str): one of cbe, dashen, awash, boa, zemen, tele.
        url_or_id (str): receipt URL, or a bare Telebirr receipt ID.
        feedback (tuple, optional): ``(confirmed, rejected)`` prior user
            verdicts for the same domain, nudging the fused risk score.

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

    run_verifiers(report, feedback=feedback)

    from .llm import attach_ai_review

    attach_ai_review(report)
    return report


def audit_receipt_url(url, feedback=None):
    """Run a transport/URL-level security audit without extracting receipt data.

    Args:
        url (str): receipt endpoint URL.
        feedback (tuple, optional): ``(confirmed, rejected)`` prior user
            verdicts for the same domain, nudging the fused risk score.

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
    report.threat = assess(report, feedback=feedback)
    return report


def verify_extracted_data(bank, data, source="text", feedback=None):
    """Verify already-extracted receipt data (image OCR, pasted text, copy).

    Runs the receipt-side checks only (integrity + fingerprint + threat
    fusion); there is no URL to audit. ``source`` labels the origin
    (e.g. ``file:///path/to/receipt.png`` or ``clipboard``).
    """
    bank = (bank or "").lower()
    if bank not in EXTRACTORS:
        raise ValueError(f"Unsupported bank: {bank}")

    report = VerificationReport(url=source or "text", bank=bank, data=data or {})
    report.add_finding(
        "info", "fetch",
        "No URL to audit; verified the receipt content only "
        f"(source: {source or 'text'})",
    )

    from .verifiers import run_verifiers

    run_verifiers(report, feedback=feedback, offline=True)

    from .llm import attach_ai_review

    attach_ai_review(report)
    return report


def verify_file(bank, path, feedback=None):
    """Verify a receipt PDF or image screenshot on disk."""
    from zebebgna.vision import extract_file_text, scan_fields

    text = extract_file_text(path)
    data = scan_fields(bank, text)
    source = f"file:///{os.path.abspath(path).replace(os.sep, '/')}"
    report = verify_extracted_data(bank, data, source=source, feedback=feedback)

    qr = None
    try:
        from zebebgna.vision import decode_qr

        qr = decode_qr(path)
    except Exception:
        qr = None
    if qr:
        report.data["qr_payload"] = qr
        report.add_finding(
            "info", "qr",
            f"QR code decoded on the receipt: {qr[:160]}",
        )
    else:
        report.add_finding(
            "info", "qr", "No QR code decoded from the receipt image"
        )
    return report
