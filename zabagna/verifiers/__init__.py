"""Security verifiers used by zabagna's verification pipeline."""

from zabagna.fetch import fetcher

from . import headers, integrity, phishing, tls


def run_verifiers(report):
    """Run the full verification pipeline over a :class:`VerificationReport`."""
    phishing.audit_url(report.url, report)
    tls.audit_tls(report.url, report)
    try:
        fetched_headers = fetcher.fetch_headers(report.url)
    except Exception as exc:
        report.add_finding(
            "error", "fetch", f"Could not fetch receipt endpoint: {exc}"
        )
        fetched_headers = None
    headers.audit_headers(fetched_headers, report)
    integrity.verify_integrity(report.bank, report.data, report)


__all__ = ["run_verifiers", "phishing", "tls", "headers", "integrity"]
