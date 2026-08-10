"""Security verifiers used by zebebgna's verification pipeline."""

from zebebgna.fetch import fetcher

from . import fingerprint, headers, integrity, phishing, tls


def run_verifiers(report, feedback=None, offline=False):
    """Run the full verification pipeline over a :class:`VerificationReport`.

    Single-signal checks run first (phishing, tls, headers, integrity,
    fingerprint); the threat-fusion engine then correlates those signals
    into an attack scenario and attaches a
    :class:`~zebebgna.fusion.ThreatAssessment`. ``feedback`` is an optional
    ``(confirmed, rejected)`` pair of prior user verdicts for the same
    domain, used to nudge the fused risk. When ``offline=True`` only the
    receipt-side checks run (for image/copy verification where there is
    no endpoint to inspect).
    """
    if not offline:
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
    fingerprint.verify_fingerprint(report.bank, report.data, report)

    from zebebgna.fusion import assess

    report.threat = assess(report, feedback=feedback)


__all__ = ["run_verifiers", "phishing", "tls", "headers", "integrity",
           "fingerprint"]
