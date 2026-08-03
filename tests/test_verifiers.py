import pytest
from unittest import mock

from zebebgna import InsecureURLError, audit_receipt_url, verify_receipt
from zebebgna.fetch import fetcher
from zebebgna.report import VerificationReport
from zebebgna.verifiers import integrity, phishing, tls


def finding_categories(report):
    return {(f.severity, f.category) for f in report.findings}


# ---------------------------------------------------------------- phishing

def test_phishing_clean_https_url_has_no_critical():
    report = VerificationReport(url="https://receipt.dashensuperapp.com/receipt/123")
    phishing.audit_url(report.url, report)
    assert not any(f.severity in ("critical", "error") for f in report.findings)


def test_phishing_flags_insecure_scheme():
    report = VerificationReport(url="http://receipt.dashensuperapp.com/receipt/123")
    phishing.audit_url(report.url, report)
    assert ("critical", "transport") in finding_categories(report)


def test_phishing_flags_raw_ip_host():
    report = VerificationReport(url="https://192.168.1.10/receipt/123")
    phishing.audit_url(report.url, report)
    assert ("critical", "url") in finding_categories(report)


def test_phishing_flags_shortener():
    report = VerificationReport(url="https://bit.ly/abc123")
    phishing.audit_url(report.url, report)
    assert ("warn", "url") in finding_categories(report)


def test_phishing_flags_lookalike_domain():
    report = VerificationReport(url="https://dashensuperapp.com/receipt/123")
    phishing.audit_url(report.url, report)
    assert ("warn", "phishing") in finding_categories(report)


def test_phishing_known_subdomain_not_flagged():
    report = VerificationReport(url="https://cs.bankofabyssinia.com/slip/?trx=123")
    phishing.audit_url(report.url, report)
    assert not any(f.category == "phishing" for f in report.findings)


def test_phishing_flags_punycode_and_odd_port():
    report = VerificationReport(url="https://xn--cbe-9db.example.com:8443/r")
    phishing.audit_url(report.url, report)
    cats = finding_categories(report)
    assert ("warn", "url") in cats


# --------------------------------------------------------------- integrity

def test_integrity_cbe_amounts_consistent():
    report = VerificationReport(bank="cbe", url="https://example.com")
    data = {
        "transferred_amount": "1000.00",
        "commission": "25.00",
        "vat_on_commission": "3.75",
        "total_debited": "1028.75",
        "reference_no": "FT25211G11JQ",
        "status": "SUCCESS",
    }
    integrity.verify_integrity("cbe", data, report)
    assert not any(f.category == "integrity" and f.severity == "error"
                   for f in report.findings)


def test_integrity_cbe_amount_mismatch():
    report = VerificationReport(bank="cbe", url="https://example.com")
    data = {
        "transferred_amount": "1000.00",
        "commission": "25.00",
        "vat_on_commission": "3.75",
        "total_debited": "999.00",
    }
    integrity.verify_integrity("cbe", data, report)
    assert any(f.severity == "error" and f.category == "integrity"
               for f in report.findings)


def test_integrity_flags_non_success_status():
    report = VerificationReport(bank="tele", url="https://example.com")
    integrity.verify_integrity("tele", {"status": "FAILED"}, report)
    assert any(f.severity == "critical" for f in report.findings)


def test_integrity_flags_bad_cbe_reference():
    report = VerificationReport(bank="cbe", url="https://example.com")
    integrity.verify_integrity(
        "cbe", {"reference_no": "not-a-ref", "status": "SUCCESS"}, report
    )
    assert any("reference" in f.message.lower() for f in report.findings)


def test_integrity_tele_zero_amount():
    report = VerificationReport(bank="tele", url="https://example.com")
    integrity.verify_integrity("tele", {"total_paid": "0.00 Birr"}, report)
    assert any(f.category == "integrity" for f in report.findings)


def test_integrity_reports_missing_fields():
    report = VerificationReport(bank="cbe", url="https://example.com")
    integrity.verify_integrity("cbe", {}, report)
    assert any(f.category == "integrity" and f.severity == "warn"
               for f in report.findings)


# ------------------------------------------------------------------ report

def test_report_score_and_status():
    report = VerificationReport(url="https://example.com")
    assert report.score == 100
    assert report.status == "PASS"
    report.add_finding("critical", "tls", "cert expired")
    assert report.status == "FAIL"
    assert report.score < 100


# ------------------------------------------------------------------- fetch

def test_fetch_refuses_plain_http():
    with pytest.raises(InsecureURLError):
        fetcher.assert_https("http://example.com/receipt")


def test_fetch_accepts_https():
    assert fetcher.assert_https("https://example.com/receipt") is None


# -------------------------------------------------------------------- tls

def test_tls_audit_handles_connection_failure_gracefully():
    report = VerificationReport(url="https://localhost:1/receipt")
    tls.audit_tls(report.url, report)
    assert any(f.category == "tls" and f.severity == "error"
               for f in report.findings)


# --------------------------------------------------------------- pipeline

def test_verify_receipt_pipeline_end_to_end():
    fake_data = {
        "transferred_amount": "1000.00",
        "commission": "25.00",
        "vat_on_commission": "3.75",
        "total_debited": "1028.75",
        "reference_no": "FT25211G11JQ",
        "status": "SUCCESS",
    }
    with mock.patch.object(
        integrity, "verify_integrity", return_value=None
    ) as vi:
        with mock.patch(
            "zebebgna.verifiers.tls.audit_tls", return_value=None
        ), mock.patch.object(
            fetcher, "fetch_headers",
            side_effect=RuntimeError("offline"),
        ):
            with mock.patch.dict(
                "zebebgna.EXTRACTORS",
                {"cbe": mock.Mock(return_value=fake_data)},
            ):
                report = verify_receipt("cbe", "https://receipt.example.com/r")
    assert isinstance(report, VerificationReport)
    assert report.bank == "cbe"
    assert report.data == fake_data
    assert any(f.category == "fetch" for f in report.findings)


def test_audit_receipt_url_rejects_http_in_fetch():
    with pytest.raises(InsecureURLError):
        audit_receipt_url("http://receipt.example.com/r")
