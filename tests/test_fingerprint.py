"""Tests for the per-bank fingerprint verifier."""

import datetime

import pytest

from zebebgna.report import VerificationReport
from zebebgna.verifiers.fingerprint import verify_fingerprint


def _report(bank="cbe"):
    return VerificationReport(
        url="https://apps.cbe.com.et/x",
        bank=bank,
        data={},
    )


def _find(report, severity, category):
    return [f for f in report.findings
            if f.severity == severity and f.category == category]


def test_clean_cbe_layout_passes():
    report = _report("cbe")
    report.data = {
        "customer_name": "ABEBE BEKELE",
        "branch": "Bole",
        "payment_date": "01/15/2024, 09:30:00 AM",
        "reference_no": "FT20240115123456",
        "transferred_amount": "1,000.00",
    }
    verify_fingerprint("cbe", report.data, report)
    assert _find(report, "error", "fingerprint") == []
    assert _find(report, "warn", "fingerprint") == []


def test_wrong_bank_layout_is_error():
    report = _report("cbe")
    report.data = {"Total Amount Paid": "500", "Reference No": "ZX23",
                   "Payer Name": "MULU"}
    verify_fingerprint("cbe", report.data, report)
    errors = _find(report, "error", "fingerprint")
    assert errors
    assert "does not match the canonical CBE" in errors[0].message


def test_partial_layout_is_warn():
    report = _report("tele")
    report.data = {"total_paid": "100", "status": "SUCCESS"}
    verify_fingerprint("tele", report.data, report)
    assert _find(report, "error", "fingerprint") == []
    warns = _find(report, "warn", "fingerprint")
    assert any("partially matches" in w.message for w in warns)


def test_amount_words_disagree_is_error():
    report = _report("cbe")
    report.data = {
        "total_debited": "1,000.00",
        "amount_in_words": "Two Thousand Birr Only",
        "reference_no": "FT20240115123456",
        "payment_date": "01/15/2024",
    }
    verify_fingerprint("cbe", report.data, report)
    errors = _find(report, "error", "fingerprint")
    assert errors
    assert "amounts disagree" in errors[0].message


def test_amount_words_agree_passes():
    report = _report("cbe")
    report.data = {
        "total_debited": "2,000.00",
        "amount_in_words": "Two Thousand Birr Only",
        "reference_no": "FT20240115123456",
        "payment_date": "01/15/2024",
    }
    verify_fingerprint("cbe", report.data, report)
    assert _find(report, "error", "fingerprint") == []


def test_amharic_amount_words_agree():
    report = _report("zemen")
    report.data = {
        "Total Amount Paid": "ETB 1,234.00",
        "Amount in Words": "አንድ ሺህ ሁለት መቶ ሰላሳ አራት",
        "Date": "2024-03-10",
        "Reference No": "ZM123456789",
        "Payer Name": "ABEBE",
        "Settled Amount": "1234.00",
    }
    verify_fingerprint("zemen", report.data, report)
    assert _find(report, "error", "fingerprint") == []


def test_unparsable_words_flagged_as_warn():
    report = _report("dashen")
    report.data = {
        "amount": "500.00",
        "amount_in_words": "Hdsa lkjasd asf ss",
        "transfer_reference": "DB12345678",
        "transaction_date": "Mar 5, 2024",
    }
    verify_fingerprint("dashen", report.data, report)
    warns = _find(report, "warn", "fingerprint")
    assert any("could not be parsed" in w.message for w in warns)


def test_future_date_flagged():
    future = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    report = _report("zemen")
    report.data = {
        "Total Amount Paid": "100",
        "Date": future,
        "Reference No": "ZM123456789",
    }
    verify_fingerprint("zemen", report.data, report)
    warns = _find(report, "warn", "fingerprint")
    assert any("future" in w.message for w in warns)


def test_no_bank_skips():
    report = VerificationReport(url="https://example.com")
    verify_fingerprint(None, {}, report)
    assert report.findings == []


def test_fingerprint_runs_in_pipeline():
    from zebebgna.verifiers import run_verifiers
    import zebebgna.fetch as fetch_mod

    report = VerificationReport(
        url="https://transactioninfo.ethiotelecom.et/receipt/ABC",
        bank="cbe",
        data={"foo": "bar"},
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(fetch_mod.fetcher, "fetch_headers",
                   lambda u: {"Strict-Transport-Security": "x"})
        mp.setattr(fetch_mod.SecureFetcher, "fetch_headers",
                   lambda self, u: {"Strict-Transport-Security": "x"})
        run_verifiers(report)
    assert any(f.category == "fingerprint" for f in report.findings)
    assert report.threat is not None