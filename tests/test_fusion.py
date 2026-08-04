import pytest
from unittest import mock

from zebebgna.fusion import Correlation, ThreatAssessment, assess
from zebebgna.report import VerificationReport
from zebebgna.verifiers import run_verifiers


def rule_ids(assessment):
    return {c.rule_id for c in assessment.correlations}


# ----------------------------------------------------------------- clean

def test_clean_known_bank_host_is_low_risk():
    report = VerificationReport(
        url="https://receipt.dashensuperapp.com/r", bank="dashen",
        data={"status": "SUCCESS"},
    )
    report.add_finding("info", "tls", "Certificate valid until 2030")
    assessment = assess(report)
    assert assessment.risk_level == "LOW"
    assert assessment.correlations == []
    assert assessment.scenario is None


def test_to_dict_serializable():
    report = VerificationReport(
        url="https://example.com", bank="cbe", data={"status": "SUCCESS"}
    )
    report.add_finding(
        "warn", "headers", "Missing security header: Strict-Transport-Security"
    )
    payload = assess(report).to_dict()
    assert set(payload) == {
        "risk_score", "risk_level", "scenario", "correlations", "indicators",
        "unreadable", "feedback_adjustment",
    }
    assert payload["correlations"][0]["signals"] == [
        "Strict-Transport-Security"
    ]


# -------------------------------------------------------------- phishing

def test_lookalike_domain_correlates_to_phishing():
    report = VerificationReport(
        url="https://dashensuperapp.ru/pay", bank="dashen", data={}
    )
    report.add_finding(
        "warn", "phishing",
        "Host 'dashensuperapp.ru' closely resembles known bank domain "
        "'dashensuperapp.com' (similarity 77%); possible lookalike/"
        "phishing domain",
    )
    assessment = assess(report)
    assert "phish_lookalike" in rule_ids(assessment)
    assert assessment.risk_level in ("HIGH", "CRITICAL")
    assert assessment.indicators["official_domain_match"] is False


def test_fraud_campaign_combo_is_critical():
    report = VerificationReport(
        url="https://dashensuperapp.ru/pay", bank="dashen",
        data={"status": "SUCCESS"},
    )
    report.add_finding(
        "warn", "phishing",
        "Host 'dashensuperapp.ru' closely resembles known bank domain "
        "'dashensuperapp.com' (similarity 77%); possible lookalike/"
        "phishing domain",
    )
    report.add_finding("error", "integrity", "CBE total debited mismatch")
    assessment = assess(report)
    assert "fraud_full_campaign" in rule_ids(assessment)
    assert assessment.risk_level == "CRITICAL"
    assert "forgery" in assessment.scenario.lower()


def test_obfuscated_host_triggers_warning():
    report = VerificationReport(url="https://bit.ly/abc123", bank="tele", data={})
    report.add_finding("warn", "url", "URL shortener domain (bit.ly)")
    assessment = assess(report)
    assert "phish_obfuscation" in rule_ids(assessment)


# ------------------------------------------------------------ integrity

def test_non_success_status_is_critical():
    report = VerificationReport(
        url="https://transactioninfo.ethiotelecom.et/receipt/1",
        bank="tele",
        data={"status": "FAILED"},
    )
    report.add_finding(
        "critical", "integrity",
        "Non-success transaction status on receipt: FAILED",
    )
    assessment = assess(report)
    assert "integrity_status" in rule_ids(assessment)
    assert assessment.risk_level == "CRITICAL"
    assert "non-success" in assessment.scenario.lower()


def test_amount_mismatch_fuses_to_doctored_amounts():
    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe", data={}
    )
    report.add_finding(
        "error", "integrity",
        "CBE total debited mismatch: 1000.00 + 25.00 + 3.75 sums to 1028.75 "
        "but receipt states 999.00",
    )
    assessment = assess(report)
    assert "integrity_amounts" in rule_ids(assessment)


# ---------------------------------------------------------------- headers

def test_missing_all_core_headers_fuses_to_unhardened():
    report = VerificationReport(url="https://x.example.com/r", bank="cbe", data={})
    for name in ("Strict-Transport-Security", "Content-Security-Policy",
                 "X-Frame-Options"):
        report.add_finding("warn", "headers", f"Missing security header: {name}")
    assessment = assess(report)
    assert "headers_unhardened" in rule_ids(assessment)


def test_partial_headers_fuse_to_partial():
    report = VerificationReport(url="https://x.example.com/r", bank="cbe", data={})
    report.add_finding("warn", "headers", "Missing security header: Content-Security-Policy")
    assessment = assess(report)
    assert "headers_partial" in rule_ids(assessment)
    assert assessment.correlations[0].signals == ["Content-Security-Policy"]


# --------------------------------------------------------------- data patterns

def test_placeholder_values_flagged():
    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe",
        data={"customer_name": "TEST USER", "status": "SUCCESS"},
    )
    assessment = assess(report)
    assert "data_placeholders" in rule_ids(assessment)


def test_repeated_amounts_flagged_as_pattern():
    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe",
        data={
            "transferred_amount": "1000.00",
            "commission": "1000.00",
            "total_debited": "1000.00",
        },
    )
    assessment = assess(report)
    assert "data_repeated_amounts" in rule_ids(assessment)


def test_indicators_capture_cert_issuer():
    report = VerificationReport(url="https://apps.cbe.com.et:100/?id=FT123")
    report.add_finding(
        "info", "tls", "TLS 1.3 - issued by: GlobalSign Organization Validation CA"
    )
    assessment = assess(report)
    assert assessment.indicators["cert_issuer"] == (
        "GlobalSign Organization Validation CA"
    )


# ---------------------------------------------------------------- feedback

def test_feedback_rejected_lowers_risk():
    report = VerificationReport(
        url="https://dashensuperapp.ru/pay", bank="dashen",
        data={"status": "SUCCESS"},
    )
    report.add_finding(
        "warn", "phishing",
        "Host 'dashensuperapp.ru' closely resembles known bank domain "
        "'dashensuperapp.com' (similarity 77%); possible lookalike/"
        "phishing domain",
    )
    base = assess(report)
    adjusted = assess(report, feedback=(1, 5))
    assert adjusted.risk_score == base.risk_score - 10
    assert adjusted.adjustment == -10


def test_feedback_confirmed_raises_risk():
    report = VerificationReport(
        url="https://x.example.com/r", bank="cbe",
        data={"status": "SUCCESS"},
    )
    base = assess(report)
    adjusted = assess(report, feedback=(5, 1))
    assert adjusted.risk_score == base.risk_score + 5
    assert adjusted.adjustment == 5


def test_feedback_weak_mixed_no_change():
    report = VerificationReport(url="https://x.example.com/r", bank="cbe")
    adjusted = assess(report, feedback=(2, 2))
    assert adjusted.adjustment == 0
    assert adjusted.risk_score == 0


def test_feedback_never_raises_unreadable():
    report = VerificationReport(url="https://x.example.com/r", bank="cbe")
    adjusted = assess(report, feedback=(9, 0))
    assert adjusted.unreadable is True
    assert adjusted.risk_score == 0


# ---------------------------------------------------------------- pipeline

def test_unreadable_receipt_is_high_risk_and_red():
    report = VerificationReport(url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe")
    report.add_finding("info", "tls", "Certificate valid until 2030")
    assessment = assess(report)
    assert assessment.unreadable is True
    assert assessment.risk_level == "HIGH"
    assert assessment.risk_score == 0
    assert "receipt_unreadable" in rule_ids(assessment)
    assert "could not be read" in assessment.scenario.lower()
    assert assessment.indicators["receipt_readable"] is False


def test_audit_without_receipt_is_not_unreadable():
    report = VerificationReport(url="https://example.com")
    assessment = assess(report)
    assert assessment.unreadable is False
    assert assessment.indicators["receipt_readable"] is False

def test_run_verifiers_attaches_threat_assessment():
    report = VerificationReport(
        url="https://receipt.example.com/r", bank="cbe",
        data={"status": "SUCCESS"},
    )
    with mock.patch(
        "zebebgna.verifiers.tls.audit_tls", return_value=None
    ), mock.patch.object(
        __import__("zebebgna.fetch", fromlist=["fetcher"]).fetcher,
        "fetch_headers",
        side_effect=RuntimeError("offline"),
    ):
        run_verifiers(report)
    assert isinstance(report.threat, ThreatAssessment)
    assert report.threat.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
