"""Tests for the community phishing-domain database (Tier 4c)."""

import sys
from unittest import mock

import pytest

from zebebgna import history


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "checks.db"))
    history.clear()
    history.clear_threat_domains()
    yield
    history.clear()
    history.clear_threat_domains()


def _run_cli(argv):
    from zebebgna import cli

    with mock.patch.object(sys, "argv", ["zebebgna"] + argv):
        return cli.main()


def test_add_list_remove(db):
    assert history.add_threat_domain("evil-bank-eth.com", "fake receipt link")
    assert not history.add_threat_domain("evil-bank-eth.com")
    assert history.is_threat_domain("evil-bank-eth.com")
    rows = history.list_threat_domains()
    assert len(rows) == 1
    assert rows[0]["domain"] == "evil-bank-eth.com"
    assert rows[0]["reason"] == "fake receipt link"

    assert history.remove_threat_domain("evil-bank-eth.com") == 1
    assert not history.is_threat_domain("evil-bank-eth.com")
    assert history.list_threat_domains() == []


def test_add_normalizes_and_rejects_empty(db):
    assert history.add_threat_domain("  Evil-Bank.eth.com ")
    assert history.is_threat_domain("evil-bank.eth.com")
    assert not history.add_threat_domain("")
    assert not history.add_threat_domain(None)


def test_fusion_raises_error_correlation_for_known_domain(db):
    from zebebgna.fusion import assess
    from zebebgna.report import VerificationReport

    history.add_threat_domain("phish-bank.et", "scam")
    report = VerificationReport(
        url="https://phish-bank.et/receipt/1",
        bank="cbe",
        data={"reference_no": "FT123", "payment_date": "01/15/2024",
              "total_debited": "100.00"},
    )
    threat = assess(report)
    assert any(c.rule_id == "community_reported" for c in threat.correlations)
    assert threat.risk_score >= 20


def test_fusion_unknown_domain_no_correlation(db):
    from zebebgna.fusion import assess
    from zebebgna.report import VerificationReport

    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe",
        data={"reference_no": "FT123"},
    )
    threat = assess(report)
    assert not any(c.rule_id == "community_reported"
                   for c in threat.correlations)


def test_cli_threatdb_commands(db):
    assert _run_cli(["threatdb", "add", "scam.et", "seen in telegram"]) == 0
    assert history.is_threat_domain("scam.et")
    assert _run_cli(["threatdb", "list"]) == 0
    assert _run_cli(["threatdb", "remove", "scam.et"]) == 0
    assert not history.is_threat_domain("scam.et")
    assert _run_cli(["threatdb", "add"]) == 1


def test_cli_feedback_report_phish(db):
    from zebebgna.report import VerificationReport

    report = VerificationReport(
        url="https://scam-bank.et/receipt/x", bank="cbe",
        data={"reference_no": "FT123"},
    )
    report.add_finding("critical", "integrity", "amount mismatch")
    check_id = history.record(report)

    assert _run_cli(["feedback", str(check_id), "--wrong",
                     "--report-phish", "confirmed scam"]) == 0
    assert history.is_threat_domain("scam-bank.et")