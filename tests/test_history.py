import os

import pytest

from zebebgna import history
from zebebgna.fusion import ThreatAssessment, assess
from zebebgna.report import VerificationReport


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "checks.db"))
    history.clear()
    yield
    history.clear()


def _report(url="https://receipt.dashensuperapp.com/r", bank="dashen"):
    report = VerificationReport(url=url, bank=bank, data={"status": "SUCCESS"})
    report.threat = assess(report)
    return report


def test_record_and_list(db):
    check_id = history.record(_report())
    rows = history.list_checks()
    assert len(rows) == 1
    assert rows[0]["id"] == check_id
    assert rows[0]["bank"] == "dashen"
    assert rows[0]["score"] == 100
    assert rows[0]["status"] == "PASS"
    assert rows[0]["risk_level"] == "LOW"
    assert rows[0]["registered_domain"] == "dashensuperapp.com"


def test_get_check_roundtrip(db):
    check_id = history.record(_report())
    report = history.report_from_record(history.get_check(check_id))
    assert isinstance(report.threat, ThreatAssessment)
    assert report.threat.risk_level == "LOW"
    assert report.data == {"status": "SUCCESS"}


def test_feedback_aggregation(db):
    history.record(_report())
    history.record(_report())
    history.record(_report("https://x.example.com/r", "cbe"))
    dashen_checks = [
        c for c in history.list_checks()
        if c["registered_domain"] == "dashensuperapp.com"
    ]
    history.record_feedback(dashen_checks[0]["id"], True)
    history.record_feedback(dashen_checks[1]["id"], False)
    assert history.domain_feedback("dashensuperapp.com") == (1, 1)
    assert history.domain_feedback("example.com") == (0, 0)


def test_clear(db):
    history.record(_report())
    assert history.clear() == 1
    assert history.list_checks() == []


def test_db_path_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "custom.db"))
    assert history._db_path().endswith("custom.db")
