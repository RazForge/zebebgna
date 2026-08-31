"""Tests for Phase B operational tooling: watch, backup, config (Tier 6)."""

import sys
from unittest import mock

import pytest

from zebebgna import history
from zebebgna.fusion import assess
from zebebgna.report import VerificationReport


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "checks.db"))
    history.clear()
    history.clear_threat_domains()
    yield
    history.clear()
    history.clear_threat_domains()


def _report(url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe"):
    report = VerificationReport(url=url, bank=bank, data={"status": "SUCCESS"})
    report.add_finding("warn", "headers", "Missing security header: CSP")
    report.threat = assess(report)
    return report


def _run_cli(argv):
    from zebebgna import cli

    with mock.patch.object(sys, "argv", ["zebebgna"] + argv):
        return cli.main()


def test_backup_export_import_roundtrip(db, capsys, tmp_path):
    history.record(_report())
    history.add_threat_domain("scam.et", "seen in telegram")
    dump = tmp_path / "backup.sql"

    assert _run_cli(["backup", "export", str(dump)]) == 0
    assert dump.exists()
    out = capsys.readouterr().out
    assert "Exported" in out

    history.clear()
    history.clear_threat_domains()
    assert history.list_checks() == []

    assert _run_cli(["backup", "import", str(dump)]) == 0
    checks = history.list_checks()
    assert len(checks) == 1
    assert checks[0]["url"] == "https://apps.cbe.com.et:100/?id=FT123"
    assert history.is_threat_domain("scam.et")


def test_config_show(db, capsys, monkeypatch):
    history.record(_report())
    monkeypatch.setenv("ZEBEBGNA_TELEGRAM_TOKEN", "sekret")
    assert _run_cli(["config", "show"]) == 0
    out = capsys.readouterr().out
    assert "Database:" in out
    assert "History checks: 1" in out
    assert "ZEBEBGNA_TELEGRAM_TOKEN: set" in out
    assert "sekret" not in out
    assert "ZEBEBGNA_LLM_API_KEY: not set" in out


def test_watch_runs_scheduled_checks(db, capsys):
    fake = mock.MagicMock(return_value=_report())
    with mock.patch("zebebgna.cli.verify_receipt", fake):
        with mock.patch("time.sleep") as sleep:
            code = _run_cli(
                ["watch", "cbe", "https://apps.cbe.com.et:100/?id=FT123",
                 "--every", "1", "--count", "3"]
            )
    assert code == 0
    assert fake.call_count == 3
    assert sleep.call_count == 2
    assert len(history.list_checks()) == 3
    out = capsys.readouterr().out
    assert out.count("[3]") == 1
    assert "threat=" in out


def test_watch_no_save(db, capsys):
    fake = mock.MagicMock(return_value=_report())
    with mock.patch("zebebgna.cli.verify_receipt", fake):
        with mock.patch("time.sleep"):
            code = _run_cli(
                ["watch", "cbe", "https://apps.cbe.com.et:100/?id=FT123",
                 "--count", "1", "--no-save"]
            )
    assert code == 0
    assert history.list_checks() == []


def test_watch_rejects_bad_every(db):
    assert _run_cli(
        ["watch", "cbe", "https://x/", "--every", "0"]
    ) == 1


def test_watch_handles_verify_errors(db, capsys):
    fake = mock.MagicMock(side_effect=RuntimeError("network down"))
    with mock.patch("zebebgna.cli.verify_receipt", fake):
        with mock.patch("time.sleep"):
            code = _run_cli(
                ["watch", "cbe", "https://x/", "--count", "2"]
            )
    assert code == 0
    out = capsys.readouterr().out
    assert "network down" in out