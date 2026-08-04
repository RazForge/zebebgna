import sys
from unittest import mock

import pytest

from zebebgna import history
from zebebgna.report import VerificationReport


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "checks.db"))
    history.clear()
    yield
    history.clear()


def _run_cli(argv):
    from zebebgna import cli

    with mock.patch.object(sys, "argv", ["zebebgna"] + argv):
        return cli.main()


def _fake_report(url):
    report = VerificationReport(url=url, bank="cbe", data={"status": "SUCCESS"})
    report.add_finding("info", "tls", "Certificate valid until 2030")
    return report


def test_batch_verifies_and_saves(db):
    with mock.patch(
        "zebebgna.verify_receipt",
        side_effect=lambda *a, **k: _fake_report(a[1]),
    ):
        code = _run_cli(
            ["batch", "cbe", "https://a.example.com/r1", "https://a.example.com/r2"]
        )
    assert code == 0
    assert len(history.list_checks()) == 2


def test_batch_reads_file(db, tmp_path):
    urls_file = tmp_path / "urls.txt"
    urls_file.write_text(
        "# comment line\nhttps://a.example.com/r1\nhttps://a.example.com/r2\n",
        encoding="utf-8",
    )
    with mock.patch(
        "zebebgna.verify_receipt",
        side_effect=lambda *a, **k: _fake_report(a[1]),
    ):
        code = _run_cli(["batch", "cbe", "--file", str(urls_file)])
    assert code == 0
    assert len(history.list_checks()) == 2


def test_history_and_feedback_commands(db):
    with mock.patch(
        "zebebgna.verify_receipt",
        side_effect=lambda *a, **k: _fake_report(a[1]),
    ):
        _run_cli(["verify", "cbe", "https://apps.cbe.com.et:100/?id=FT123"])
    check_id = history.list_checks()[0]["id"]

    code = _run_cli(["history"])
    assert code == 0
    code = _run_cli(["feedback", str(check_id), "--correct"])
    assert code == 0
    assert history.get_check(check_id)["feedback"] == 1

    code = _run_cli(["history", "--clear"])
    assert code == 0
    assert history.list_checks() == []


def test_feedback_requires_flag(db):
    assert _run_cli(["feedback", "1"]) == 1


def test_verify_unknown_bank(db):
    with pytest.raises(SystemExit):
        _run_cli(["verify", "nope", "https://example.com/r"])
