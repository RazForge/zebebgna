import os
import sqlite3

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


def test_db_path_bare_filename(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ZEBEBGNA_DB", "checks.db")
    check_id = history.record(_report())
    assert history.get_check(check_id)["id"] == check_id


# -- web accounts -------------------------------------------------------------


def test_users_add_verify_remove(db):
    assert history.has_users() is False
    assert history.add_user("Alice", "correct horse") is True
    # taken (usernames are case-insensitive)
    assert history.add_user("alice", "other") is False
    assert history.has_users() is True
    assert [u["username"] for u in history.list_users()] == ["alice"]
    assert history.verify_user("Alice", "correct horse") is True
    assert history.verify_user("alice", "wrong") is False
    assert history.verify_user("nobody", "wrong") is False
    assert history.remove_user("Alice") == 1
    assert history.remove_user("alice") == 0
    assert history.has_users() is False


def test_add_user_rejects_empty(db):
    assert history.add_user("", "pw") is False
    assert history.add_user("bob", "") is False
    assert history.has_users() is False


def test_record_owner_scope_and_share_tokens(db):
    alice_id = history.record(_report(), owner="alice")
    bob_id = history.record(_report(), owner="bob")
    assert len(history.list_checks()) == 2

    alice_rows = history.list_checks(owner="alice")
    assert [r["id"] for r in alice_rows] == [alice_id]

    alice_token = history.get_check(alice_id)["share_token"]
    bob_token = history.get_check(bob_id)["share_token"]
    assert alice_token and bob_token and alice_token != bob_token
    assert history.get_check_by_token(alice_token)["id"] == alice_id
    assert history.get_check_by_token("not-a-token") is None
    assert history.get_check_by_token("") is None


def test_clear_scoped_to_owner(db):
    history.record(_report(), owner="alice")
    history.record(_report(), owner="alice")
    history.record(_report(), owner="bob")
    assert history.clear(owner="alice") == 2
    remaining = history.list_checks()
    assert len(remaining) == 1
    assert remaining[0]["owner"] == "bob"
    assert history.clear() == 1


def test_migrate_old_database(tmp_path, monkeypatch):
    # Simulate a database created before owners/share tokens existed.
    path = tmp_path / "old.db"
    monkeypatch.setenv("ZEBEBGNA_DB", str(path))
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            url TEXT NOT NULL,
            registered_domain TEXT,
            bank TEXT,
            score INTEGER,
            status TEXT,
            risk_level TEXT,
            feedback INTEGER,
            report_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO checks (ts, url, registered_domain, bank, score,"
        " status, risk_level, feedback, report_json) VALUES"
        " ('2026-01-01T00:00:00', 'https://x.example.com/r', 'example.com',"
        " 'cbe', 100, 'PASS', 'LOW', NULL, '{}')"
    )
    conn.commit()
    conn.close()

    rows = history.list_checks()
    assert len(rows) == 1
    assert rows[0]["owner"] is None
    assert rows[0]["share_token"]  # backfilled during migration

    new_id = history.record(_report(), owner="alice")
    assert history.get_check(new_id)["owner"] == "alice"
