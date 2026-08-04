"""Persistence and feedback loop for verification history.

Every check can be stored in a local SQLite database so users can:

- review past checks (history),
- correct the verdict (feedback), which feeds back into the fusion
  engine's risk score for the same domain,
- clear the history.

The database location is taken from the ``ZEBEBGNA_DB`` environment
variable and defaults to ``~/.zebebgna/checks.db``.
"""

import json
import os
import sqlite3
from datetime import datetime
from urllib.parse import urlparse

from zebebgna.verifiers import phishing

FEEDBACK_CONFIRMED = 1
FEEDBACK_REJECTED = 0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
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
);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);
"""


def _db_path():
    return os.environ.get(
        "ZEBEBGNA_DB",
        os.path.join(os.path.expanduser("~"), ".zebebgna", "checks.db"),
    )


def _connect():
    path = _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    conn.row_factory = sqlite3.Row
    return conn


def _registered_domain(url):
    host = (urlparse(url).hostname or "").lower()
    return phishing._registered_domain(host) if host else None


def record(report):
    """Persist a VerificationReport and return its new check id."""
    threat = report.threat
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO checks (ts, url, registered_domain, bank, score,
                                status, risk_level, feedback, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                datetime.now().isoformat(timespec="seconds"),
                report.url,
                _registered_domain(report.url),
                report.bank,
                report.score,
                report.status,
                threat.risk_level if threat else None,
                json.dumps(report.to_dict()),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_checks(limit=50):
    """Return the most recent checks as dicts (newest first)."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM checks ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_check(check_id):
    """Return a single check by id, or None."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM checks WHERE id = ?", (check_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def record_feedback(check_id, correct):
    """Mark a past check as correct (True) or incorrect (False)."""
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE checks SET feedback = ? WHERE id = ?",
            (FEEDBACK_CONFIRMED if correct else FEEDBACK_REJECTED, check_id),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def clear():
    """Delete all stored checks. Returns the number removed."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM checks")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def domain_feedback(registered_domain):
    """Aggregate user feedback for a domain.

    Returns a ``(confirmed, rejected)`` pair used by the fusion engine to
    nudge risk scores for previously reviewed domains.
    """
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN feedback = ? THEN 1 ELSE 0 END) AS confirmed,
                SUM(CASE WHEN feedback = ? THEN 1 ELSE 0 END) AS rejected
            FROM checks
            WHERE registered_domain = ?
            """,
            (FEEDBACK_CONFIRMED, FEEDBACK_REJECTED, registered_domain),
        ).fetchone()
        return (row["confirmed"] or 0, row["rejected"] or 0)
    finally:
        conn.close()


def report_from_record(check):
    """Rebuild a VerificationReport (with threat) from a stored check dict."""
    payload = json.loads(check["report_json"])

    from zebebgna.fusion import ThreatAssessment
    from zebebgna.report import VerificationReport

    report = VerificationReport(
        url=payload["url"], bank=payload["bank"], data=payload["extracted_data"]
    )
    for finding in payload["findings"]:
        report.add_finding(
            finding["severity"], finding["category"], finding["message"]
        )
    if payload.get("threat"):
        report.threat = ThreatAssessment.from_dict(payload["threat"])
    return report
