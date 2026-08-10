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

_THREAT_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_domains (
    domain TEXT PRIMARY KEY,
    reason TEXT,
    ts TEXT NOT NULL,
    source TEXT
);
"""


def _db_path():
    return os.environ.get(
        "ZEBEBGNA_DB",
        os.path.join(os.path.expanduser("~"), ".zebebgna", "checks.db"),
    )


def db_path():
    """Absolute path of the local history database."""
    return os.path.abspath(_db_path())


def export_sql(path):
    """Dump the whole database (checks + threat domains) to ``path``.

    Returns the number of SQL statements written.
    """
    conn = _connect()
    try:
        sql = "\n".join(conn.iterdump())
    finally:
        conn.close()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(sql + "\n")
    return sql.count("\n")


def import_sql(path):
    """Restore a database from an ``export_sql`` dump.

    The existing local checks and threat domains are replaced by the
    dump content (restore semantics). Returns the number of SQL
    statements executed.
    """
    with open(path, "r", encoding="utf-8") as fh:
        sql = fh.read()
    conn = _connect()
    try:
        conn.execute("DROP TABLE IF EXISTS checks")
        conn.execute("DROP TABLE IF EXISTS threat_domains")
        cur = conn.executescript(sql)
        conn.commit()
    finally:
        conn.close()
    return cur.rowcount


def _connect():
    path = _db_path()
    # ``dirname`` of a bare filename is "" and makedirs would fail; resolve
    # to an absolute path first so a plain "checks.db" works too.
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    conn.executescript(_THREAT_SCHEMA)
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
    ai_review = payload.get("ai_review")
    if ai_review:
        from zebebgna.llm import AIVerdict

        report.ai_review = AIVerdict.from_dict(ai_review)
    return report


# -- community phishing-domain database ---------------------------------------

def add_threat_domain(domain, reason=None, source=None):
    """Record a registered domain as community-reported phishing.

    Returns True when newly added, False when already known.
    """
    domain = (domain or "").strip().lower().lstrip("*.").lstrip(".")
    if not domain:
        return False
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO threat_domains (domain, reason, ts, source)"
            " VALUES (?, ?, ?, ?)",
            (domain, reason, datetime.now().isoformat(timespec="seconds"),
             source),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def remove_threat_domain(domain):
    """Remove a domain from the threat database. Returns rows removed."""
    domain = (domain or "").strip().lower()
    conn = _connect()
    try:
        cur = conn.execute(
            "DELETE FROM threat_domains WHERE domain = ?", (domain,)
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def list_threat_domains():
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM threat_domains ORDER BY ts DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def is_threat_domain(registered_domain):
    """True when a registered domain sits in the community threat DB."""
    if not registered_domain:
        return False
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM threat_domains WHERE domain = ?",
            (str(registered_domain).lower(),),
        ).fetchone()
        return row is not None
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def clear_threat_domains():
    """Delete all community-reported domains. Returns the number removed."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM threat_domains")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
