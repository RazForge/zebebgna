"""Persistence and feedback loop for verification history.

Every check can be stored in a local SQLite database so users can:

- review past checks (history),
- correct the verdict (feedback), which feeds back into the fusion
  engine's risk score for the same domain,
- clear the history.

The database location is taken from the ``ZEBEBGNA_DB`` environment
variable and defaults to ``~/.zebebgna/checks.db``.
"""

import hashlib
import hmac
import json
import os
import secrets
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
    report_json TEXT NOT NULL,
    owner TEXT,
    share_token TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created TEXT NOT NULL
);
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
    """Dump the whole database (checks, threat domains, accounts) to ``path``.

    Returns the number of SQL statements written.
    """
    conn = _connect()
    try:
        sql = "\n".join(conn.iterdump())
    finally:
        conn.close()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(sql + "\n")
    return sql.count(";")


def import_sql(path):
    """Restore a database from an ``export_sql`` dump.

    The existing local checks, threat domains, and web accounts are
    replaced by the dump content (restore semantics). Returns the
    number of SQL statements executed.
    """
    with open(path, "r", encoding="utf-8") as fh:
        sql = fh.read()
    conn = _connect()
    try:
        conn.execute("DROP TABLE IF EXISTS checks")
        conn.execute("DROP TABLE IF EXISTS threat_domains")
        conn.execute("DROP TABLE IF EXISTS users")
        conn.executescript(sql)
        conn.commit()
    finally:
        conn.close()
    return sql.count(";")


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
    _migrate(conn)
    return conn


def _migrate(conn):
    """Bring databases created by older releases up to the current schema.

    ``CREATE TABLE IF NOT EXISTS`` leaves existing tables untouched, so
    columns added in later releases (``owner``, ``share_token``) must be
    added explicitly. Rows stored before share tokens existed get a
    fresh unguessable token.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(checks)")}
    if "owner" not in columns:
        conn.execute("ALTER TABLE checks ADD COLUMN owner TEXT")
    if "share_token" not in columns:
        conn.execute("ALTER TABLE checks ADD COLUMN share_token TEXT")
    missing = conn.execute(
        "SELECT id FROM checks WHERE share_token IS NULL"
    ).fetchall()
    for (check_id,) in missing:
        conn.execute(
            "UPDATE checks SET share_token = ? WHERE id = ?",
            (secrets.token_urlsafe(16), check_id),
        )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_checks_share_token "
        "ON checks(share_token)"
    )
    conn.commit()


def _registered_domain(url):
    host = (urlparse(url).hostname or "").lower()
    return phishing._registered_domain(host) if host else None


def record(report, owner=None):
    """Persist a VerificationReport and return its new check id.

    ``owner`` is the web account that ran the check (None in CLI/local
    mode). Every row also gets an unguessable share token so archived
    reports can be shared without exposing sequential check ids.
    """
    threat = report.threat
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO checks (ts, url, registered_domain, bank, score,
                                status, risk_level, feedback, report_json,
                                owner, share_token)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
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
                owner,
                secrets.token_urlsafe(16),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_checks(limit=50, owner=None):
    """Return the most recent checks as dicts (newest first).

    ``owner`` filters to a single web account; None returns every row
    (CLI/local mode).
    """
    conn = _connect()
    try:
        if owner is None:
            rows = conn.execute(
                "SELECT * FROM checks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM checks WHERE owner = ? ORDER BY id DESC "
                "LIMIT ?",
                (owner, limit),
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


def get_check_by_token(share_token):
    """Return a single check by share token, or None.

    Share links use these random tokens instead of the sequential check
    id so an archived report cannot be found by counting up.
    """
    if not share_token:
        return None
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM checks WHERE share_token = ?", (share_token,)
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


def clear(owner=None):
    """Delete stored checks. Returns the number removed.

    ``owner`` restricts the deletion to one web account's checks; None
    clears everything (CLI/local mode).
    """
    conn = _connect()
    try:
        if owner is None:
            cur = conn.execute("DELETE FROM checks")
        else:
            cur = conn.execute(
                "DELETE FROM checks WHERE owner = ?", (owner,)
            )
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


# -- web accounts --------------------------------------------------------------

_PBKDF2_ITERATIONS = 200_000

_dummy_password_hash = None


def _hash_password(password, salt=None, iterations=_PBKDF2_ITERATIONS):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def _verify_password(password, stored):
    try:
        algorithm, iterations, salt, digest = stored.split("$")
        iterations = int(iterations)
        salt_bytes = bytes.fromhex(salt)
        expected = bytes.fromhex(digest)
    except (AttributeError, ValueError):
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, iterations
    )
    return hmac.compare_digest(candidate, expected)


def _burn_password_check(password):
    """Run one PBKDF2 verification for an unknown user.

    Keeps the response time of "unknown user" and "wrong password"
    comparable so accounts cannot be enumerated by timing.
    """
    global _dummy_password_hash
    if _dummy_password_hash is None:
        _dummy_password_hash = _hash_password(secrets.token_hex(16))
    return _verify_password(password or "", _dummy_password_hash)


def add_user(username, password):
    """Create a web account. Returns False when the name is taken/invalid."""
    username = (username or "").strip().lower()
    password = password or ""
    if not username or not password:
        return False
    conn = _connect()
    try:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, created) "
                "VALUES (?, ?, ?)",
                (username, _hash_password(password),
                 datetime.now().isoformat(timespec="seconds")),
            )
        except sqlite3.IntegrityError:
            return False
        conn.commit()
        return True
    finally:
        conn.close()


def verify_user(username, password):
    """True when the account exists and the password matches."""
    username = (username or "").strip().lower()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        _burn_password_check(password)
        return False
    return _verify_password(password or "", row["password_hash"])


def has_users():
    """True when at least one web account exists."""
    conn = _connect()
    try:
        row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return row is not None
    finally:
        conn.close()


def list_users():
    """Return the web accounts (name + creation date), sorted by name."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT username, created FROM users ORDER BY username"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def remove_user(username):
    """Delete a web account. Returns the number of rows removed."""
    username = (username or "").strip().lower()
    conn = _connect()
    try:
        cur = conn.execute(
            "DELETE FROM users WHERE username = ?", (username,)
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# -- community phishing-domain database ---------------------------------------

def _normalize_domain(domain):
    """Lowercase, trim, and strip a leading ``*.``/``.`` wildcard prefix."""
    return (domain or "").strip().lower().lstrip("*.").lstrip(".")


def add_threat_domain(domain, reason=None, source=None):
    """Record a registered domain as community-reported phishing.

    Returns True when newly added, False when already known.
    """
    domain = _normalize_domain(domain)
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
    """Remove a domain from the threat database. Returns rows removed.

    Uses the same normalization as :func:`add_threat_domain`, so a domain
    added as ``*.example.com`` can be removed with the same spelling.
    """
    domain = _normalize_domain(domain)
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
