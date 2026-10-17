import pytest
from unittest import mock

import webapp
from zebebgna import history
from zebebgna.fusion import assess
from zebebgna.report import VerificationReport


@pytest.fixture
def client():
    webapp.app.config["TESTING"] = True
    return webapp.app.test_client()


def test_index_renders_form(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Zebebgna" in resp.data
    assert b"name=\"bank\"" in resp.data
    assert b"Verify receipt" in resp.data


def test_verify_requires_input(client):
    resp = client.post("/verify", data={"bank": "cbe", "url_or_id": ""})
    assert resp.status_code == 200
    assert b"Paste a receipt link" in resp.data


def test_verify_rejects_non_url(client):
    resp = client.post("/verify", data={"bank": "cbe", "url_or_id": "abc123"})
    assert resp.status_code == 200
    assert b"does not look like a valid receipt link" in resp.data


def test_verify_renders_report(client, db):
    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT25211G11JQ21827223",
        bank="cbe",
        data={"customer_name": "TEST USER", "status": "SUCCESS"},
    )
    report.add_finding("warn", "headers", "Missing security header: CSP")
    report.add_finding("warn", "headers", "Missing security header: HSTS")
    report.add_finding("info", "tls", "Certificate valid until 2030")

    with mock.patch.object(webapp, "verify_receipt", return_value=report) as vr:
        resp = client.post(
            "/verify",
            data={
                "bank": "cbe",
                "url_or_id": "https://apps.cbe.com.et:100/?id=FT25211G11JQ21827223",
            },
        )

    vr.assert_called_once()
    assert resp.status_code == 200
    assert b"Verification Result" in resp.data
    assert b"Needs review" in resp.data
    assert b"TEST USER" in resp.data
    assert b"Missing security header: CSP" in resp.data


def test_verify_accepts_uppercase_scheme_url(client, db):
    # URL schemes are case-insensitive (RFC 3986): an uppercase-scheme
    # receipt link must not be rejected as invalid.
    report = VerificationReport(
        url="HTTPS://apps.cbe.com.et:100/?id=FT25211G11JQ21827223",
        bank="cbe",
        data={"customer_name": "TEST USER", "status": "SUCCESS"},
    )
    with mock.patch.object(webapp, "verify_receipt", return_value=report) as vr:
        resp = client.post(
            "/verify",
            data={
                "bank": "cbe",
                "url_or_id": "HTTPS://apps.cbe.com.et:100/?id=FT25211G11JQ21827223",
            },
        )
    vr.assert_called_once()
    assert resp.status_code == 200
    assert b"does not look like a valid receipt link" not in resp.data


def test_normalize_url_keeps_uppercase_tele_url():
    url = "HTTPS://transactioninfo.ethiotelecom.et/receipt/ABC123"
    assert webapp._normalize_url("tele", url) == url


def test_verify_renders_fail_verdict_for_critical(client, db):
    report = VerificationReport(
        url="https://x.example.com/r", bank="cbe", data={}
    )
    report.add_finding("critical", "tls", "Certificate is EXPIRED")

    with mock.patch.object(webapp, "verify_receipt", return_value=report):
        resp = client.post(
            "/verify",
            data={"bank": "cbe", "url_or_id": "https://x.example.com/r"},
        )
    assert resp.status_code == 200
    assert b"Problem found" in resp.data


def test_verify_renders_threat_card(client, db):
    report = VerificationReport(
        url="https://x.example.com/r", bank="cbe",
        data={"status": "SUCCESS"},
    )
    report.add_finding(
        "error", "integrity",
        "CBE total debited mismatch: 1000.00 sums to 1000.00 but receipt "
        "states 999.00",
    )
    report.threat = assess(report)

    with mock.patch.object(webapp, "verify_receipt", return_value=report):
        resp = client.post(
            "/verify",
            data={"bank": "cbe", "url_or_id": "https://x.example.com/r"},
        )
    assert resp.status_code == 200
    assert b"Threat intelligence" in resp.data
    assert b"Receipt amounts do not reconcile" in resp.data
    assert b"sev-red" in resp.data
    assert b">HIGH<" in resp.data


def test_verify_hides_weak_correlations(client, db):
    report = VerificationReport(
        url="https://x.example.com/r", bank="cbe",
        data={"status": "SUCCESS"},
    )
    report.add_finding(
        "warn", "headers", "Missing security header: Strict-Transport-Security"
    )
    report.threat = assess(report)

    with mock.patch.object(webapp, "verify_receipt", return_value=report):
        resp = client.post(
            "/verify",
            data={"bank": "cbe", "url_or_id": "https://x.example.com/r"},
        )
    assert resp.status_code == 200
    assert b"Threat intelligence" in resp.data
    assert b"No correlated threat signals" in resp.data
    assert b"Weak transport hardening" not in resp.data


def test_verify_renders_red_pill_for_unreadable_receipt(client, db):
    report = VerificationReport(
        url="https://x.example.com/r", bank="cbe", data={}
    )
    report.threat = assess(report)

    with mock.patch.object(webapp, "verify_receipt", return_value=report):
        resp = client.post(
            "/verify",
            data={"bank": "cbe", "url_or_id": "https://x.example.com/r"},
        )
    assert resp.status_code == 200
    assert b"unreadable" in resp.data
    assert b"could not be read" in resp.data
    assert b"left: 75%" in resp.data


def test_verify_hides_checks_when_no_issues(client, db):
    report = VerificationReport(
        url="https://transactioninfo.ethiotelecom.et/receipt/DH19FZOZYV",
        bank="tele",
        data={"status": "SUCCESS", "total_paid": "100.00"},
    )
    report.add_finding(
        "info", "tls",
        "Certificate valid until Mar 8 16:46:15 2027 GMT (216 days remaining)",
    )
    report.add_finding("info", "tls", "TLS TLSv1.2 - issued by: GlobalSign nv-sa")
    for name in ("Strict-Transport-Security", "Content-Security-Policy",
                 "X-Frame-Options"):
        report.add_finding("info", "headers", f"Missing security header: {name}")

    with mock.patch.object(webapp, "verify_receipt", return_value=report):
        resp = client.post(
            "/verify",
            data={
                "bank": "tele",
                "url_or_id": "https://transactioninfo.ethiotelecom.et/receipt/DH19FZOZYV",
            },
        )

    assert resp.status_code == 200
    assert b"Checks performed" not in resp.data
    assert b"Receipt details" in resp.data


def test_verify_summarizes_info_findings_when_issues_exist(client, db):
    report = VerificationReport(
        url="https://transactioninfo.ethiotelecom.et/receipt/DH19FZOZYV",
        bank="tele",
        data={"status": "SUCCESS", "total_paid": "100.00"},
    )
    report.add_finding(
        "info", "tls",
        "Certificate valid until Mar 8 16:46:15 2027 GMT (216 days remaining)",
    )
    report.add_finding("info", "tls", "TLS TLSv1.2 - issued by: GlobalSign nv-sa")
    for name in ("Strict-Transport-Security", "Content-Security-Policy",
                 "X-Frame-Options"):
        report.add_finding("info", "headers", f"Missing security header: {name}")
    report.add_finding("warn", "integrity", "Receipt data is incomplete")

    with mock.patch.object(webapp, "verify_receipt", return_value=report):
        resp = client.post(
            "/verify",
            data={
                "bank": "tele",
                "url_or_id": "https://transactioninfo.ethiotelecom.et/receipt/DH19FZOZYV",
            },
        )

    assert resp.status_code == 200
    assert b"Checks performed" in resp.data
    assert b"TLS &amp; certificate" in resp.data
    assert b"3 missing: HSTS, CSP, X-Frame-Options" in resp.data
    assert b"Receipt data is incomplete" in resp.data
    assert b"Missing security header: Strict-Transport-Security" not in resp.data


def test_host_allowlist_blocks_unknown(client, monkeypatch):
    monkeypatch.setenv("zebebgna_ALLOWED_HOSTS", "apps.cbe.com.et")
    with mock.patch.object(webapp, "ALLOWED_HOSTS", {"apps.cbe.com.et"}):
        resp = client.post(
            "/verify",
            data={
                "bank": "cbe",
                "url_or_id": "https://evil.example.com/receipt/1",
            },
        )
    assert resp.status_code == 200
    assert b"not in the allowed list" in resp.data


# ------------------------------------------------------------------ history


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "checks.db"))
    history.clear()
    yield
    history.clear()


def _report(url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe"):
    report = VerificationReport(url=url, bank=bank, data={"status": "SUCCESS"})
    report.add_finding("info", "tls", "Certificate valid until 2030")
    report.threat = assess(report)
    return report


def test_verify_saves_to_history(client, db):
    with mock.patch.object(webapp, "verify_receipt", return_value=_report()):
        resp = client.post(
            "/verify",
            data={"bank": "cbe", "url_or_id": "https://apps.cbe.com.et:100/?id=FT123"},
        )
    assert resp.status_code == 200
    assert len(history.list_checks()) == 1


def test_history_page_lists_checks(client, db):
    check_id = history.record(_report())
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"History" in resp.data
    assert b"apps.cbe.com.et" in resp.data
    assert b"View" in resp.data


def test_history_view_renders_report(client, db):
    check_id = history.record(_report())
    resp = client.get(f"/history/{check_id}")
    assert resp.status_code == 200
    assert b"Verification Result" in resp.data
    assert b"apps.cbe.com.et" in resp.data


def test_history_feedback_post(client, db):
    check_id = history.record(_report())
    resp = client.post(
        f"/history/{check_id}/feedback", data={"ok": "1"}
    )
    assert resp.status_code == 302
    assert history.get_check(check_id)["feedback"] == 1
    assert history.domain_feedback("cbe.com.et") == (1, 0)


def test_history_missing_check(client, db):
    resp = client.get("/history/99999")
    assert resp.status_code == 200
    assert b"No stored check" in resp.data


def test_verify_page_offers_share_link(client, db):
    with mock.patch.object(webapp, "verify_receipt", return_value=_report()):
        resp = client.post(
            "/verify",
            data={"bank": "cbe",
                  "url_or_id": "https://apps.cbe.com.et:100/?id=FT123"},
        )
    assert resp.status_code == 200
    token = history.list_checks()[0]["share_token"]
    assert f"/share/{token}".encode() in resp.data


def test_share_view_renders_archived_report(client, db):
    check_id = history.record(_report())
    token = history.get_check(check_id)["share_token"]
    resp = client.get(f"/share/{token}")
    assert resp.status_code == 200
    assert b"Verification Result" in resp.data
    assert b"archived report" in resp.data


def test_share_view_rejects_sequential_id(client, db):
    # Share links must use the unguessable token, never the check id.
    check_id = history.record(_report())
    assert history.get_check(check_id)["share_token"] != str(check_id)
    resp = client.get(f"/share/{check_id}")
    assert b"No stored check" in resp.data


def test_share_view_missing_check(client, db):
    resp = client.get("/share/99999")
    assert resp.status_code == 200
    assert b"No stored check" in resp.data


def test_history_clear_button(client, db):
    history.record(_report())
    assert len(history.list_checks()) == 1
    resp = client.post("/history/clear")
    assert resp.status_code == 302
    assert history.list_checks() == []


def test_history_page_shows_clear_button(client, db):
    history.record(_report())
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"Clear all" in resp.data


# ------------------------------------------------------------------- accounts


@pytest.fixture
def auth(client, db):
    webapp._login_failures.clear()
    history.add_user("alice", "alice-pw")
    yield
    webapp._login_failures.clear()
    history.remove_user("alice")


def _login(client, username="alice", password="alice-pw"):
    return client.post(
        "/login", data={"username": username, "password": password}
    )


def test_login_page_redirects_home_without_accounts(client, db):
    resp = client.get("/login")
    assert resp.status_code == 302


def test_auth_redirects_anonymous_to_login(client, auth):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]
    resp = client.get("/history")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_flow(client, auth):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Sign in" in resp.data

    resp = _login(client, password="wrong")
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data

    resp = _login(client)
    assert resp.status_code == 302
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Sign out (alice)" in resp.data

    resp = client.post("/logout")
    assert resp.status_code == 302
    assert client.get("/").status_code == 302


def test_login_next_param_cannot_leave_site(client, auth):
    resp = client.post(
        "/login?next=https://evil.example.com",
        data={"username": "alice", "password": "alice-pw"},
    )
    assert resp.status_code == 302
    assert "evil.example.com" not in resp.headers["Location"]


def test_history_scoped_to_logged_in_user(client, auth):
    history.add_user("bob", "bob-pw")
    alice_id = history.record(
        _report(url="https://a.example.com/r"), owner="alice"
    )
    bob_id = history.record(
        _report(url="https://b.example.com/r"), owner="bob"
    )

    assert _login(client).status_code == 302
    resp = client.get("/history")
    assert b"a.example.com" in resp.data
    assert b"b.example.com" not in resp.data

    assert client.get(f"/history/{alice_id}").status_code == 200
    assert client.get(f"/history/{bob_id}").status_code == 403

    resp = client.post(f"/history/{bob_id}/feedback", data={"ok": "1"})
    assert resp.status_code == 403
    assert history.get_check(bob_id)["feedback"] is None

    # Feedback on the user's own check still works.
    resp = client.post(f"/history/{alice_id}/feedback", data={"ok": "1"})
    assert resp.status_code == 302
    assert history.get_check(alice_id)["feedback"] == 1

    history.remove_user("bob")


def test_verify_records_owner_and_share_token(client, auth):
    assert _login(client).status_code == 302
    with mock.patch.object(webapp, "verify_receipt", return_value=_report()):
        resp = client.post(
            "/verify",
            data={"bank": "cbe",
                  "url_or_id": "https://apps.cbe.com.et:100/?id=FT123"},
        )
    assert resp.status_code == 200
    rows = history.list_checks()
    assert len(rows) == 1
    assert rows[0]["owner"] == "alice"
    assert f"/share/{rows[0]['share_token']}".encode() in resp.data


def test_share_link_is_public_even_with_accounts(client, auth):
    check_id = history.record(_report(), owner="alice")
    token = history.get_check(check_id)["share_token"]
    anonymous = webapp.app.test_client()
    resp = anonymous.get(f"/share/{token}")
    assert resp.status_code == 200
    assert b"archived report" in resp.data


def test_login_rate_limit_blocks_brute_force(client, auth):
    for _ in range(10):
        _login(client, password="wrong")
    resp = _login(client)  # correct password, but the door is shut
    assert b"Too many failed login attempts" in resp.data


def test_session_secret_persists_across_restarts(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "checks.db"))
    monkeypatch.delenv("ZEBEBGNA_SECRET_KEY", raising=False)
    first = webapp._load_or_create_secret()
    second = webapp._load_or_create_secret()
    assert first == second
    secret_file = tmp_path / "secret_key"
    assert secret_file.read_text(encoding="utf-8").strip() == first
    # The key must not be readable by other local users.
    assert (secret_file.stat().st_mode & 0o777) == 0o600


def test_session_secret_env_var_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEBEBGNA_DB", str(tmp_path / "checks.db"))
    monkeypatch.setenv("ZEBEBGNA_SECRET_KEY", "from-env")
    assert webapp._load_or_create_secret() == "from-env"
    assert not (tmp_path / "secret_key").exists()
