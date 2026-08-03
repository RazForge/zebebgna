import pytest
from unittest import mock

import webapp
from zabagna.report import VerificationReport


@pytest.fixture
def client():
    webapp.app.config["TESTING"] = True
    return webapp.app.test_client()


def test_index_renders_form(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Receipt Verification Tool" in resp.data
    assert b"name=\"bank\"" in resp.data
    assert b"Verify receipt" in resp.data


def test_verify_requires_input(client):
    resp = client.post("/verify", data={"bank": "cbe", "url_or_id": ""})
    assert resp.status_code == 200
    assert b"paste a receipt link" in resp.data


def test_verify_rejects_non_url(client):
    resp = client.post("/verify", data={"bank": "cbe", "url_or_id": "abc123"})
    assert resp.status_code == 200
    assert b"does not look like a valid receipt link" in resp.data


def test_verify_renders_report(client):
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


def test_verify_renders_fail_verdict_for_critical(client):
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


def test_host_allowlist_blocks_unknown(client, monkeypatch):
    monkeypatch.setenv("zabagna_ALLOWED_HOSTS", "apps.cbe.com.et")
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
