"""Tests for the SSRF guard and hardened secure fetching."""

import socket
from unittest import mock

import pytest
import requests

from zebebgna import InsecureURLError
from zebebgna.fetch import (
    SecureFetcher,
    host_is_private,
    validate_fetch_target,
)


class FakeResp:
    def __init__(self, is_redirect=False, location=None, content=b"ok",
                 status_code=200):
        self.is_redirect = is_redirect
        self.headers = {"Location": location} if location else {}
        self.content = content
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.status_code)

    def close(self):
        pass


def _public_dns(monkeypatch, hosts=("example.com",)):
    def fake_getaddrinfo(host, *args, **kwargs):
        if host in hosts:
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ]
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


# ---------------------------------------------------------------- host checks

def test_host_is_private_flags_loopback_and_private():
    assert host_is_private("127.0.0.1")
    assert host_is_private("localhost")
    assert host_is_private("::1")
    assert host_is_private("10.0.0.5")
    assert host_is_private("192.168.1.1")
    assert host_is_private("169.254.1.1")
    assert host_is_private("192.0.2.1")
    assert host_is_private("myhost.local")
    assert host_is_private("db.internal")


def test_host_is_private_allows_public(monkeypatch):
    _public_dns(monkeypatch)
    assert not host_is_private("example.com")


# -------------------------------------------------------------- validate target

def test_validate_allows_public_https(monkeypatch):
    _public_dns(monkeypatch)
    assert validate_fetch_target("https://example.com/r") is None


def test_validate_rejects_plain_http():
    with pytest.raises(InsecureURLError):
        validate_fetch_target("http://example.com/r")


def test_validate_rejects_private_literal():
    with pytest.raises(InsecureURLError):
        validate_fetch_target("https://127.0.0.1/internal")


def test_validate_rejects_host_outside_allowlist(monkeypatch):
    _public_dns(monkeypatch)
    with pytest.raises(InsecureURLError):
        validate_fetch_target("https://example.com/r", allowed_hosts={"bank.com"})


def test_validate_accepts_subdomain_of_allowed_host(monkeypatch):
    _public_dns(monkeypatch)
    assert validate_fetch_target(
        "https://sub.bank.com/r", allowed_hosts={"bank.com"}
    ) is None


# ---------------------------------------------------------------- fetcher.get

def test_fetcher_refuses_private_host_in_get():
    sf = SecureFetcher()
    with pytest.raises(InsecureURLError):
        sf.get("https://127.0.0.1/x")


def test_fetcher_blocks_redirect_to_private_host(monkeypatch):
    sf = SecureFetcher()
    _public_dns(monkeypatch)
    landing = FakeResp(is_redirect=True, location="https://127.0.0.1/internal")
    with mock.patch.object(sf.session, "get", return_value=landing) as mg:
        with pytest.raises(InsecureURLError):
            sf.get("https://example.com/start")
        mg.assert_called_once()


def test_fetcher_blocks_redirect_to_http(monkeypatch):
    sf = SecureFetcher()
    _public_dns(monkeypatch)
    landing = FakeResp(is_redirect=True, location="http://example.com/down")
    with mock.patch.object(sf.session, "get", return_value=landing):
        with pytest.raises(InsecureURLError):
            sf.get("https://example.com/start")


def test_fetcher_blocks_redirect_outside_allowlist(monkeypatch):
    sf = SecureFetcher(allowed_hosts={"example.com"})
    _public_dns(monkeypatch)
    landing = FakeResp(is_redirect=True, location="https://evil.com/x")
    with mock.patch.object(sf.session, "get", return_value=landing):
        with pytest.raises(InsecureURLError):
            sf.get("https://example.com/start")


def test_fetcher_follows_redirect_to_allowed_host(monkeypatch):
    sf = SecureFetcher(allowed_hosts={"example.com"})
    _public_dns(monkeypatch, hosts=("example.com", "www.example.com"))
    landing = FakeResp(is_redirect=True, location="https://www.example.com/final")
    final = FakeResp(content=b"ok")
    with mock.patch.object(sf.session, "get", side_effect=[landing, final]) as mg:
        resp = sf.get("https://example.com/start")
    assert resp.content == b"ok"
    assert mg.call_count == 2


def test_redirect_limit_enforced(monkeypatch):
    sf = SecureFetcher()
    _public_dns(monkeypatch)
    loop = FakeResp(is_redirect=True, location="https://example.com/again")
    with mock.patch.object(sf.session, "get", return_value=loop):
        with pytest.raises(requests.TooManyRedirects):
            sf.get("https://example.com/start")


# ---------------------------------------------------------------- helpers

def test_fetch_pdf_bytes_returns_content():
    sf = SecureFetcher()
    with mock.patch.object(
        sf.session, "get", return_value=FakeResp(content=b"%PDF-1.4")
    ):
        assert sf.fetch_pdf_bytes("https://example.com/r.pdf") == b"%PDF-1.4"
