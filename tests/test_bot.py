"""Tests for the Telegram bot's pure parsing/formatting logic (Tier 5).

The telegram network layer is not exercised; only the testable pure
functions (``parse_verify_command``, ``format_verdict``) are covered so the
tests run without a token or a connection.
"""

from zebebgna.bot import BANK_ALIASES, format_verdict, parse_verify_command
from zebebgna.report import VerificationReport


def test_parse_verify_command_bank_and_input():
    bank, target = parse_verify_command("cbe https://apps.cbe.com.et:100/?id=X")
    assert bank == "cbe"
    assert target == "https://apps.cbe.com.et:100/?id=X"


def test_parse_verify_command_aliases():
    assert parse_verify_command("commercial https://x/")[0] == "cbe"
    assert parse_verify_command("abyssinia https://x/")[0] == "boa"
    assert parse_verify_command("telebirr CHQ0FJ403O")[0] == "tele"


def test_parse_verify_command_errors():
    bank, err = parse_verify_command("cbe")
    assert bank is None and "Usage" in err
    bank, err = parse_verify_command("unknownbank https://x/")
    assert bank is None and "Unknown bank" in err
    bank, err = parse_verify_command("")
    assert bank is None and "Usage" in err


def test_format_verdict_pass():
    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe",
        data={"reference_no": "FT123"},
    )
    text = format_verdict(report)
    assert "CBE" in text and "PASS" in text
    assert "FT123" in text


def test_format_verdict_with_findings_and_threat():
    from zebebgna.fusion import assess

    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT123", bank="cbe",
        data={"reference_no": "FT123"},
    )
    report.add_finding("warn", "headers", "Missing security header: CSP")
    report.add_finding("error", "integrity", "Amount mismatch")
    report.threat = assess(report)
    text = format_verdict(report)
    assert "Findings:" in text
    assert "Amount mismatch" in text
    assert report.threat.risk_level in text


def test_build_app_requires_token():
    import pytest

    from zebebgna.bot import build_app

    with pytest.raises(ValueError):
        build_app(token=None)
    with pytest.raises(ValueError):
        build_app(token="")