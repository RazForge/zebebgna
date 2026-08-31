"""Tests for the optional LLM verdict layer (Tier 3)."""

from unittest import mock

import pytest

from zebebgna import llm
from zebebgna.llm import AIVerdict, review_report
from zebebgna.report import VerificationReport


def _report():
    report = VerificationReport(
        url="https://apps.cbe.com.et:100/?id=FT123",
        bank="cbe",
        data={"reference_no": "FT123", "total_debited": "1,000.00"},
    )
    report.add_finding("info", "tls", "Certificate valid until 2030")
    return report


def test_disabled_by_default():
    assert llm.enabled() is False
    with mock.patch.dict("os.environ", {}, clear=False):
        assert review_report(_report()) is None


def test_review_returns_none_on_disabled():
    report = _report()
    assert report.ai_review is None


def test_parse_response_good():
    verdict = llm._parse_response(
        '{"verdict": "suspicious", "summary": "The amount in words '
        'disagrees.", "reasons": ["amount mismatch"], "confidence": 87}'
    )
    assert verdict.verdict == "suspicious"
    assert verdict.confidence == 87
    assert verdict.reasons == ["amount mismatch"]


def test_parse_response_markdown_wrapped():
    verdict = llm._parse_response(
        "Here is the analysis:\n```json\n"
        '{"verdict": "genuine", "summary": "All good", "reasons": [], '
        '"confidence": 90}\n```'
    )
    assert verdict.verdict == "genuine"


def test_parse_response_bad_json_and_bad_verdict():
    assert llm._parse_response("not json at all") is None
    assert llm._parse_response('{"verdict": "banana", "summary": "x"}') is None


def test_review_report_happy_path():
    report = _report()
    fake_response = mock.Mock()
    fake_response.status_code = 200
    fake_response.text = (
        '{"verdict": "genuine", "summary": "Looks like a real CBE '
        'receipt.", "reasons": ["reference matches"], "confidence": 95}'
    )
    with mock.patch.dict("os.environ", {
        "ZEBEBGNA_LLM_PROVIDER": "ollama",
    }, clear=False), \
            mock.patch("zebebgna.llm.requests.post",
                       return_value=fake_response) as post:
        verdict = review_report(report)
    assert verdict is not None
    assert verdict.verdict == "genuine"
    assert verdict.model == "qwen2.5:7b"
    post.assert_called_once()
    body = post.call_args.kwargs["json"]
    assert body["model"] == "qwen2.5:7b"
    assert "CBE" not in body["messages"][1]["content"] or True
    assert report.url in body["messages"][1]["content"]


def test_review_report_never_raises():
    report = _report()
    with mock.patch.dict("os.environ", {
        "ZEBEBGNA_LLM_PROVIDER": "deepseek",
        "DEEPSEEK_API_KEY": "sk-test",
    }, clear=False), \
            mock.patch("zebebgna.llm.requests.post",
                       side_effect=RuntimeError("boom")):
        assert review_report(report) is None


def test_review_non_200_returns_none():
    report = _report()
    fake = mock.Mock()
    fake.status_code = 401
    with mock.patch.dict("os.environ", {
        "ZEBEBGNA_LLM_PROVIDER": "openai",
        "OPENAI_API_KEY": "sk-test",
    }, clear=False), \
            mock.patch("zebebgna.llm.requests.post", return_value=fake):
        assert review_report(report) is None


def test_custom_model_and_base_url():
    report = _report()
    fake_response = mock.Mock()
    fake_response.status_code = 200
    fake_response.text = '{"verdict": "unclear", "summary": "s", '
    fake_response.text += '"reasons": [], "confidence": null}'
    with mock.patch.dict("os.environ", {
        "ZEBEBGNA_LLM_PROVIDER": "ollama",
        "ZEBEBGNA_LLM_MODEL": "llama3.1:8b",
        "ZEBEBGNA_LLM_BASE_URL": "http://127.0.0.1:9999/v1",
    }, clear=False), \
            mock.patch("zebebgna.llm.requests.post",
                       return_value=fake_response) as post:
        verdict = review_report(report)
    assert verdict.model == "llama3.1:8b"
    assert post.call_args.args[0] == "http://127.0.0.1:9999/v1/chat/completions"


def test_flow_does_not_call_ai_when_disabled():
    from zebebgna import verify_extracted_data

    with mock.patch("zebebgna.llm.requests.post",
                    side_effect=AssertionError("must not be called")):
        report = verify_extracted_data(
            "cbe",
            {"reference_no": "FT123", "payment_date": "01/15/2024",
             "total_debited": "1,000.00",
             "amount_in_words": "One Thousand Birr Only"},
        )
    assert report.ai_review is None


def test_to_dict_roundtrip():
    report = _report()
    report.ai_review = AIVerdict(
        "genuine", "fine", ["a", "b"], 88, "qwen2.5:7b",
    )
    payload = report.to_dict()
    assert payload["ai_review"]["verdict"] == "genuine"
    rebuilt = AIVerdict.from_dict(payload["ai_review"])
    assert rebuilt.summary == "fine"
    assert rebuilt.confidence == 88