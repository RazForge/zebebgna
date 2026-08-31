"""Optional LLM verdict layer for zebebgna.

Adds a plain-language AI review of a receipt verification. Everything is
strictly optional and offline by default: when no provider is configured
(``ZEBEBGNA_LLM_PROVIDER`` unset or ``off``), ``review_report`` returns
``None`` instantly and the pipeline is unchanged.

Providers (all OpenAI-compatible chat-completions endpoints):

- ``ollama``   — local, no API key (default model ``qwen2.5:7b``)
- ``deepseek`` — needs ``DEEPSEEK_API_KEY`` (default model ``deepseek-chat``)
- ``openai``   — needs ``OPENAI_API_KEY`` (default model ``gpt-4o-mini``)

Env vars:

- ``ZEBEBGNA_LLM_PROVIDER``: off | ollama | deepseek | openai
- ``ZEBEBGNA_LLM_MODEL``: model override
- ``ZEBEBGNA_LLM_BASE_URL``: endpoint override (any OpenAI-compatible API)
- ``ZEBEBGNA_OLLAMA_URL``: ollama base URL (default http://localhost:11434)

Any failure (network, bad JSON, wrong key) yields ``None``: the AI review
must never break receipt verification.
"""

import json
import os
import re
import time

import requests

PROVIDERS = {
    "ollama": {
        "base": lambda: os.environ.get(
            "ZEBEBGNA_OLLAMA_URL", "http://localhost:11434").rstrip("/")
        + "/v1",
        "model": "qwen2.5:7b",
        "key": None,
    },
    "deepseek": {
        "base": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "key": "DEEPSEEK_API_KEY",
    },
    "openai": {
        "base": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "key": "OPENAI_API_KEY",
    },
}

SYSTEM_PROMPT = (
    "You are Zebebgna, a careful Ethiopian receipt-authenticity analyst. "
    "You review bank receipts (CBE, Dashen, Awash, BOA, Zemen, Telebirr) "
    "using the extracted fields and the automated checks that were run. "
    "You know that Ethiopian bank receipts may use the Ethiopian calendar "
    "and Amharic, and that small inconsistencies in the amount written in "
    "words, the reference number format, or the receipt layout are signs "
    "of forgery. Reply ONLY with a single JSON object, no markdown, of "
    "the form: "
    '{"verdict": "genuine|suspicious|unclear", "summary": "one or two '
    'sentences in plain English (mention Amharic/EC facts if relevant)", '
    '"reasons": ["short reason", ...], "confidence": 0-100}'
)

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


class AIVerdict:
    __slots__ = ("verdict", "summary", "reasons", "confidence",
                 "model", "generated_at")

    def __init__(self, verdict, summary, reasons, confidence, model,
                 generated_at=None):
        self.verdict = verdict
        self.summary = summary
        self.reasons = list(reasons or [])
        self.confidence = confidence
        self.model = model
        self.generated_at = generated_at or time.strftime(
            "%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "summary": self.summary,
            "reasons": self.reasons,
            "confidence": self.confidence,
            "model": self.model,
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, payload):
        return cls(
            payload["verdict"],
            payload["summary"],
            payload.get("reasons", []),
            payload.get("confidence"),
            payload.get("model"),
            payload.get("generated_at"),
        )

    def __repr__(self):
        return f"<AIVerdict {self.verdict} ({self.confidence}%)>"


def provider():
    return os.environ.get("ZEBEBGNA_LLM_PROVIDER", "off").strip().lower()


def enabled():
    return provider() in PROVIDERS


def model_name():
    name = os.environ.get("ZEBEBGNA_LLM_MODEL", "").strip()
    if name:
        return name
    return PROVIDERS.get(provider(), {}).get("model", "off")


def _endpoint():
    base = os.environ.get("ZEBEBGNA_LLM_BASE_URL", "").strip()
    if not base:
        base = PROVIDERS[provider()]["base"]
        if callable(base):
            base = base()
    return base.rstrip("/") + "/chat/completions"


def _headers():
    headers = {"Content-Type": "application/json"}
    key_env = PROVIDERS.get(provider(), {}).get("key")
    if key_env:
        key = os.environ.get(key_env, "")
        if key:
            headers["Authorization"] = f"Bearer {key}"
    return headers


def _build_payload(report):
    threat = report.threat
    return {
        "model": model_name(),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _describe(report)},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }


def _describe(report):
    data = {}
    for key, value in (report.data or {}).items():
        if value is not None and str(value).strip():
            data[key] = str(value)[:120]
    threat = report.threat
    correlations = [
        {
            "rule": c.rule_id,
            "severity": c.severity,
            "title": c.title,
        }
        for c in (threat.correlations if threat else [])
    ][:6]
    if threat:
        risk = f"{threat.risk_level} ({threat.risk_score}/100)"
        if threat.scenario:
            risk += f" scenario={threat.scenario}"
    else:
        risk = "none"
    return (
        "Verification report to review:\n"
        f"- bank: {report.bank}\n"
        f"- url/source: {report.url}\n"
        f"- automated score: {report.score}/100 (status {report.status})\n"
        f"- threat risk: {risk}\n"
        f"- fused correlations: {json.dumps(correlations, ensure_ascii=False)}\n"
        f"- extracted fields: {json.dumps(data, ensure_ascii=False)}\n"
    )


def _parse_response(text):
    match = _JSON_BLOCK_RE.search(text)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except (ValueError, TypeError):
        return None
    verdict = str(payload.get("verdict", "")).strip().lower()
    if verdict not in ("genuine", "suspicious", "unclear"):
        return None
    confidence = payload.get("confidence")
    try:
        confidence = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        confidence = None
    return AIVerdict(
        verdict=verdict,
        summary=str(payload.get("summary", "")).strip() or "No summary",
        reasons=[str(r) for r in payload.get("reasons", []) if str(r).strip()],
        confidence=confidence,
        model=model_name(),
    )


def review_report(report, timeout=60):
    """Ask the configured LLM for a verdict on a verification report.

    Returns an :class:`AIVerdict`, or ``None`` when AI is disabled or
    anything fails. Never raises.
    """
    if not enabled() or report is None:
        return None
    try:
        response = requests.post(
            _endpoint(),
            headers=_headers(),
            json=_build_payload(report),
            timeout=timeout,
        )
        if response.status_code != 200:
            return None
        return _parse_response(response.text)
    except Exception:
        # The AI review must never break verification, whatever happens
        # (network, timeout, malformed response, bad config).
        return None


def attach_ai_review(report):
    """Attach the AI verdict to a report if AI is enabled (no-op otherwise)."""
    if not enabled():
        return
    report.ai_review = review_report(report)