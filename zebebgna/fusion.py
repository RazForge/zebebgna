"""Threat-fusion engine: correlates weak signals across verifier groups
into attack scenarios with a 0-100 risk score.

This is the "intelligence fusion" layer of zebebgna. Where the verifiers
(phishing, tls, headers, integrity) each report single-signal findings,
this module:

- extracts a structured signal bundle from a report (URL shape, TLS state,
  header posture, receipt-data anomalies),
- runs correlation rules that combine weak signals into strong ones
  (e.g. unknown host + lookalike name + missing HSTS -> phishing
  infrastructure),
- computes a fused 0-100 risk score and a risk level,
- synthesizes the most likely attack scenario in plain language.

Everything here is deterministic and offline; no external feeds are
contacted. Rules are data-driven so new correlations can be added as
plain table entries.
"""

import difflib
import re
from urllib.parse import urlparse

from zebebgna.report import PENALTIES
from zebebgna.verifiers import phishing

RISK_WEIGHTS = {"info": 2, "warn": 8, "error": 20, "high": 35, "critical": 50}

RISK_LEVELS = ((70, "CRITICAL"), (45, "HIGH"), (20, "MEDIUM"), (0, "LOW"))

PLACEHOLDER_RE = re.compile(
    r"(^|[\s\-_.])(test|testing|demo|sample|fake|scam|alert|example|xxxx+)"
    r"([\s\-_.]|$)",
    re.IGNORECASE,
)

TLS_FAILURE_MESSAGES = (
    "chain verification failed",
    "EXPIRED",
    "does not cover hostname",
    "no certificate",
)

INTEGRITY_ERROR_MESSAGES = ("mismatch", "reference", "non-success")


class Correlation:
    """A single fused signal: several weak indicators, one strong claim."""

    __slots__ = ("rule_id", "severity", "title", "description", "signals")

    def __init__(self, rule_id, severity, title, description, signals):
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.description = description
        self.signals = list(signals)

    @classmethod
    def from_dict(cls, payload):
        return cls(
            payload["rule_id"],
            payload["severity"],
            payload["title"],
            payload["description"],
            payload["signals"],
        )

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "signals": self.signals,
        }

    def __repr__(self):
        return f"<Correlation {self.rule_id} {self.severity} {self.title}>"


class ThreatAssessment:
    """Fused threat picture for a single verification report."""

    def __init__(self, risk_score=0, correlations=None, scenario=None,
                 indicators=None, unreadable=False, adjustment=0):
        self.risk_score = risk_score
        self.correlations = correlations or []
        self.scenario = scenario
        self.indicators = indicators or {}
        self.unreadable = unreadable
        self.adjustment = adjustment

    @classmethod
    def from_dict(cls, payload):
        correlations = [
            Correlation.from_dict(c) for c in payload.get("correlations", [])
        ]
        return cls(
            risk_score=payload["risk_score"],
            correlations=correlations,
            scenario=payload.get("scenario"),
            indicators=payload.get("indicators", {}),
            unreadable=payload.get("unreadable", False),
        )

    @property
    def risk_level(self):
        if self.unreadable:
            return "HIGH"
        for threshold, level in RISK_LEVELS:
            if self.risk_score >= threshold:
                return level
        return "LOW"

    def to_dict(self):
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "scenario": self.scenario,
            "correlations": [c.to_dict() for c in self.correlations],
            "indicators": self.indicators,
            "unreadable": self.unreadable,
            "feedback_adjustment": self.adjustment,
        }

    def __repr__(self):
        return f"<ThreatAssessment {self.risk_level} ({self.risk_score}/100)>"


class SignalBundle:
    """Normalized view of a report that correlation rules inspect."""

    def __init__(self, report):
        parsed = urlparse(report.url)
        self.url = report.url
        self.bank = report.bank
        self.data = report.data or {}
        self.scheme = (parsed.scheme or "").lower()
        self.host = (parsed.hostname or "").lower()
        self.port = parsed.port
        self.path = parsed.path or ""
        self.registered = phishing._registered_domain(self.host)

        self.is_ip = bool(phishing.IP_HOST_RE.match(self.host))
        self.is_punycode = bool(phishing.PUNYCODE_RE.match(self.host))
        self.is_shortener = self.host in phishing.SHORTENERS
        self.is_known_bank_host = any(
            self.host == known or self.host.endswith("." + known)
            for known in phishing.KNOWN_BANK_DOMAINS
        )
        self.lookalike_of = self._lookalike()

        self.messages = [f.message for f in report.findings]
        self.has = {
            (f.severity, f.category)
            for f in report.findings
        }
        self.amounts = self._amounts()
        self.placeholders = self._placeholders()

    # -- signal extractors -------------------------------------------------

    def _lookalike(self):
        best, best_ratio = None, 0.0
        for known in phishing.KNOWN_BANK_DOMAINS:
            if self.host == known or self.host.endswith("." + known):
                continue
            ratio = difflib.SequenceMatcher(
                None, self.registered, phishing._registered_domain(known)
            ).ratio()
            if ratio >= phishing.LOOKALIKE_THRESHOLD and ratio > best_ratio:
                best, best_ratio = known, ratio
        return best

    def _amounts(self):
        values = []
        for value in self.data.values():
            text = str(value).replace(",", "").replace("ETB", "").strip()
            if re.match(r"^\d+(\.\d{1,2})?$", text):
                values.append(text)
        return values

    def _placeholders(self):
        found = []
        for key, value in self.data.items():
            if isinstance(value, str) and PLACEHOLDER_RE.search(value):
                found.append(key)
        return found

    def tls_failure(self):
        return any(
            msg in message.lower()
            for message in self.messages
            for msg in TLS_FAILURE_MESSAGES
        )

    def integrity_failure(self):
        return any(
            msg in message.lower()
            for message in self.messages
            for msg in INTEGRITY_ERROR_MESSAGES
        )


# -- correlation rules ------------------------------------------------------
# Each rule: (id, severity, title, description, matcher)
#   matcher(signals) -> list of contributing signal names (empty = no match).

def _missing_headers(signals):
    missing = [
        name for name in (
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options",
        )
        if f"Missing security header: {name}" in signals.messages
    ]
    return missing


def _untrusted_infra(signals):
    return not signals.is_known_bank_host and not signals.is_ip


RULES = [
    (
        "tls_chain_broken",
        "critical",
        "TLS trust is broken",
        "The certificate chain, hostname match, or expiry check failed; "
        "data may be intercepted or the endpoint spoofed.",
        lambda s: ["tls"] if s.tls_failure() else [],
    ),
    (
        "phish_lookalike",
        "high",
        "Lookalike domain impersonating a bank",
        "The host resembles a known bank domain but is not one; typical of "
        "credential-phishing infrastructure.",
        lambda s: [s.host, s.lookalike_of] if s.lookalike_of else [],
    ),
    (
        "fraud_full_campaign",
        "critical",
        "Coordinated fake-receipt campaign",
        "An untrusted lookalike host serves receipt data whose financial "
        "fields do not reconcile; likely a forged-receipt operation.",
        lambda s: (
            [s.host] if not s.is_known_bank_host and s.lookalike_of
            and s.integrity_failure() else []
        ),
    ),
    (
        "integrity_amounts",
        "error",
        "Receipt amounts do not reconcile",
        "The extracted amounts sum to a different value than the stated "
        "total; the receipt may have been doctored.",
        lambda s: (
            ["amounts"]
            if any("mismatch" in m.lower() for m in s.messages) else []
        ),
    ),
    (
        "integrity_status",
        "critical",
        "Failed transaction presented as success",
        "The receipt carries a non-success status; trusting it would be "
        "dangerous.",
        lambda s: (
            ["status"]
            if any("non-success" in m.lower() for m in s.messages) else []
        ),
    ),
    (
        "phish_obfuscation",
        "warn",
        "Destination obfuscation",
        "Raw IP, URL shortener, punycode, or a non-standard port hides the "
        "true destination of the receipt link.",
        lambda s: (
            ["ip", "shortener", "punycode", "port"]
            if s.is_ip or s.is_shortener or s.is_punycode
            or (s.port and s.port != 443) else []
        ),
    ),
    (
        "tls_short_lease",
        "warn",
        "Short-lived or expiring certificate",
        "The certificate expires within a month; a short lease can indicate "
        "throwaway phishing infrastructure.",
        lambda s: (
            ["tls"]
            if any("expires soon" in m.lower() for m in s.messages) else []
        ),
    ),
    (
        "headers_unhardened",
        "warn",
        "Weak transport hardening",
        "HSTS, CSP, and X-Frame-Options are all missing, leaving browsers "
        "vulnerable to downgrade and framing attacks.",
        lambda s: ["headers"] if len(_missing_headers(s)) == 3 else [],
    ),
    (
        "headers_partial",
        "warn",
        "Incomplete security headers",
        "Some essential security headers are missing from the response.",
        lambda s: _missing_headers(s) if len(_missing_headers(s)) in (1, 2) else [],
    ),
    (
        "infra_unverified",
        "warn",
        "Unverified endpoint infrastructure",
        "The host is not a known bank domain; legitimate bank receipts are "
        "served from official domains only.",
        lambda s: [s.host] if _untrusted_infra(s) and not s.lookalike_of else [],
    ),
    (
        "data_placeholders",
        "warn",
        "Template placeholders in receipt data",
        "Field values such as 'test', 'demo', or 'xxxx' are typical of "
        "generated or fake receipts.",
        lambda s: s.placeholders or [],
    ),
    (
        "data_repeated_amounts",
        "info",
        "Repeated identical amounts",
        "Several fields share the same amount string; consistent with a "
        "copy-pasted or template-generated receipt.",
        lambda s: (
            ["amounts"]
            if len(s.amounts) >= 2 and len(set(s.amounts)) == 1 else []
        ),
    ),
    (
        "data_missing_fields",
        "info",
        "Incomplete receipt data",
        "Required receipt fields are missing; the receipt may be partial or "
        "forged.",
        lambda s: (
            ["fields"]
            if any("incomplete" in m.lower() for m in s.messages) else []
        ),
    ),
]


# -- scenario synthesis ------------------------------------------------------

SCENARIOS = [
    (
        "tls_chain_broken",
        "A man-in-the-middle or spoofed endpoint: the connection cannot be "
        "trusted end to end.",
    ),
    (
        "receipt_unreadable",
        "The receipt could not be read from the link; its authenticity "
        "cannot be verified. Treat it as unverified until a readable copy "
        "is obtained.",
    ),
    (
        "fraud_full_campaign",
        "Suspected coordinated forgery: an untrusted lookalike domain is "
        "serving receipt data with doctored financial fields.",
    ),
    (
        "integrity_status",
        "Suspected fraud: a failed or non-success transaction is being "
        "presented as a successful receipt.",
    ),
    (
        "phish_lookalike",
        "Likely phishing infrastructure impersonating a bank to harvest "
        "credentials.",
    ),
    (
        "integrity_amounts",
        "Suspected forged receipt: financial fields do not reconcile.",
    ),
    (
        "phish_obfuscation",
        "The link obscures its destination; treat with suspicion until "
        "manually verified.",
    ),
    (
        "infra_unverified",
        "Unverified endpoint: the host is not associated with the official "
        "bank domain. Verify manually before trusting.",
    ),
]


def _feedback_delta(confirmed, rejected):
    """Nudge the fused risk from community feedback on the same domain.

    Only strong, lopsided feedback moves the score (never more than a small
    amount): repeatedly-confirmed verdicts push risk slightly up, repeatedly
    rejected (false-positive) verdicts pull it down.
    """
    if rejected >= 3 and rejected >= 2 * confirmed:
        return -10
    if confirmed >= 3 and confirmed >= 2 * rejected:
        return +5
    return 0


def assess(report, feedback=None):
    """Fuse all signals in ``report`` into a :class:`ThreatAssessment`.

    ``feedback`` is an optional ``(confirmed, rejected)`` pair of prior
    user verdicts for the same domain; it slightly adjusts the fused score.
    """
    signals = SignalBundle(report)
    correlations = []

    for rule_id, severity, title, description, matcher in RULES:
        contributing = matcher(signals)
        if contributing:
            correlations.append(
                Correlation(rule_id, severity, title, description, contributing)
            )

    correlations.sort(key=lambda c: -RISK_WEIGHTS.get(c.severity, 0))

    # A receipt whose details could not be extracted cannot be verified at
    # all: that alone is a high-risk, unverified state regardless of how
    # clean the endpoint looks.
    unreadable = report.bank is not None and not report.data
    if unreadable:
        correlations.append(
            Correlation(
                "receipt_unreadable", "high",
                "Receipt could not be read",
                "No receipt details could be extracted from the link, so "
                "the receipt's authenticity cannot be verified.",
                ["extraction"],
            )
        )

    # Worst single finding (verifier-level) feeds the fused score too, so a
    # critical verifier finding can never be masked by a clean fusion pass.
    worst_verifier = max(
        (PENALTIES[f.severity] for f in report.findings),
        default=0,
    )
    fused = sum(RISK_WEIGHTS.get(c.severity, 0) for c in correlations)
    risk_score = min(100, fused + worst_verifier)
    adjustment = 0
    if feedback:
        adjustment = _feedback_delta(feedback[0], feedback[1])
        risk_score = min(100, max(0, risk_score + adjustment))
    if unreadable:
        risk_score = 0

    scenario = None
    for rule_id, text in SCENARIOS:
        if any(c.rule_id == rule_id for c in correlations):
            scenario = text
            break

    indicators = _build_indicators(report, signals, correlations)
    indicators["receipt_readable"] = bool(report.data)
    return ThreatAssessment(
        risk_score=risk_score,
        correlations=correlations,
        scenario=scenario,
        indicators=indicators,
        unreadable=unreadable,
        adjustment=adjustment,
    )


def _build_indicators(report, signals, correlations):
    issuer = None
    for message in signals.messages:
        match = re.search(r"issued by: (.+)$", message)
        if match:
            issuer = match.group(1)
            break

    return {
        "host": signals.host or None,
        "registered_domain": signals.registered,
        "bank_claimed": report.bank,
        "official_domain_match": signals.is_known_bank_host,
        "cert_issuer": issuer,
        "scheme": signals.scheme,
        "port": signals.port,
        "top_rule": correlations[0].rule_id if correlations else None,
    }
