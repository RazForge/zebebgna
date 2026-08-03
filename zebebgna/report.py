"""Shared data model for security findings and verification reports."""

SEVERITIES = ("info", "warn", "error", "critical")

PENALTIES = {"info": 2, "warn": 10, "error": 20, "critical": 40}


class Finding:
    __slots__ = ("severity", "category", "message")

    def __init__(self, severity, category, message):
        if severity not in SEVERITIES:
            raise ValueError(f"Unknown severity: {severity}")
        self.severity = severity
        self.category = category
        self.message = message

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
        }

    def __repr__(self):
        return f"<Finding {self.severity} [{self.category}] {self.message}>"


class VerificationReport:
    """Aggregated result of a receipt verification / security audit."""

    def __init__(self, url, bank=None, data=None):
        self.url = url
        self.bank = bank
        self.data = data or {}
        self.findings = []

    def add_finding(self, severity, category, message):
        self.findings.append(Finding(severity, category, message))

    @property
    def score(self):
        """0-100 security score; each finding carries a severity penalty."""
        total = sum(PENALTIES[f.severity] for f in self.findings)
        return max(0, min(100 - total, 100))

    @property
    def status(self):
        if any(f.severity == "critical" for f in self.findings):
            return "FAIL"
        if self.score >= 85:
            return "PASS"
        if self.score >= 55:
            return "REVIEW"
        return "FAIL"

    def to_dict(self):
        return {
            "url": self.url,
            "bank": self.bank,
            "score": self.score,
            "status": self.status,
            "extracted_data": self.data,
            "findings": [f.to_dict() for f in self.findings],
        }
