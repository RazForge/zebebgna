"""Shared data model for security findings and verification reports."""

SEVERITIES = ("info", "warn", "error", "critical")

# Informational notes ("info") carry no penalty: they describe the serving
# site's hardening posture, not the receipt's authenticity, so genuine
# receipts are never failed for them.
PENALTIES = {"info": 0, "warn": 10, "error": 20, "critical": 40}


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
        self.threat = None
        self.check_id = None

    def add_finding(self, severity, category, message):
        self.findings.append(Finding(severity, category, message))

    @property
    def score(self):
        """0-100 security score; each finding carries a severity penalty.

        A receipt whose data is missing or fails integrity checks (amount
        mismatch, bad reference, non-success status) cannot be trusted at
        all, so the score collapses to 0 regardless of how clean the
        endpoint itself looks.
        """
        if self._receipt_data_failed():
            return 0
        total = sum(PENALTIES[f.severity] for f in self.findings)
        return max(0, min(100 - total, 100))

    def _receipt_data_failed(self):
        if self.bank is None:
            return False
        if not self.data:
            return True
        return any(
            f.category == "integrity" and f.severity in ("error", "critical")
            for f in self.findings
        )

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
            "threat": self.threat.to_dict() if self.threat else None,
        }
