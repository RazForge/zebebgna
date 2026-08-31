"""Receipt authenticity heuristics: cross-field consistency and format checks."""

import re
from decimal import Decimal, InvalidOperation

SUCCESS_STATUSES = {
    "SUCCESS", "SUCCESSFUL", "COMPLETED", "COMPLETED SUCCESSFULLY",
    "PAID", "DONE",
}

BANK_REFERENCE_PATTERNS = {
    "cbe": re.compile(r"^FT[A-Z0-9]{6,20}$"),
    "tele": re.compile(r"^[A-Z0-9]{8,12}$"),
    "dashen": re.compile(r"^[A-Z0-9]{8,24}$"),
    "awash": re.compile(r"^[A-Z0-9\-]{6,30}$"),
    "boa": re.compile(r"^[A-Z0-9\-]{6,40}$"),
    "zemen": re.compile(r"^[A-Z0-9]{6,30}$"),
}

REQUIRED_FIELDS = {
    "cbe": ("amount_in_words", "payment_date", "reference_no"),
    "dashen": ("amount", "transaction_date", "transfer_reference"),
    "awash": ("Amount", "Transaction Time", "Transaction ID"),
    "boa": ("Total Amount", "Transaction Date", "Transaction Reference"),
    "zemen": ("Total Amount Paid", "Date", "Reference No"),
    "tele": ("total_paid", "status", "payer_name"),
}

_AMOUNT_TOLERANCE = Decimal("0.01")


def _to_decimal(value):
    if value is None:
        return None
    cleaned = (
        str(value).replace(",", "").replace("ETB", "").replace("Birr", "").strip()
    )
    try:
        return Decimal(cleaned)
    except InvalidOperation:
        return None


def _close(a, b):
    if a is None or b is None:
        return None
    return abs(a - b) <= _AMOUNT_TOLERANCE


def _check_amount_math(report, label, components, expected):
    """Verify that ``components`` sum to ``expected`` within tolerance."""
    parts = [_to_decimal(c) for c in components]
    if None in parts or _to_decimal(expected) is None:
        return
    total = sum(p for p in parts if p is not None)
    expected_dec = _to_decimal(expected)
    if not _close(total, expected_dec):
        report.add_finding(
            "error", "integrity",
            f"{label} mismatch: {' + '.join(str(c) for c in components)} "
            f"sums to {total} but receipt states {expected_dec}",
        )


def _check_reference(bank, data, report):
    pattern = BANK_REFERENCE_PATTERNS.get(bank)
    if not pattern:
        return
    candidates = [
        data.get(k)
        for k in ("reference", "reference_no", "transfer_reference",
                  "transaction_reference", "Transaction Reference",
                  "Transaction ID", "Reference No")
        if data.get(k)
    ]
    if not candidates:
        return
    ref = str(candidates[0]).strip()
    if not pattern.match(ref):
        report.add_finding(
            "error", "integrity",
            f"{bank.upper()} reference '{ref}' does not match the "
            f"expected format ({pattern.pattern})",
        )


def verify_integrity(bank, data, report):
    """Run authenticity heuristics over extracted receipt data."""
    status_raw = data.get("status") or data.get("transaction_status")
    status = str(status_raw).strip().upper() if status_raw else ""
    if status and status not in SUCCESS_STATUSES:
        report.add_finding(
            "critical", "integrity",
            f"Non-success transaction status on receipt: {status}",
        )

    if bank == "cbe":
        _check_amount_math(
            report, "CBE total debited",
            [
                data.get("transferred_amount"),
                data.get("commission"),
                data.get("vat_on_commission"),
            ],
            data.get("total_debited"),
        )
    elif bank == "dashen":
        _check_amount_math(
            report, "Dashen transaction total",
            [
                data.get("amount"),
                data.get("service_charge"),
                data.get("vat"),
            ],
            data.get("total"),
        )
    elif bank == "zemen":
        _check_amount_math(
            report, "Zemen total paid",
            [
                data.get("Settled Amount"),
                data.get("Service Charge"),
                data.get("VAT"),
            ],
            data.get("Total Amount Paid"),
        )
    elif bank == "awash":
        _check_amount_math(
            report, "Awash total amount",
            [
                data.get("Amount"),
                data.get("Charge"),
                data.get("VAT"),
            ],
            data.get("Total"),
        )
    elif bank == "boa":
        _check_amount_math(
            report, "BOA total amount",
            [
                data.get("Transferred Amount"),
                data.get("Service Charge"),
                data.get("VAT"),
            ],
            data.get("Total Amount"),
        )
    elif bank == "tele":
        _check_amount_math(
            report, "Telebirr total paid",
            [
                data.get("amount"),
                data.get("service_charge"),
            ],
            data.get("total_paid"),
        )

    _check_reference(bank, data, report)

    required = REQUIRED_FIELDS.get(bank, ())
    missing = [f for f in required if not data.get(f)]
    if missing:
        report.add_finding(
            "warn", "integrity",
            f"Receipt data is incomplete; missing fields: {', '.join(missing)}",
        )
