"""Per-bank receipt fingerprinting.

Every Ethiopian bank issues receipts with its own layout, field set,
reference format, and date convention. This verifier encodes each bank's
canonical "receipt DNA" and flags data that does not match it:

- layout mismatch: none of the canonical fields of the selected bank are
  present (classic sign that the wrong extractor/bank was chosen, or the
  document is a forgery made from a different bank's template),
- amount-in-words conflict: the numeric amount and the amount written in
  words disagree (a strong forged-receipt signal),
- date anomalies: receipt dates that are unparsable, in the future, or
  implausibly old.

Category of all findings: ``fingerprint``.
"""

from zebebgna.dates import parse_and_plausibility
from zebebgna.words import parse_amount_words

# Canonical field sets per bank: the fields a genuine receipt of that bank
# always carries. Only keys with non-empty values count as present.
CANONICAL_FIELDS = {
    "cbe": ("transferred_amount", "total_debited", "reference_no",
            "payment_date", "customer_name"),
    "dashen": ("amount", "total", "transfer_reference", "transaction_date",
               "sender_name", "beneficiary_name"),
    "awash": ("Amount", "Total", "Transaction ID", "Transaction Time",
              "Sender Name", "Beneficiary name"),
    "boa": ("Transferred Amount", "Total Amount", "Transaction Reference",
            "Transaction Date", "Transaction Type"),
    "zemen": ("Settled Amount", "Total Amount Paid", "Reference No", "Date",
              "Payer Name"),
    "tele": ("total_paid", "reference_no", "status", "payer_name",
             "service_charge"),
}

# (numeric field, words field) pairs whose values must agree.
AMOUNT_WORDS_FIELDS = {
    "cbe": ("total_debited", "amount_in_words"),
    "dashen": ("amount", "amount_in_words"),
    "zemen": ("Total Amount Paid", "Amount in Words"),
}

DATE_FIELDS = {
    "cbe": ("payment_date",),
    "dashen": ("transaction_date",),
    "awash": ("Transaction Time",),
    "boa": ("Transaction Date",),
    "zemen": ("Date",),
    "tele": (),
}

REFERENCE_FIELDS = {
    "cbe": ("reference_no",),
    "dashen": ("transfer_reference", "transaction_reference"),
    "awash": ("Transaction ID",),
    "boa": ("Transaction Reference",),
    "zemen": ("Reference No", "Invoice No"),
    "tele": ("reference_no",),
}

CANONICAL_KIND_LABEL = "field"


def _present(data, *keys):
    for key in keys:
        value = data.get(key)
        if value is not None and str(value).strip():
            return True
    return False


def _check_layout(bank, data, report):
    canonical = CANONICAL_FIELDS.get(bank, ())
    if not canonical:
        return
    matched = [k for k in canonical if _present(data, k)]
    if not matched:
        report.add_finding(
            "error", "fingerprint",
            f"Receipt data does not match the canonical {bank.upper()} "
            f"receipt layout; expected fields like {', '.join(canonical[:4])}",
        )
    elif len(matched) < max(2, (len(canonical) + 1) // 2):
        report.add_finding(
            "warn", "fingerprint",
            f"Receipt partially matches the {bank.upper()} layout "
            f"({len(matched)}/{len(canonical)} canonical fields found)",
        )


def _check_amount_words(bank, data, report):
    pair = AMOUNT_WORDS_FIELDS.get(bank)
    if not pair:
        return
    numeric_field, words_field = pair
    numeric = data.get(numeric_field)
    words = data.get(words_field)
    if not numeric or not words:
        return
    words_value = parse_amount_words(str(words))
    if words_value is None:
        report.add_finding(
            "warn", "fingerprint",
            f"Amount in words '{words}' could not be parsed; "
            f"cannot confirm it matches {numeric}",
        )
        return
    numeric_value = _to_decimal(numeric)
    if numeric_value is None:
        return
    if abs(words_value - numeric_value) > 1:
        report.add_finding(
            "error", "fingerprint",
            f"Amount in words says {words_value} but the receipt "
            f"states {numeric}; amounts disagree",
        )


def _to_decimal(value):
    from zebebgna.verifiers.integrity import _to_decimal as conv

    return conv(value)


def _check_dates(bank, data, report):
    for field in DATE_FIELDS.get(bank, ()):
        value = data.get(field)
        if not value:
            continue
        state = parse_and_plausibility(str(value))
        if state.status == "unparsable":
            report.add_finding(
                "warn", "fingerprint",
                f"Receipt date '{value}' is not in a recognizable format",
            )
        elif state.status == "future":
            report.add_finding(
                "warn", "fingerprint",
                f"Receipt date '{value}' is in the future "
                f"({state.ec_readable}); receipts cannot predate issuance",
            )
        elif state.status == "old":
            report.add_finding(
                "warn", "fingerprint",
                f"Receipt date '{value}' is unusually old "
                f"({state.ec_readable}); verify this receipt manually",
            )


def verify_fingerprint(bank, data, report):
    """Run per-bank fingerprint checks over extracted receipt data."""
    if not bank:
        return
    _check_layout(bank, data, report)
    _check_amount_words(bank, data, report)
    _check_dates(bank, data, report)