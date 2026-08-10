"""English/Amharic number-to-amount parsing for receipt cross-checks."""

import re
from decimal import Decimal, InvalidOperation

ONES_EN = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19,
}
TENS_EN = {
    "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
    "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90,
}
SCALES_EN = {"hundred": 100, "thousand": 1000, "million": 1000000,
             "billion": 1000000000}

ONES_AM = {
    "አንድ": 1, "ሁለት": 2, "ሶስት": 3, "ሶሰት": 3, "ሦስት": 3,
    "አራት": 4, "አምስት": 5, "ስድስት": 6, "ሰባት": 7, "ስምንት": 8,
    "ዘጠኝ": 9, "አስር": 10, "አስራ": 10, "አሥራ": 10,
}
TENS_AM = {
    "ሃያ": 20, "ሀያ": 20, "ሰላሳ": 30, "አርባ": 40, "ሃምሳ": 50,
    "ሀምሳ": 50, "ስልሳ": 60, "ስሳ": 60, "ሰባ": 70, "ሰማንያ": 80,
    "ዘጠና": 90,
}
SCALES_AM = {"መቶ": 100, "ሺህ": 1000, "ሚሊዮን": 1000000}

# Coocurrence words that carry no numeric value on receipts.
NOISE_WORDS = {"birr", "birrs", "cents", "sent", "cent", "only", "and",
               "etb", "amount", "in", "words", "of", "ብር", "ሳንቲም",
               "ብርም", "ብሮች"}

_NUMBER_TOKEN_RE = re.compile(r"[a-z\u1200-\u137f'-]+", re.IGNORECASE)


def _word_value(token):
    return (
        ONES_EN.get(token) or ONES_AM.get(token)
        or TENS_EN.get(token) or TENS_AM.get(token)
    )


def _parse_number(tokens):
    """Parse a token list into an integer amount using the standard
    hundred/thousand scale algorithm."""
    current = 0
    total = 0
    for token in tokens:
        if token in NOISE_WORDS:
            continue
        value = _word_value(token)
        if value is not None:
            current += value
            continue
        scale = SCALES_EN.get(token) or SCALES_AM.get(token)
        if scale is None:
            return None
        current = (current or 1) * scale
        if scale >= 1000:
            total += current
            current = 0
    return total + current


def parse_amount_words(text):
    """Parse an English or Amharic number written in words.

    Supports Ethiopian-style phrases such as
    ``One Thousand Two Hundred Thirty-Four Birr and Fifty Cents Only`` or
    ``አንድ ሺህ ሁለት መቶ ሰላሳ አራት`` (one thousand two hundred thirty-four).

    Returns a ``Decimal``, or ``None`` when the text cannot be parsed.
    """
    if not text:
        return None

    cleaned = str(text).strip().replace("-", " ").replace("–", " ").replace("—", " ")
    if re.search(r"\d", cleaned):
        # Some receipts mix words and digits (e.g. "1,000 Birr Only").
        digits = re.search(r"\d[\d,]*\.?\d*", cleaned)
        if digits:
            try:
                return Decimal(digits.group(0).replace(",", ""))
            except InvalidOperation:
                return None

    tokens = [t for t in _NUMBER_TOKEN_RE.findall(cleaned.lower()) if t]
    if not tokens:
        return None

    cents_tokens = []
    for i, token in enumerate(tokens):
        if token.startswith("cent"):
            # The cent amount is the numeric phrase directly before the
            # word "cent(s)": "… and fifty cents …".
            j = i - 1
            while j >= 0 and _word_value(tokens[j]) is not None:
                j -= 1
            cents_tokens = tokens[j + 1:i]
            tokens = tokens[:j + 1]
            break

    amount = _parse_number(tokens)
    if amount is None:
        return None

    if cents_tokens:
        cents = _parse_number(cents_tokens)
        if cents is None:
            return None
        amount = Decimal(amount) + Decimal(cents) / 100
    return Decimal(str(amount))