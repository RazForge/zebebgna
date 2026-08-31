"""Ethiopian calendar (ዓ.ም.) and Ge'ez/Amharic numeral helpers.

Receipts issued in Ethiopia may carry dates in the Ethiopian calendar
(EC) or with Amharic numerals. This module converts between Gregorian
(GC) and Ethiopian (EC) dates, parses Ge'ez numerals, and scores the
plausibility of receipt dates (future / implausibly old / unparsable).

Encoding of the EC (civil) calendar on which this module relies:

- EC year length is 360 days + Pagumē (5 days, 6 in leap years).
- EC years are leap iff ``year % 4 == 3``; Enkutatash (Meskerem 1) of a
  year divisible by 4 falls on GC September 12, otherwise September 11
  (of GC year ``ec_year + 7``).
- Locked to documented anchors: Enkutatash 2000 EC = 2007-09-12 (the
  third-millennium celebration), 2007 EC = 2014-09-11, 2012 EC = 2019-09-12,
  2016 EC = 2023-09-12.
"""

import re
from datetime import date, datetime, timedelta

EC_MONTHS = (
    "መስከረም", "ጥቅምት", "ህዳር", "ታህሳስ", "ጥር", "የካቲት",
    "መጋቢት", "ሚያዚያ", "ግንቦት", "ሰኔ", "ሐምሌ", "ነሐሴ", "ጳጉሜ",
)

# Ge'ez numerals (additive system).
GEEZ_DIGITS = {
    "፩": 1, "፪": 2, "፫": 3, "፬": 4, "፭": 5, "፮": 6, "፯": 7, "፰": 8, "፱": 9,
}
GEEZ_TENS = {
    "፲": 10, "፳": 20, "፴": 30, "፵": 40, "፶": 50, "፷": 60, "፸": 70,
    "፹": 80, "፺": 90,
}
GEEZ_100 = "፻"
GEEZ_10000 = "፼"

_GEEZ_CHARS = set(GEEZ_DIGITS) | set(GEEZ_TENS) | {GEEZ_100, GEEZ_10000}

_EC_EPOCH = date(2007, 9, 12)  # Meskerem 1, 2000 EC

# (stripped) formats tried for receipt dates, in order.
_DATE_FORMATS = (
    "%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%d/%m/%Y", "%d-%m-%Y",
    "%d-%b-%Y", "%d %b %Y", "%d %b, %Y", "%b %d, %Y", "%b %d %Y",
    "%B %d, %Y", "%d %B %Y", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M",
    "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M",
)
_MONTH_ABBREV = {f"{m:02d}": m for m in range(1, 13)}

_DATE_RAW_RE = re.compile(
    r"(\d{1,4}|[\u1369-\u137c]+)[/.\-]"
    r"(\d{1,2}|[\u1369-\u137c]+)[/.\-]"
    r"(\d{2,4}|[\u1369-\u137c]+)"
)

_GEEZ_NUM_RE = re.compile(r"^[\u1369-\u137c]+$")


def _ec_year_len(year):
    return 360 + (6 if year % 4 == 3 else 5)


def parse_geez(text):
    """Parse a Ge'ez numeral string (e.g. ``፲፱፻፺፯`` = 1997).

    Returns an int, or ``None`` when the string is not a plain Ge'ez
    numeral. The Ge'ez system is additive: ፻ multiplies the preceding
    part by 100, ፼ by 10000.
    """
    if not text or not _GEEZ_NUM_RE.match(str(text).strip()):
        return None
    total = 0
    block = 0
    for char in str(text).strip():
        if char in GEEZ_DIGITS:
            block += GEEZ_DIGITS[char]
        elif char in GEEZ_TENS:
            block += GEEZ_TENS[char]
        elif char == GEEZ_100:
            block = (block or 1) * 100
            total += block
            block = 0
        elif char == GEEZ_10000:
            block = (block or 1) * 10000
            total += block
            block = 0
    return total + block


def geez_to_digits(text):
    """Convert a Ge'ez numeral inside a number into ASCII digits.

    Also handles Western decimal digits and mixed ``፲፱-፱፻፺፯`` forms by
    converting each numeral segment. Returns cleaned string or None.
    """
    value = parse_geez(text)
    if value is not None:
        return str(value)
    return None


def gregorian_to_ethiopian(gy, gm, gd):
    """Convert a Gregorian date ``(gy, gm, gd)`` to ``(ey, em, ed)`` EC."""
    days = (date(gy, gm, gd) - _EC_EPOCH).days
    ey = 2000
    if days >= 0:
        while days >= _ec_year_len(ey):
            days -= _ec_year_len(ey)
            ey += 1
    else:
        while days < 0:
            ey -= 1
            days += _ec_year_len(ey)
    month = days // 30 + 1
    day = days % 30 + 1
    return (ey, month, day)


def ethiopian_to_gregorian(ey, em, ed):
    """Convert an Ethiopian (civil) date to a ``datetime.date``."""
    days = 0
    if ey >= 2000:
        for y in range(2000, ey):
            days += _ec_year_len(y)
    else:
        for y in range(ey, 2000):
            days -= _ec_year_len(y)
    days += (em - 1) * 30 + (ed - 1)
    return _EC_EPOCH + timedelta(days=days)


def ec_readable(ey, em, ed):
    month = EC_MONTHS[em - 1] if 1 <= em <= 13 else "?"
    return f"{month} {ed}, {ey} ዓ.ም."


def _strip_time(text):
    # "9/12/2023, 10:30 AM" -> "9/12/2023"; "12-Sep-2023 14:00" -> ...
    text = re.sub(r"\s+\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM|am|pm)?$", "", text.strip())
    text = re.sub(
        r",?\s*\d{1,2}:\d{2}(:\d{2})?\s*(AM|PM|am|pm)?$", "", text.strip()
    )
    return text.strip()


def _parse_raw(text):
    """Try to parse a raw date string into a ``date``.

    Handles GC formats, EC years (1999-2025 interpreted as EC when the
    value cannot be a sane GC date), and Ge'ez numerals. Returns a
    ``date`` or ``None``. ``ec_year`` is set when the year denotes EC.
    """
    def try_formats(candidate):
        for fmt in _DATE_FORMATS:
            try:
                return datetime.strptime(candidate, fmt).date()
            except ValueError:
                continue
        return None

    stripped = _strip_time(text)
    for candidate in (stripped, stripped.replace("/", "-")):
        if not candidate:
            continue
        d = try_formats(candidate)
        if d:
            return d
        match = _DATE_RAW_RE.search(candidate)
        if match:
            parts = match.groups()
            converted = []
            for part in parts:
                num = parse_geez(part) or (int(part) if part.isdigit() else None)
                if num is None:
                    break
                converted.append(num)
            else:
                if len(converted) == 3:
                    a, b, c = converted
                    if c >= 1000 and a <= 12 and b <= 31:
                        try:
                            return date(c, a, b)
                        except ValueError:
                            pass
                    if a >= 1000 and b <= 12 and c <= 31:
                        try:
                            return date(a, b, c)
                        except ValueError:
                            pass
                    if c > 31 and a <= 31 and b <= 12:
                        try:
                            return date(c, b, a)
                        except ValueError:
                            pass
    return None


def parse_and_plausibility(text):
    """Classify a receipt date string.

    Returns an object with:

    - ``status``: ``ok`` | ``unparsable`` | ``future`` | ``old``
    - ``ec_readable``: Ethiopian-calendar rendering (if known)
    - ``gc_date``: the Gregorian date, or ``None``
    """
    class Result:
        def __init__(s, status, gc_date, ec):
            s.status = status
            s.gc_date = gc_date
            s.ec_readable = ec if ec else _ec_readable_or_none(gc_date)

        def __repr__(s):
            return f"<DateCheck {s.status} gc={s.gc_date} ec={s.ec_readable}>"

    today = date.today()
    gc = _parse_raw(str(text))
    if not gc:
        return Result("unparsable", None, None)

    # A year far outside a sane GC receipt window is re-read as an
    # Ethiopian-calendar year: EC 1999..2026 maps to GC 2006..2034, and
    # receipts are routinely dated in EC.
    if not (1980 <= gc.year <= today.year + 1):
        ec = _ec_year_to_gc(gc)
        if ec:
            ec_gc, ec_year = ec
            if ec_gc > today + timedelta(days=2):
                return Result("future", ec_gc, ec_readable(
                    ec_year, gc.month, gc.day))
            if ec_gc < today - timedelta(days=365 * 5):
                return Result("old", ec_gc, ec_readable(
                    ec_year, gc.month, gc.day))
            return Result("ok", ec_gc, ec_readable(ec_year, gc.month, gc.day))
        return Result("unparsable", gc, None)

    if gc > today + timedelta(days=2):
        return Result("future", gc, None)
    if gc < today - timedelta(days=365 * 5):
        return Result("old", gc, None)
    return Result("ok", gc, None)


def _ec_year_to_gc(d):
    """Read a date as Ethiopian-calendar and return its GC date (or None).

    An EC date (year == d.year) lands roughly 7-8 GC years later; both
    candidate readings are tried because months 9-13 of an EC year fall
    in the GC year after Meskerem.
    """
    for ec_year in (d.year, d.year - 1):
        try:
            candidate = ethiopian_to_gregorian(ec_year, d.month, d.day)
        except (ValueError, OverflowError):
            continue
        if 1900 <= candidate.year <= 2100:
            return (candidate, ec_year)
    return None


def _ec_readable_or_none(gc_date):
    if not gc_date:
        return None
    ey, em, ed = gregorian_to_ethiopian(
        gc_date.year, gc_date.month, gc_date.day
    )
    return ec_readable(ey, em, ed)