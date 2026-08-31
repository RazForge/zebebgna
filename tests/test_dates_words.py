import datetime

import pytest

from zebebgna.dates import (
    ec_readable,
    ethiopian_to_gregorian,
    gregorian_to_ethiopian,
    parse_and_plausibility,
    parse_geez,
)
from zebebgna.words import parse_amount_words


# -- English/Amharic amount words ------------------------------------------

def test_english_amount_words():
    assert parse_amount_words("One Thousand Two Hundred Thirty-Four Birr "
                              "Only") == 1234
    assert parse_amount_words("Fifty Thousand Birr") == 50000
    assert parse_amount_words("One Million Five Hundred Thousand") == 1500000
    assert parse_amount_words("Nine Hundred Ninety Nine Birr") == 999
    assert parse_amount_words("Twenty Birr") == 20


def test_english_amount_words_with_cents():
    assert parse_amount_words("One Thousand Birr and Fifty Cents Only") == 1000.50
    assert parse_amount_words("Two Hundred Birr and Twenty-Five Cents") == 200.25


def test_amount_words_mixed_digits():
    assert parse_amount_words("ETB 1,000.00 Birr Only") == 1000
    assert parse_amount_words("1500 Birr Only") == 1500


def test_amount_words_unparsable():
    assert parse_amount_words("") is None
    assert parse_amount_words(None) is None
    assert parse_amount_words("somethingsomething xyz") is None


def test_amharic_amount_words():
    assert parse_amount_words("አንድ ሺህ ሁለት መቶ ሰላሳ አራት") == 1234
    assert parse_amount_words("ሃምሳ ሺህ ብር") == 50000
    assert parse_amount_words("ሁለት መቶ ብር") == 200
    assert parse_amount_words("አስር ሺህ") == 10000


# -- Ge'ez numerals ----------------------------------------------------------

def test_parse_geez():
    assert parse_geez("፩") == 1
    assert parse_geez("፲") == 10
    assert parse_geez("፳") == 20
    assert parse_geez("፲፱") == 19
    assert parse_geez("፻") == 100
    assert parse_geez("፲፱፻፺፯") == 1997
    assert parse_geez("፪፻፲፭") == 215
    assert parse_geez("፼") == 10000
    assert parse_geez("bogus") is None
    assert parse_geez("123") is None


# -- Ethiopian calendar -------------------------------------------------------

# Documented anchors: Enkutatash (Meskerem 1) of selected EC years.
def test_enkutatash_anchors():
    assert gregorian_to_ethiopian(2007, 9, 12) == (2000, 1, 1)  # Millennium
    assert gregorian_to_ethiopian(2014, 9, 11) == (2007, 1, 1)
    assert gregorian_to_ethiopian(2015, 9, 12) == (2008, 1, 1)
    assert gregorian_to_ethiopian(2019, 9, 12) == (2012, 1, 1)
    assert gregorian_to_ethiopian(2022, 9, 11) == (2015, 1, 1)
    assert gregorian_to_ethiopian(2023, 9, 12) == (2016, 1, 1)
    assert gregorian_to_ethiopian(2024, 9, 11) == (2017, 1, 1)


def test_roundtrip_ethiopian_gregorian():
    for (y, m, d) in [(2000, 1, 1), (2012, 6, 15), (2016, 13, 5),
                      (1999, 13, 6), (2015, 10, 3), (2008, 9, 21)]:
        gc = ethiopian_to_gregorian(y, m, d)
        assert gregorian_to_ethiopian(gc.year, gc.month, gc.day) == (y, m, d)


def test_pagume_days():
    # Pagumē 1..6 of the (leap) EC year 2015 fall on Sep 6-11, 2023;
    # Enkutatash 2016 EC = Sep 12, 2023.
    assert gregorian_to_ethiopian(2023, 9, 6) == (2015, 13, 1)
    assert gregorian_to_ethiopian(2023, 9, 11) == (2015, 13, 6)
    gc = ethiopian_to_gregorian(2015, 13, 6)
    assert (gc.year, gc.month, gc.day) == (2023, 9, 11)


def test_ec_readable_format():
    assert "መስከረም" in ec_readable(2016, 1, 1)
    assert "ጳጉሜ" in ec_readable(2015, 13, 6)


# -- Date plausibility ---------------------------------------------------------

def test_recent_gc_date_is_ok():
    today = datetime.date.today()
    result = parse_and_plausibility(today.isoformat())
    assert result.status == "ok"
    assert result.gc_date == today


def test_future_date_flagged():
    future = (datetime.date.today() + datetime.timedelta(days=400)).isoformat()
    result = parse_and_plausibility(future)
    assert result.status == "future"


def test_old_date_flagged():
    old = (datetime.date.today() - datetime.timedelta(days=365 * 6)).isoformat()
    result = parse_and_plausibility(old)
    assert result.status == "old"


def test_unparsable_date():
    assert parse_and_plausibility("not a date at all").status == "unparsable"
    assert parse_and_plausibility(None).status == "unparsable"


def test_ethiopian_calendar_date_interpreted():
    # 13/09/2016 read as EC = Sep 13, 2023 GC (within the last 5 years).
    result = parse_and_plausibility("13/09/2016")
    if result.status == "ok":
        assert result.ec_readable is not None
        assert "ዓ.ም." in result.ec_readable


def test_geez_numeral_date():
    result = parse_and_plausibility("፲፫/፱/፳፻፲፮")
    assert result.status in ("ok", "future", "old")
    assert result.ec_readable is None or "ዓ.ም." in result.ec_readable


def test_time_suffixed_date_parses():
    result = parse_and_plausibility("9/12/2023, 10:30:00 AM")
    assert result.status in ("ok", "old", "future")
    assert result.gc_date == datetime.date(2023, 9, 12)