"""Extractors for Ethiopian bank receipt formats.

All extraction goes through :mod:`zebebgna.fetch`'s ``SecureFetcher``,
which refuses plain-HTTP URLs and always verifies TLS certificates.
"""

from . import awash, boa, cbe, dashen, tele, zemen

EXTRACTORS = {
    "cbe": cbe.extract_cbe_receipt_info,
    "dashen": dashen.extract_dashen_receipt_data,
    "awash": awash.extract_awash_receipt_data,
    "boa": boa.extract_boa_receipt_data,
    "zemen": zemen.extract_zemen_receipt_data,
    "tele": tele.extract_tele_receipt_data,
}

__all__ = ["EXTRACTORS", "cbe", "dashen", "awash", "boa", "zemen", "tele"]
