"""Telebirr (Ethio Telecom) receipt extraction with secure fetching."""

import re
from typing import Dict

from bs4 import BeautifulSoup

from zebebgna.fetch import fetcher

# Total Paid Amount is the only reliable amount on Telebirr receipts; the
# breakdown (principal + service charge) is not exposed as separate labelled
# fields, so no "amount" pick is attempted (it would match ambiguous text).
PICKS = (
    (r"Payer\s*Name", "payer_name"),
    (r"Payer\s*telebirr", "payer_number"),
    (r"Credited\s*Party\s*name", "credited_party"),
    (r"Credited\s*party\s*account\s*no", "credited_party_number"),
    (r"transaction\s*status", "status"),
    (r"Receipt\s*No", "reference_no"),
    (r"Service\s*Charge", "service_charge"),
    (r"Total\s*Paid\s*Amount", "total_paid"),
)


def _extract_from_soup(soup: BeautifulSoup) -> Dict[str, str]:
    data: Dict[str, str] = {}

    def pick(label_regex: str, key: str):
        node = soup.find(string=re.compile(label_regex, re.I))
        if node:
            td = node.find_next("td")
            if td:
                data[key] = td.get_text(strip=True)

    for label_regex, key in PICKS:
        pick(label_regex, key)
    return data


def extract_tele_receipt_data(url_or_id: str) -> Dict[str, str]:
    """Extract Telebirr receipt details from a URL or bare receipt ID."""
    if not url_or_id:
        raise ValueError("Telebirr receipt id or URL is required")

    url = url_or_id if url_or_id.startswith(
        "http") else f"https://transactioninfo.ethiotelecom.et/receipt/{url_or_id}"

    soup = BeautifulSoup(fetcher.fetch_text(url), "html.parser")
    return _extract_from_soup(soup)
