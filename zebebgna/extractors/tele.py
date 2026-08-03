"""Telebirr (Ethio Telecom) receipt extraction with secure fetching."""

import re
from typing import Dict

from bs4 import BeautifulSoup

from zebebgna.fetch import fetcher


def extract_tele_receipt_data(url_or_id: str) -> Dict[str, str]:
    """Extract Telebirr receipt details from a URL or bare receipt ID."""
    if not url_or_id:
        raise ValueError("Telebirr receipt id or URL is required")

    url = url_or_id if url_or_id.startswith(
        "http") else f"https://transactioninfo.ethiotelecom.et/receipt/{url_or_id}"

    soup = BeautifulSoup(fetcher.fetch_text(url), "html.parser")
    data: Dict[str, str] = {}

    def pick(label_regex: str, key: str):
        node = soup.find(string=re.compile(label_regex, re.I))
        if node:
            td = node.find_next("td")
            if td:
                data[key] = td.get_text(strip=True)

    pick(r"Payer\s*Name", "payer_name")
    pick(r"Payer\s*telebirr", "payer_number")
    pick(r"Credited\s*Party\s*name", "credited_party")
    pick(r"Credited\s*party\s*account\s*no", "credited_party_number")
    pick(r"transaction\s*status", "status")
    pick(r"Total\s*Paid\s*Amount", "total_paid")

    return data
