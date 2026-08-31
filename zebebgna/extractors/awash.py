"""Awash Bank receipt extraction (HTML table) with secure fetching."""

import logging

from bs4 import BeautifulSoup

from zebebgna.fetch import fetcher

log = logging.getLogger(__name__)


def extract_awash_receipt_data(url):
    response = fetcher.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    rows = soup.select("table.info-table tr")

    data = {}
    for row in rows:
        cells = row.find_all("td")
        if len(cells) == 3:
            key = cells[0].text.strip().rstrip(":")
            value = cells[2].text.strip()
            data[key] = value

    keys_of_interest = [
        "Transaction Time", "Transaction Type", "Amount", "Charge", "VAT",
        "Total", "Sender Name", "Sender Account", "Beneficiary name",
        "Beneficiary Account", "Beneficiary Bank", "Reason", "Transaction ID",
    ]

    result = {k: data.get(k) for k in keys_of_interest}
    missing = [k for k, v in result.items() if v is None]
    if missing:
        log.warning("Awash extraction missing fields: %s", ", ".join(missing))
    return result
