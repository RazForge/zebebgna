"""Bank of Abyssinia (BOA) receipt extraction via headless Chrome.

BOA receipts render client-side, so a Selenium WebDriver is required.
The driver is created headless and cached for reuse across calls; it is
quit automatically when the process exits (via ``atexit``) so repeated
verifications do not leak Chrome processes.
"""

import atexit
import time
from functools import lru_cache

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from zebebgna.fetch import fetcher, validate_fetch_target


@lru_cache(maxsize=1)
def get_chrome_driver():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    driver = webdriver.Chrome(options=options)
    atexit.register(driver.quit)
    return driver


def extract_boa_receipt_data(url):
    # The browser follows redirects itself, so the entry URL and the
    # post-redirect destination are both validated against the SSRF policy
    # (HTTPS-only, no private/internal hosts, optional allowlist).
    validate_fetch_target(url, fetcher.allowed_hosts)
    driver = get_chrome_driver()
    driver.get(url)
    time.sleep(2)
    validate_fetch_target(driver.current_url, fetcher.allowed_hosts)

    soup = BeautifulSoup(driver.page_source, "html.parser")

    data = {}
    for row in soup.select("table tr"):
        cells = row.find_all("td")
        if len(cells) == 2:
            key = cells[0].text.strip().rstrip(":")
            value = cells[1].text.strip()
            data[key] = value

    return {
        "Source Account": data.get("Source Account"),
        "Source Account Name": data.get("Source Account Name"),
        "Receiver's Account": data.get("Receiver's Account"),
        "Receiver's Name": data.get("Receiver's Name"),
        "Transferred Amount": data.get("Transferred amount"),
        "Service Charge": data.get("Service Charge"),
        "VAT": data.get("VAT (15%)"),
        "Total Amount": data.get("Total Amount"),
        "Transaction Type": data.get("Transaction Type"),
        "Transaction Date": data.get("Transaction Date"),
        "Transaction Reference": data.get("Transaction Reference"),
        "Narrative": data.get("Narrative"),
    }
