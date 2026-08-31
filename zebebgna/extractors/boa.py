"""Bank of Abyssinia (BOA) receipt extraction via headless Chrome.

BOA receipts render client-side, so a Selenium WebDriver is required.
The driver is created headless and cached for reuse across calls; it is
quit automatically when the process exits (via ``atexit``) so repeated
verifications do not leak Chrome processes.
"""

import atexit
import logging
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from zebebgna.fetch import fetcher, validate_fetch_target

log = logging.getLogger(__name__)

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

_driver = None


def get_chrome_driver():
    global _driver
    if _driver is not None:
        try:
            _driver.title  # quick health check
            return _driver
        except Exception:
            _driver = None  # driver is dead, create a new one
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-background-networking")
    _driver = webdriver.Chrome(options=options)
    atexit.register(lambda: _driver.quit() if _driver else None)
    return _driver


def extract_boa_receipt_data(url):
    validate_fetch_target(url, fetcher.allowed_hosts)
    driver = get_chrome_driver()
    driver.get(url)

    # Wait for a table to appear (up to 10s) instead of a fixed sleep
    try:
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located(("css selector", "table tr"))
        )
    except Exception:
        log.warning("BOA page did not render table within 10s for %s", url)

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
