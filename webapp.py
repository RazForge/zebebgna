"""Simple web UI for non-technical users.

Run locally with:

    pip install flask
    python webapp.py
    -> open http://127.0.0.1:5000

Optional hardening: set zebebgna_ALLOWED_HOSTS to a comma-separated
list of hostnames the server may fetch (SSRF guard). When unset, only
HTTPS URLs are accepted (enforced by the secure fetcher).
"""

import os
from urllib.parse import urlparse

from flask import Flask, render_template, request

from zebebgna import verify_receipt
from zebebgna.fetch import InsecureURLError

PKG_DIR = os.path.dirname(os.path.abspath(__import__("zebebgna").__file__))
TEMPLATE_DIR = os.path.join(PKG_DIR, "templates")
app = Flask(__name__, template_folder=TEMPLATE_DIR)

BANK_NAMES = {
    "cbe": "Commercial Bank of Ethiopia (CBE)",
    "dashen": "Dashen Bank",
    "awash": "Awash Bank",
    "boa": "Bank of Abyssinia (BOA)",
    "zemen": "Zemen Bank",
    "tele": "Telebirr (Ethio Telecom)",
}

SEVERITY_LABELS = {
    "critical": "Critical",
    "error": "Error",
    "warn": "Warning",
    "info": "Note",
}

ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("zebebgna_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}


def _host_allowed(url):
    if not ALLOWED_HOSTS:
        return True
    host = (urlparse(url).hostname or "").lower()
    return host in ALLOWED_HOSTS or any(host.endswith("." + h) for h in ALLOWED_HOSTS)


def _normalize_url(bank, url_or_id):
    url = url_or_id
    if not url.startswith("http") and bank == "tele":
        url = f"https://transactioninfo.ethiotelecom.et/receipt/{url_or_id}"
    return url


@app.route("/")
def index():
    return render_template("index.html", banks=BANK_NAMES)


@app.route("/verify", methods=["POST"])
def verify():
    bank = request.form.get("bank", "").strip().lower()
    url_or_id = request.form.get("url_or_id", "").strip()

    if not url_or_id:
        return render_template(
            "index.html", banks=BANK_NAMES,
            error="Please paste a receipt link (or Telebirr receipt ID) first.",
        )

    url = _normalize_url(bank, url_or_id)
    if url.startswith("http"):
        if not _host_allowed(url):
            return render_template(
                "index.html", banks=BANK_NAMES,
                error=(
                    "This link points to a website that is not in the allowed "
                    "list. Only trusted receipt websites can be checked."
                ),
            )
    else:
        return render_template(
            "index.html", banks=BANK_NAMES,
            error="That does not look like a valid receipt link.",
        )

    try:
        report = verify_receipt(bank, url_or_id)
    except (ValueError, InsecureURLError) as exc:
        return render_template(
            "index.html", banks=BANK_NAMES, error=f"Could not verify: {exc}"
        )
    except Exception as exc:
        return render_template(
            "index.html", banks=BANK_NAMES,
            error=(
                "Something went wrong while checking this receipt. "
                "Please check the link and try again."
            ),
        )

    return render_template(
        "report.html",
        report=report,
        bank_name=BANK_NAMES.get(report.bank, report.bank),
        severity_labels=SEVERITY_LABELS,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
