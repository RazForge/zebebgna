<div align="center">
  <img src="logo.png" alt="Zebebgna Logo" width="200"/>
  <h1>Zebebgna</h1>
  <p><strong>"guard"</strong> · Defensive verification of Ethiopian bank receipts</p>

  [![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0f172a)]()
  [![Banks](https://img.shields.io/badge/Banks-6%20supported-1d4ed8)]()
  [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![Tests](https://img.shields.io/badge/Tests-174%20passing-brightgreen)]()
</div>

---

## What is this?

A receipt is only as trustworthy as its source. **Zebebgna** is a cybersecurity toolkit that keeps fake and tampered Ethiopian bank receipts out of your hands. It extracts receipt data from **six major banks** — CBE, Dashen, Awash, BOA, Zemen, and Telebirr — then puts that data on trial:

- Checks the serving website's **security posture**
- Flags **phishing lookalikes** and typosquatting domains
- **Reconciles amounts** (transferred + fees = total)
- Validates every **reference number**
- Fuses all signals into a clear **0–100 risk score**

**Result:** a color-coded verdict — **Good**, **Needs review**, or **Problem found**.

---

## Why does this matter?

> **In 2025, Ethiopian bank fraud via fake receipts surged.** Scammers create pixel-perfect copies of bank receipts or host them on phishing domains that look like `apps.cbe.com.et`. Victims lose millions of Birr trusting receipts that were never real.

Zebebgna catches what visual inspection misses:

| Check | What it catches |
|-------|----------------|
| **Phishing domain detection** | Typosquatting, punycode IDN attacks, suspicious TLDs (.xyz, .top, .tk) |
| **TLS certificate audit** | Expired certs, weak protocols (TLS 1.0/1.1), hostname mismatches |
| **Amount reconciliation** | Math that doesn't add up (transferred + commission + VAT ≠ total) |
| **Reference format validation** | Fake transaction IDs that don't match bank patterns |
| **Community threat database** | Domains reported by other users as phishing |
| **Threat fusion engine** | Correlates weak signals into attack scenarios with risk scoring |

---

## Quick start

```bash
# Install
pip install -e .

# Verify a receipt (Python)
from zebebgna import verify_receipt
report = verify_receipt("cbe", "https://apps.cbe.com.et:100/?id=FT25211G11JQ21827223")
print(report.score, report.status)  # e.g. 74 REVIEW

# Verify via CLI
zebebgna verify cbe "https://apps.cbe.com.et:100/?id=FT25211G11JQ21827223"
zebebgna verify tele CHQ0FJ403O

# Web UI (for non-technical users)
pip install -e ".[web]"
python webapp.py
# Open http://127.0.0.1:5000
```

---

## Features

- **Strict TLS everywhere** — plain-HTTP URLs are refused; every fetch verifies the full certificate chain
- **Phishing detection** — raw IPs, lookalike domains, punycode IDN, URL shorteners, suspicious TLDs
- **TLS certificate audit** — chain validation, SAN check, expiry, protocol version enforcement
- **Security headers audit** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Authenticity verification** — amount cross-checks, reference format validation, status checks
- **Amount-in-words parsing** — English and Amharic number words, cross-referenced against digits
- **Ethiopian calendar support** — Ge'ez numeral parsing, EC/GC date conversion
- **Threat fusion engine** — deterministic rule-based correlation of weak signals into attack scenarios
- **Community phishing database** — user-reported domains raise error-level correlations
- **OCR/PDF extraction** — Tesseract for images, pdfplumber for PDFs, QR code decoding
- **Telegram bot** — `/verify` commands, photo/PDF upload support
- **LLM review** — optional OpenAI-compatible AI verdict layer (Ollama, DeepSeek, etc.)

---

## Supported banks

| Bank | Extraction method | Amount math verified |
|------|-------------------|---------------------|
| **CBE** (Commercial Bank of Ethiopia) | PDF regex | transferred + commission + VAT = total debited |
| **Dashen Bank** | PDF regex | amount + service charge + VAT = total |
| **Awash Bank** | HTML table scraping | Amount + Charge + VAT = Total |
| **Bank of Abyssinia (BOA)** | Headless Chrome (Selenium) | Transferred + Service Charge + VAT = Total |
| **Zemen Bank** | PDF regex | Settled Amount + Service Charge + VAT = Total Paid |
| **Telebirr** (Ethio Telecom) | HTML scraping | amount + service charge = total paid |

---

## Security hardening

Zebebgna practices what it preaches:

- **No `verify_ssl=False`** — ever. All network goes through `SecureFetcher` with strict TLS
- **SSRF protection** — private/internal IPs blocked, DNS rebinding mitigation, per-redirect validation
- **CSRF protection** — all POST routes require tokens
- **Rate limiting** — 30 requests/minute/IP on the web UI
- **File size limits** — 10 MB max for uploads
- **Fail-safe design** — LLM failures, OCR unavailability, and network errors never crash the pipeline

---

## Contributing

We want your help! Here are ways to contribute:

1. **Test with real receipts** — run `zebebgna verify` against your own receipts and report if fields are missing or amounts are wrong
2. **Report phishing domains** — `zebebgna feedback <check_id> --report-phish "description"` adds to the community threat database
3. **Add bank support** — extractors are modular (one file per bank in `zebebgna/extractors/`)
4. **Improve the threat fusion engine** — add new correlation rules in `zebebgna/fusion.py`
5. **Translate the UI** — help make the web UI available in Amharic

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.

---

## Questions? Ideas? Found a bug?

**Open an issue!** We'd love to hear from you:

- [Bug report](https://github.com/RazForge/zebebgna/issues/new?template=bug_report.md)
- [Feature request](https://github.com/RazForge/zebebgna/issues/new?template=feature_request.md)
- [Security vulnerability](https://github.com/RazForge/zebebgna/security/advisories/new)
- [General discussion](https://github.com/RazForge/zebebgna/discussions)

---

## Architecture

```
zebebgna/
  __init__.py          # Public API: verify_receipt, audit_receipt_url
  fetch.py             # SecureFetcher: HTTPS-only, SSRF protection, TLS verification
  fusion.py            # Threat-fusion engine: 0-100 risk score, correlation rules
  history.py           # SQLite persistence, community threat database, feedback loop
  vision.py            # OCR (Tesseract), PDF extraction, QR decoding
  words.py             # English/Amharic number word parsing
  dates.py             # Ethiopian calendar (EC/GC) conversion, Ge'ez numerals
  llm.py               # Optional LLM verdict layer (Ollama, DeepSeek, OpenAI)
  bot.py               # Telegram bot interface
  cli.py               # Command-line interface
  report.py            # VerificationReport data model, scoring
  extractors/          # Per-bank receipt data extraction
    cbe.py             # CBE PDF extraction
    dashen.py          # Dashen Bank PDF extraction
    awash.py           # Awash Bank HTML table extraction
    boa.py             # BOA headless Chrome extraction
    zemen.py           # Zemen Bank PDF extraction
    tele.py            # Telebirr HTML extraction
  verifiers/           # Security and authenticity checks
    phishing.py        # URL phishing heuristics
    tls.py             # TLS certificate audit
    headers.py         # HTTP security headers audit
    integrity.py       # Amount math, reference format, status checks
    fingerprint.py     # Per-bank layout fingerprinting
  templates/           # Flask HTML templates
  static/              # Static assets (logo, CSS)
webapp.py              # Flask web UI entry point
```

---

## Testing

```bash
pip install pytest
pytest tests/ -q        # 174 tests, all pass
```

Tests use mocked network (no live receipt endpoints). Coverage includes:
- SSRF protection and redirect validation
- Phishing domain detection
- TLS certificate handling
- Amount reconciliation for all 6 banks
- Amharic/English word parsing
- Ethiopian calendar conversion
- CLI commands
- Web UI routes
- Telegram bot parsing
- Threat fusion engine

---

## License

MIT License. See [LICENSE](LICENSE).

---

<div align="center">
  <p>Built with care for the Ethiopian financial security community.</p>
  <p>
    <a href="https://github.com/RazForge/zebebgna/issues">Report a bug</a> ·
    <a href="https://github.com/RazForge/zebebgna/discussions">Start a discussion</a> ·
    <a href="https://github.com/RazForge/zebebgna/pulls">Submit a PR</a>
  </p>
</div>
