<div align="center">
  <img src="zebebgna-logo.png" alt="Zebebgna Logo" width="220"/>
  <h1>ZEBEGNA</h1>
  <p><strong>🇿🇪 Guard — Defensive Verification of Ethiopian Bank Receipts</strong></p>
  <p>Secure · Verified · Trusted</p>

  [![Python 3.8+](https://img.shields.io/badge/python-3.8+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-RazForge%20Source--Available-orange.svg)](LICENSE)
  [![Tests](https://img.shields.io/badge/Tests-174%20passing-brightgreen.svg)]()
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0f172a.svg)]()
  [![Banks](https://img.shields.io/badge/Banks-6%20supported-1d4ed8.svg)]()
  [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## What is Zebebgna?

**Zebebgna** (Amharic: ዘበኛ — "guard") is a cybersecurity toolkit that verifies the authenticity of Ethiopian bank receipts. It extracts receipt data from **six major banks**, then puts that data on trial through a multi-layered verification pipeline.

In 2025, Ethiopian bank fraud via fake receipts surged. Scammers create pixel-perfect copies of bank receipts or host them on phishing domains that look like `apps.cbe.com.et`. Victims lose millions of Birr trusting receipts that were never real.

**Zebebgna catches what visual inspection misses.**

---

## How it works

```
Receipt Input (URL / PDF / Screenshot / Text)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                   EXTRACTION LAYER                       │
│  CBE · Dashen · Awash · BOA · Zemen · Telebirr           │
│  PDF regex · HTML scraping · Headless Chrome · OCR        │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   VERIFICATION LAYER                     │
│  Phishing detection · TLS audit · Amount reconciliation  │
│  Reference validation · Security headers · DNS checks    │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    FUSION ENGINE                         │
│  Correlates weak signals into attack scenarios           │
│  Produces a deterministic 0–100 risk score               │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │   VERDICT       │
                 │  ✅ Good        │
                 │  ⚠️  Needs Review│
                 │  ❌ Problem     │
                 └─────────────────┘
```

---

## Features

### Extraction

- **6 banks supported** — CBE, Dashen, Awash, Bank of Abyssinia, Zemen, Telebirr
- **Multiple input formats** — URLs, PDFs, images (OCR), QR codes, pasted text
- **Amount-in-words parsing** — English and Amharic number words, cross-referenced against digits
- **Ethiopian calendar support** — Ge'ez numeral parsing, EC/GC date conversion

### Verification

- **Phishing domain detection** — Typosquatting, punycode IDN attacks, suspicious TLDs (.xyz, .top, .tk), URL shorteners
- **TLS certificate audit** — Chain validation, SAN check, expiry, protocol version enforcement (TLS 1.2+)
- **Security headers audit** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **Amount reconciliation** — transferred + commission + VAT = total debited
- **Reference format validation** — Fake transaction IDs that don't match bank patterns
- **Community threat database** — Domains reported by other users as phishing

### Intelligence

- **Threat fusion engine** — Deterministic rule-based correlation of weak signals into attack scenarios with risk scoring
- **LLM review** — Optional OpenAI-compatible AI verdict layer (Ollama, DeepSeek, etc.)
- **Telegram bot** — `/verify` commands, photo/PDF upload support
- **Web UI** — Flask-based interface for non-technical users

### Security

- **No `verify_ssl=False`** — ever. All network goes through `SecureFetcher` with strict TLS
- **SSRF protection** — Private/internal IPs blocked, DNS rebinding mitigation, per-redirect validation
- **CSRF protection** — All POST routes require tokens
- **Rate limiting** — 30 requests/minute/IP on the web UI
- **File size limits** — 10 MB max for uploads
- **Fail-safe design** — LLM failures, OCR unavailability, and network errors never crash the pipeline

---

## Getting Started

### Quick Start (Windows)

1. **Install Python** — Download from [python.org](https://www.python.org/downloads/) (check "Add Python to PATH")
2. **Double-click `start.bat`** — It installs everything and opens the app in your browser
3. **Verify a receipt** — Paste a receipt URL or upload a PDF

That's it. No command line needed.

### Manual Installation

```bash
git clone https://github.com/RazForge/zebebgna.git
cd zebebgna
pip install -e .
```

### Verify a receipt

```python
from zebebgna import verify_receipt

report = verify_receipt("cbe", "https://apps.cbe.com.et:100/?id=FT25211G11JQ21827223")
print(report.score, report.status)  # e.g. 74 REVIEW
```

### CLI

```bash
zebebgna verify cbe "https://apps.cbe.com.et:100/?id=FT25211G11JQ21827223"
zebebgna verify tele CHQ0FJ403O
```

### Web UI

```bash
pip install -e ".[web]"
python webapp.py
# Open http://127.0.0.1:5000
```

---

## Supported Banks

| Bank | Extraction | Amount Math |
|------|-----------|-------------|
| **CBE** (Commercial Bank of Ethiopia) | PDF regex | transferred + commission + VAT = total debited |
| **Dashen Bank** | PDF regex | amount + service charge + VAT = total |
| **Awash Bank** | HTML table scraping | Amount + Charge + VAT = Total |
| **Bank of Abyssinia (BOA)** | Headless Chrome (Selenium) | Transferred + Service Charge + VAT = Total |
| **Zemen Bank** | PDF regex | Settled Amount + Service Charge + VAT = Total Paid |
| **Telebirr** (Ethio Telecom) | HTML scraping | amount + service charge = total paid |

---

## Architecture

```
zebebgna/
├── __init__.py              # Public API: verify_receipt, audit_receipt_url
├── fetch.py                 # SecureFetcher: HTTPS-only, SSRF protection
├── fusion.py                # Threat-fusion engine: 0-100 risk score
├── history.py               # SQLite persistence, community threat database
├── vision.py                # OCR (Tesseract), PDF extraction, QR decoding
├── words.py                 # English/Amharic number word parsing
├── dates.py                 # Ethiopian calendar (EC/GC) conversion
├── llm.py                   # Optional LLM verdict layer
├── bot.py                   # Telegram bot interface
├── cli.py                   # Command-line interface
├── report.py                # VerificationReport data model
├── extractors/
│   ├── cbe.py               # CBE PDF extraction
│   ├── dashen.py            # Dashen Bank PDF extraction
│   ├── awash.py             # Awash Bank HTML table extraction
│   ├── boa.py               # BOA headless Chrome extraction
│   ├── zemen.py             # Zemen Bank PDF extraction
│   └── tele.py              # Telebirr HTML extraction
├── verifiers/
│   ├── phishing.py          # URL phishing heuristics
│   ├── tls.py               # TLS certificate audit
│   ├── headers.py           # HTTP security headers audit
│   ├── integrity.py         # Amount math, reference format validation
│   └── fingerprint.py       # Per-bank layout fingerprinting
├── templates/               # Flask HTML templates
└── static/                  # Static assets (logo, CSS)
webapp.py                    # Flask web UI entry point
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Language** | Python 3.8+ |
| **Network** | requests, urllib3 (strict TLS) |
| **PDF parsing** | pdfplumber |
| **OCR** | Tesseract (pytesseract) |
| **Browser automation** | Selenium (headless Chrome) |
| **Web UI** | Flask |
| **Bot** | python-telegram-bot |
| **Database** | SQLite |
| **LLM** | OpenAI-compatible API (Ollama, DeepSeek, etc.) |
| **Testing** | pytest |

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

## Contributing

We want your help! Here are ways to contribute:

1. **Test with real receipts** — run `zebebgna verify` against your own receipts and report if fields are missing or amounts are wrong
2. **Report phishing domains** — `zebebgna feedback <check_id> --report-phish "description"` adds to the community threat database
3. **Add bank support** — extractors are modular (one file per bank in `zebebgna/extractors/`)
4. **Improve the threat fusion engine** — add new correlation rules in `zebebgna/fusion.py`
5. **Translate the UI** — help make the web UI available in Amharic

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.

---

## Security

If you discover a security vulnerability, please report it responsibly:

- [Security vulnerability](https://github.com/RazForge/zebebgna/security/advisories/new)

Do **not** open a public issue for security vulnerabilities.

---

## License

This project is licensed under the **RazForge Source-Available License**.

### You CAN

- View, download, and study the source code
- Use the Software for personal learning and education
- Use the Software for non-commercial research and experimentation
- Create private modifications for permitted purposes
- Conduct authorized security research

### You CANNOT

- Commercially use, sell, or distribute the Software
- Incorporate the Software into a commercial product or service
- Publicly fork the repository without written permission
- Sublicense or redistribute the Software
- Use RazForge trademarks or imply official endorsement

### Attribution Required

Any permitted use must preserve attribution to the Copyright Holder, RazForge Lab, and RazForge organization.

### Commercial Use

Commercial use requires a separate written license. Contact: [razforge@hotmail.com](mailto:razforge@hotmail.com)

### Full License

See [LICENSE](LICENSE) for the complete 28-section license document.

---

<div align="center">
  <p><strong>Built with care for the Ethiopian financial security community.</strong></p>
  <p>
    <a href="https://github.com/RazForge/zebebgna/issues">Report a bug</a> ·
    <a href="https://github.com/RazForge/zebebgna/discussions">Start a discussion</a> ·
    <a href="https://github.com/RazForge/zebebgna/pulls">Submit a PR</a>
  </p>
  <br>
  <p>
    <a href="https://github.com/RazForge">
      <img src="https://img.shields.io/badge/Part%20of-RazForge-blue?style=for-the-badge&logo=github" alt="Part of RazForge"/>
    </a>
  </p>
</div>
