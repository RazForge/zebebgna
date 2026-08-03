# Zebebgna — Project Memory (AGENTS.md)

When the user says "Zebegna" / "Zebebgna", this is the project they mean. Read this
file first to recall the full context before doing any work on it.

## Project identity
- **Name:** Zebebgna (previously named "zabagna", originally based on `ethiobank-receipts`)
- **Meaning:** Amharic for "guard"
- **Purpose:** Defensive cybersecurity toolkit that verifies the authenticity of
  Ethiopian bank receipts and audits the security posture of the endpoints that serve them.
- **Repo:** https://github.com/natahanjr/zebebgna (public, main branch)
- **Location on disk:** `F:\My Project\zebebgna`

## What it does
- Extracts receipt data from 6 Ethiopian banks/mobile money: CBE, Dashen, Awash,
  BOA, Zemen, Telebirr (extractors in `zebebgna/extractors/`)
- Runs 4 verifier groups (`zebebgna/verifiers/`): phishing (URL heuristics),
  TLS (cert chain/hostname/expiry), security headers (HSTS/CSP/XFO/etc.),
  integrity (amount math, reference formats, status, completeness)
- Produces a `VerificationReport` with 0–100 score and PASS / REVIEW / FAIL verdict
  (any critical finding forces FAIL)
- Never fetches plain HTTP — `SecureFetcher` (zebebgna/fetch.py) enforces HTTPS +
  strict TLS verification (the original project had `verify_ssl=False`; we removed that)

## Interfaces
- **CLI:** `zebebgna verify <bank> <url_or_id>` and `zebebgna audit <url>`
  (module form: `python -m zebebgna.cli`)
- **Python API:** `verify_receipt(bank, url_or_id)`, `audit_receipt_url(url)`
- **Web UI (for non-technical users):** `python webapp.py` → http://127.0.0.1:5000
  (Flask; form + color-coded verdict page; optional SSRF allowlist via
  `RECEIPTGUARD_ALLOWED_HOSTS` env var — note: env var name kept as RECEIPTGUARD_*)
- **Docs:** `docs/Zebebgna-Documentation.html` + `.pdf` (13 pages, generated via
  Edge headless `--print-to-pdf`)

## How to install / test
```
cd F:\My Project\zebebgna
py -m pip install -e ".[web]"     # core + Flask web UI
py -m pytest tests/ -q            # 25 tests, all pass
py webapp.py                      # start web UI
```
Note: on this machine `python` is not on PATH — use `py` (Python 3.14.4).
Deps: requests, pdfplumber, beautifulsoup4, selenium (+ flask for web).
BOA extractor needs ChromeDriver (selenium).

## Key decisions / history
1. Built from `ethiobank-receipts` (scraper) as a DEFENSIVE security project —
   no offensive tooling, no verify_ssl=False, ethics section in README.
2. Renamed twice: receiptguard → zabagna → zebebgna (user-chosen name).
3. Templates live inside the package (`zebebgna/templates/`) so wheels work;
   `pyproject.toml` pins `[tool.setuptools.packages.find]` and package-data.
4. Web UI serves non-technical users: pick bank → paste receipt link → verdict.
5. Scoring: info=-2, warn=-10, error=-20, critical=-40; >=85 PASS, 55–84 REVIEW, <55 FAIL.
6. Tests use mocked network (no live receipt endpoints in the suite).
7. PDF docs generated with Edge headless; keep `docs/Zebebgna-Documentation.html`
   as the editable source.

## Environment specifics
- Windows (PowerShell 5.1); git 2.55; gh CLI 2.97 installed and authed as `natahanjr`
  (git identity: user.name "Haaraphel", noreply email 261567925+natahanjr@users.noreply.github.com)
- GitHub repo renamed via `gh repo rename`; local remote updated to
  https://github.com/natahanjr/zebebgna.git
- Web UI may be running as a hidden `py webapp.py` process on port 5000;
  kill it before renaming the project folder (Windows folder lock).

## Session recovery
- This project's main opencode session: `ses_038f259c8ffekamkUB930ADf3i`
  (resume with `opencode -s <id>` or the `Zebegna.cmd` helper in the project root)
