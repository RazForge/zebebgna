# Zebebgna — Project Memory (AGENTS.md)

When the user says "Zebegna" / "Zebebgna", this is the project they mean. Read this
file first to recall the full context before doing any work on it.

## Project identity
- **Name:** Zebebgna (previously named "zabagna", originally based on `ethiobank-receipts`)
- **Meaning:** Amharic for "guard"
- **Purpose:** Defensive cybersecurity toolkit that verifies the authenticity of
  Ethiopian bank receipts and audits the security posture of the endpoints that serve them.
- **Repo:** https://github.com/RazForge/zebebgna (public, main branch)

## What it does
- Extracts receipt data from 6 Ethiopian banks/mobile money: CBE, Dashen, Awash,
  BOA, Zemen, Telebirr (extractors in `zebebgna/extractors/`)
- Runs 4 verifier groups (`zebebgna/verifiers/`): phishing (URL heuristics),
  TLS (cert chain/hostname/expiry), security headers (HSTS/CSP/XFO/etc.),
  integrity (amount math, reference formats, status, completeness)
- Threat-fusion engine (`zebebgna/fusion.py`): correlates weak signals across
  verifier groups into attack scenarios (lookalike phishing infra, forged
  receipts, weak hardening) with a fused 0-100 risk score + risk level
  (LOW/MEDIUM/HIGH/CRITICAL) and indicators; deterministic rule table, no
  external feeds; attached to every report as `report.threat`
  (Python API: `zebebgna.fusion.assess(report)`)
- Community threat database (`zebebgna/history.py` threat_domains table):
  `threatdb add|remove|list`, `feedback --report-phish`; a reported domain
  raises an error-level "community_reported" correlation in fusion.
- Vision/OCR (`zebebgna/vision.py` + `words.py`/`dates.py`): pasted receipt
  text (`verify-text`, web "paste text" box) and local PDF/image screenshots
  (`verify_file`); `scan_fields(bank, text)` extracts structured fields.
- LLM review (`zebebgna/llm.py`): optional OpenAI-compatible review when
  `ZEBEBGNA_LLM_API_KEY` is set; `AIVerdict` (genuine/suspicious/unclear)
  shown on report pages and in CLI output; failures degrade silently.
- Produces a `VerificationReport` with 0–100 score and PASS / REVIEW / FAIL verdict
  (any critical finding forces FAIL)
- History + feedback loop (`zebebgna/history.py`): every check can be stored
  in SQLite (`ZEBEBGNA_DB` env var, default `~/.zebebgna/checks.db`); CLI
  `history`/`feedback` commands, web `/history` pages with thumbs up/down;
  per-domain feedback (`(confirmed, rejected)`) nudges the fused risk score
  via `assess(report, feedback=...)` (delta: -10 if >=3 rejections outweigh
  confirmations, +5 if vice versa; exposed as `feedback_adjustment`). The
  feedback loop is deterministic, capped, and never lifts an unreadable
  receipt off 0.
- Batch verification: `zebebgna batch <bank> <urls...>` / `--file urls.txt`
  (JSON array output); all CLI verify/audit/batch/watch runs auto-save unless
  `--no-save`.
- Operational tooling: `zebebgna watch <bank> <input> --every N --count M`
  (scheduled re-verification), `zebebgna backup export|import <file>` (SQLite
  dump/restore, replaces local data on import), `zebebgna config show`.
- Shareable reports: web UI `/share/<check_id>` link (archived banner, no
  admin chrome) plus a Share chip on fresh report pages.
- Never fetches plain HTTP — `SecureFetcher` (zebebgna/fetch.py) enforces HTTPS +
  strict TLS verification (the original project had `verify_ssl=False`; we removed that)

## Interfaces
- **CLI:** `zebebgna verify <bank> <url_or_id>` and `zebebgna audit <url>`
  (module form: `python -m zebebgna.cli`)
- **Python API:** `verify_receipt(bank, url_or_id)`, `audit_receipt_url(url)`
- **Web UI (for non-technical users):** `python webapp.py` → http://127.0.0.1:5000
  (Flask; form + color-coded verdict page; optional SSRF allowlist via
  `zebebgna_ALLOWED_HOSTS` env var); webapp.py lives at repo ROOT (not in the
  package), templates/static inside `zebebgna/`.
- **Telegram bot (optional):** `zebebgna/bot.py`, run `python -m zebebgna.bot`
  with `ZEBEBGNA_TELEGRAM_TOKEN`; `/verify <bank> <link|id>`, `/verifytext`,
  photo/PDF uploads; pure logic (`parse_verify_command`, `format_verdict`) is
  testable without a token. Extra: `pip install -e ".[bot]"`.
- **Docs:** `docs/Zebebgna-Documentation.html` + `.pdf` (generated via
  Edge headless `--print-to-pdf`)

## How to install / test
```
pip install -e ".[web]"     # core + Flask web UI
pytest tests/ -q            # 174 tests, all pass
python webapp.py            # start web UI
```
Deps: requests, pdfplumber, beautifulsoup4, selenium (+ flask for web,
python-telegram-bot for the bot). BOA extractor needs ChromeDriver (selenium).
CI lint gate (GitHub Actions): `flake8 . --select=E9,F63,F7,F82` (fatal
errors only; long lines E501 are NOT enforced).

## Key decisions / history
1. Built from `ethiobank-receipts` (scraper) as a DEFENSIVE security project —
   no offensive tooling, no verify_ssl=False, ethics section in README.
2. Renamed twice: receiptguard → zabagna → zebebgna (user-chosen name).
3. Templates live inside the package (`zebebgna/templates/`) so wheels work;
   `pyproject.toml` pins `[tool.setuptools.packages.find]` and package-data.
4. Web UI serves non-technical users: pick bank → paste receipt link → verdict.
5. Scoring: info=0 (notes never penalize a genuine receipt), warn=-10,
   error=-20, critical=-40; >=85 PASS, 55–84 REVIEW, <55 FAIL. Missing
   security headers are reported as informational notes (server posture,
   not receipt authenticity). Receipt-data failures (empty extraction or
   integrity error/critical findings) force score 0 / FAIL.
6. Tests use mocked network (no live receipt endpoints in the suite).
7. PDF docs generated with Edge headless; keep `docs/Zebebgna-Documentation.html`
   as the editable source.

## Session recovery
- This project's main opencode session can be resumed with `opencode -s <session_id>`
