# Contributing to Zebebgna

Thank you for your interest in making Ethiopian bank receipts more secure!

## Quick start

```bash
git clone https://github.com/RazForge/zebebgna.git
cd zebebgna
pip install -e ".[dev,web,bot]"
pytest tests/ -q
```

## How to contribute

### 1. Test with real receipts

The most valuable contribution is testing against actual receipts from your bank. Run:

```bash
zebebgna verify cbe "YOUR_RECEIPT_URL"
```

If fields are missing or amounts are wrong, [open an issue](https://github.com/RazForge/zebebgna/issues/new?template=bug_report.md) with:
- Which bank
- What went wrong (missing fields, wrong amounts, etc.)
- The receipt URL or pasted text (redact personal info)

### 2. Report phishing domains

If you encounter a fake receipt website, report it:

```bash
zebebgna feedback <check_id> --report-phish "Description of the phishing attempt"
```

Or [open a security advisory](https://github.com/RazForge/zebebgna/security/advisories/new).

### 3. Add bank support

Each bank has its own extractor in `zebebgna/extractors/`. To add a new bank:

1. Create `zebebgna/extractors/newbank.py`
2. Implement `extract_newbank_receipt_data(url)` that returns a dict
3. Register it in `zebebgna/extractors/__init__.py`
4. Add required fields in `zebebgna/verifiers/integrity.py`
5. Add layout fingerprint in `zebebgna/verifiers/fingerprint.py`
6. Write tests in `tests/`

### 4. Improve phishing detection

Add new heuristics in `zebebgna/verifiers/phishing.py`:
- New known bank domains
- New URL shorteners
- New suspicious TLDs
- Improved lookalike detection

### 5. Enhance the threat fusion engine

Add correlation rules in `zebebgna/fusion.py`:
- New signal combinations that indicate attacks
- Better risk scoring weights
- New scenario descriptions

### 6. Translate the UI

Help make the web UI available in Amharic and other Ethiopian languages. Templates are in `zebebgna/templates/`.

## Code style

- Follow existing patterns (look at neighboring files)
- Use `parameterized queries` for all SQL (never string formatting)
- Never use `verify_ssl=False`
- Add logging for silent failures
- Write tests for new features

## Pull request process

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Run `pytest tests/ -q` and `flake8 . --select=E9,F63,F7,F82`
5. Open a PR with a clear description

## Questions?

Open a [discussion](https://github.com/RazForge/zebebgna/discussions) or reach out via [issues](https://github.com/RazForge/zebebgna/issues).
