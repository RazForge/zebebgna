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
import re
from urllib.parse import urlparse

import requests
from flask import Flask, redirect, render_template, request, url_for

from zebebgna import verify_extracted_data, verify_file, verify_receipt
from zebebgna.fetch import InsecureURLError, fetcher, host_is_private_literal
from zebebgna.verifiers import phishing
from zebebgna.vision import OCRUnavailable, scan_fields

PKG_DIR = os.path.dirname(os.path.abspath(__import__("zebebgna").__file__))
TEMPLATE_DIR = os.path.join(PKG_DIR, "templates")
STATIC_DIR = os.path.join(PKG_DIR, "static")
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR, static_url_path='/static')

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

HEADER_SHORT = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "X-Frame-Options",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "Referrer-Policy": "Referrer-Policy",
    "Permissions-Policy": "Permissions-Policy",
}

ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("zebebgna_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}

# Keep the secure fetcher in sync so every redirect hop is re-validated
# against the same allowlist (the check here is only the first line of
# defense; the fetcher enforces the policy on every hop).
fetcher.allowed_hosts = ALLOWED_HOSTS


def _host_allowed(url):
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if host_is_private_literal(host):
        return False
    if ALLOWED_HOSTS and not (
        host in ALLOWED_HOSTS or any(host.endswith("." + h) for h in ALLOWED_HOSTS)
    ):
        return False
    return True


def _normalize_url(bank, url_or_id):
    url = url_or_id
    if not url.startswith("http") and bank == "tele":
        url = f"https://transactioninfo.ethiotelecom.et/receipt/{url_or_id}"
    return url


def _domain_feedback(url):
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return None
    from zebebgna import history

    return history.domain_feedback(phishing._registered_domain(host))


def _report_context(report):
    """Compute everything the report template needs from a report."""
    summary, issues = _summarize_findings(report)
    threat_correlations = (
        [c for c in report.threat.correlations if c.severity in STRONG_SEVERITIES]
        if report.threat else []
    )
    threat_pin = (
        RISK_PIN.get(report.threat.risk_level, 12) if report.threat else None
    )
    return {
        "threat": report.threat,
        "threat_correlations": threat_correlations,
        "threat_pin": threat_pin,
        "summary": summary,
        "issues": issues,
    }


def _summarize_findings(report):
    """Collapse informational notes into short per-topic lines.

    Returns (summary, issues) where ``summary`` is a list of
    (category, title, short_text) tuples and ``issues`` keeps every
    warn/error/critical finding with its full message.
    """
    infos = [f for f in report.findings if f.severity == "info"]
    issues = [f for f in report.findings if f.severity != "info"]

    summary = []

    tls_msgs = [f.message for f in infos if f.category == "tls"]
    if tls_msgs:
        parts = []
        for msg in tls_msgs:
            m = re.search(
                r"Certificate valid until (.*?) \((\d+) days remaining\)", msg
            )
            if m:
                raw_date = m.group(1)
                date = " ".join(
                    t for t in raw_date.split() if ":" not in t
                )
                parts.append(
                    f"valid until {date} ({m.group(2)} days left)"
                )
                continue
            m = re.search(r"TLS (.+?) - issued by: (.+)$", msg)
            if m:
                parts.append(f"TLS {m.group(1)} issued by {m.group(2)}")
                continue
            parts.append(msg)
        summary.append(("tls", "TLS & certificate", "; ".join(parts)))

    header_msgs = [f.message for f in infos if f.category == "headers"]
    if header_msgs:
        missing = []
        present = []
        for msg in header_msgs:
            if msg.startswith("Missing security header: "):
                name = msg[len("Missing security header: "):]
                missing.append(HEADER_SHORT.get(name, name))
            else:
                present.append(msg)
        parts = []
        if missing:
            parts.append(f"{len(missing)} missing: {', '.join(missing)}")
        if present:
            parts.append("core security headers present")
        summary.append(("headers", "Security headers", "; ".join(parts)))

    return summary, issues


STRONG_SEVERITIES = ("error", "high", "critical")

RISK_PIN = {"LOW": 12, "MEDIUM": 45, "HIGH": 75, "CRITICAL": 95}


@app.route("/")
def index():
    return render_template("index.html", banks=BANK_NAMES)


@app.route("/verify", methods=["POST"])
def verify():
    bank = request.form.get("bank", "").strip().lower()
    url_or_id = request.form.get("url_or_id", "").strip()
    pasted_text = request.form.get("text", "").strip()
    upload = request.files.get("file")

    if not url_or_id and not pasted_text and not (upload and upload.filename):
        return render_template(
            "index.html", banks=BANK_NAMES,
            error="Paste a receipt link (or Telebirr receipt ID), paste "
                  "receipt text, or upload a PDF/screenshot first.",
        )

    from zebebgna import history

    try:
        if upload and upload.filename:
            import tempfile

            lower = upload.filename.lower()
            suffix = os.path.splitext(lower)[1] or ".png"
            with tempfile.NamedTemporaryFile(
                    delete=False, suffix=suffix) as tmp:
                upload.save(tmp.name)
                path = tmp.name
            try:
                report = verify_file(bank, path)
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass
        elif pasted_text:
            report = verify_extracted_data(
                bank, scan_fields(bank, pasted_text), source="pasted-text"
            )
        else:
            url = _normalize_url(bank, url_or_id)
            if url.startswith("http"):
                if not _host_allowed(url):
                    return render_template(
                        "index.html", banks=BANK_NAMES,
                        error=(
                            "This link points to a website that is not in "
                            "the allowed list. Only trusted receipt websites "
                            "can be checked."
                        ),
                    )
            else:
                return render_template(
                    "index.html", banks=BANK_NAMES,
                    error="That does not look like a valid receipt link.",
                )
            report = verify_receipt(
                bank, url_or_id, feedback=_domain_feedback(url)
            )
    except OCRUnavailable as exc:
        return render_template(
            "index.html", banks=BANK_NAMES,
            error=(f"{exc}. You can still upload PDFs or paste the receipt "
                   f"text."),
        )
    except (ValueError, InsecureURLError) as exc:
        return render_template(
            "index.html", banks=BANK_NAMES, error=f"Could not verify: {exc}"
        )
    except (requests.ConnectionError, requests.Timeout) as exc:
        app.logger.error(
            "Network error verifying receipt bank=%r url=%r: %s",
            bank, url_or_id, exc, exc_info=True,
        )
        return render_template(
            "index.html", banks=BANK_NAMES,
            error=(
                "Could not reach the receipt website. It may be temporarily "
                "down, or your network/internet may be blocking it. "
                "Please try again in a moment."
            ),
        )
    except Exception as exc:
        app.logger.error(
            "Receipt verification failed for bank=%r input=%r: %s",
            bank, url_or_id or upload.filename, exc, exc_info=True,
        )
        return render_template(
            "index.html", banks=BANK_NAMES,
            error=(
                "Something went wrong while checking this receipt. "
                "Please check the link and try again."
            ),
        )

    from zebebgna import history

    try:
        report.check_id = history.record(report)
    except Exception as exc:
        # A DB failure must not turn a successful verification into a 500;
        # the report is still shown, just without a stored history entry.
        app.logger.warning("Could not store check in history: %s", exc)
    context = _report_context(report)
    context.update(
        report=report,
        ai_review=report.ai_review,
        check_id=report.check_id,
        bank_name=BANK_NAMES.get(report.bank, report.bank),
        severity_labels=SEVERITY_LABELS,
    )
    return render_template("report.html", **context)


@app.route("/history")
def history_page():
    from zebebgna import history

    rows = history.list_checks(limit=100)
    return render_template("history.html", checks=rows)


@app.route("/history/<int:check_id>")
def history_view(check_id):
    from zebebgna import history

    check = history.get_check(check_id)
    if not check:
        return render_template(
            "history.html", checks=history.list_checks(limit=100),
            error=f"No stored check with id {check_id}.",
        )
    report = history.report_from_record(check)
    context = _report_context(report)
    context.update(
        report=report,
        ai_review=report.ai_review,
        check_id=check["id"],
        bank_name=BANK_NAMES.get(report.bank, report.bank or "audit"),
        severity_labels=SEVERITY_LABELS,
    )
    return render_template("report.html", **context)


@app.route("/share/<int:check_id>")
def share_view(check_id):
    """Public shareable link: same stored report, no admin chrome."""
    from zebebgna import history

    check = history.get_check(check_id)
    if not check:
        return render_template(
            "index.html", banks=BANK_NAMES,
            error=f"No stored check with id {check_id}.",
        )
    report = history.report_from_record(check)
    context = _report_context(report)
    context.update(
        report=report,
        ai_review=report.ai_review,
        check_id=check["id"],
        share=True,
        bank_name=BANK_NAMES.get(report.bank, report.bank or "audit"),
        severity_labels=SEVERITY_LABELS,
    )
    return render_template("report.html", **context)


@app.route("/history/<int:check_id>/feedback", methods=["POST"])
def history_feedback(check_id):
    from zebebgna import history

    ok = request.form.get("ok")
    if ok in ("1", "0"):
        history.record_feedback(check_id, ok == "1")
    return redirect(url_for("history_page"))


@app.route("/history/clear", methods=["POST"])
def history_clear():
    from zebebgna import history

    history.clear()
    return redirect(url_for("history_page"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
