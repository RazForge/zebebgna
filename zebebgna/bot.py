"""Telegram bot for zebebgna.

Optional: set ``ZEBEBGNA_TELEGRAM_TOKEN`` and run ``python -m zebebgna.bot``.

Commands:
    /start                - intro
    /verify <bank> <url|telebirr-id>   - verify a receipt link/ID
    /verifytext <bank> <text>          - verify pasted receipt text
    photo/PDF + caption <bank>         - verify an uploaded receipt file

The reply-building and parsing logic is pure (``parse_verify_command``,
``format_verdict``) so it can be tested without a Telegram connection.
"""

import os
import sys

BANK_ALIASES = {
    "cbe": "cbe", "commercial": "cbe", "commercialbankofethiopia": "cbe",
    "dashen": "dashen", "awash": "awash",
    "boa": "boa", "abyssinia": "boa", "bankofabyssinia": "boa",
    "zemen": "zemen", "tele": "tele", "telebirr": "tele",
    "ethiotelecom": "tele",
}


def parse_verify_command(text):
    """Parse a ``/verify <bank> <input>`` command.

    Returns ``(bank, input)`` or ``(None, error_message)``.
    """
    parts = (text or "").strip().split(maxsplit=1)
    if len(parts) < 2:
        return None, (
            "Usage: /verify <bank> <receipt link or Telebirr ID>\n"
            "Banks: cbe, dashen, awash, boa, zemen, tele"
        )
    bank = BANK_ALIASES.get(parts[0].strip().lower())
    if not bank:
        return None, (
            f"Unknown bank '{parts[0]}'. Use one of: cbe, dashen, awash, "
            f"boa, zemen, tele"
        )
    target = parts[1].strip()
    if not target:
        return None, "Give me a receipt link or Telebirr ID to verify."
    return bank, target


def format_verdict(report):
    """Render a VerificationReport as plain text for Telegram."""
    lines = [
        f"[{report.bank.upper()} receipt check]",
        f"Score: {report.score}/100 -> {report.status}",
    ]
    lines.append(f"URL: {report.url}")
    threat = report.threat
    if threat:
        lines.append(f"Threat: {threat.risk_level} ({threat.risk_score}/100)")
        if threat.scenario:
            lines.append(f"Scenario: {threat.scenario}")
    findings = [f for f in report.findings if f.severity != "info"]
    if findings:
        lines.append("")
        lines.append("Findings:")
        for finding in findings[:6]:
            icon = {"critical": "X", "error": "!", "warn": "!"}[
                finding.severity
            ]
            lines.append(f"{icon} {finding.message}")
    ai = report.ai_review
    if ai:
        lines.append("")
        lines.append(f"AI review: {ai.summary}")
        if ai.reasons:
            for reason in ai.reasons[:3]:
                lines.append(f"  - {reason}")
    lines.append("")
    lines.append("Advisory only - verify receipts you are entitled to see.")
    return "\n".join(lines)


def _verify(bank, target):
    from zebebgna import verify_receipt

    return verify_receipt(bank, target)


def _verify_text(bank, text):
    from zebebgna import verify_extracted_data
    from zebebgna.vision import scan_fields

    return verify_extracted_data(bank, scan_fields(bank, text),
                                 source="telegram-text")


def _verify_file(bank, path):
    from zebebgna import verify_file

    return verify_file(bank, path)


async def _handle_verify(update, context, mode="link"):
    user_text = " ".join(context.args)
    if mode == "text":
        bank, target = parse_verify_command("x " + user_text)
        if not bank:
            target = user_text
            bank = None
        if not bank:
            await update.message.reply_text(
                "Tell me the bank first, e.g. /verifytext cbe <text>"
            )
            return
        report = _verify_text(bank, target)
    else:
        bank, target = parse_verify_command(user_text)
        if not bank:
            await update.message.reply_text(target)
            return
        try:
            report = _verify(bank, target)
        except Exception as exc:
            await update.message.reply_text(
                f"Could not verify: {exc}\nCareful \u2014 do not send "
                f"sensitive receipt data to untrusted bots."
            )
            return
    await update.message.reply_text(format_verdict(report))


async def _handle_file(update, context):
    bank = "tele"
    caption = (update.message.caption or "").strip().lower()
    if caption:
        bank = BANK_ALIASES.get(caption.split()[0], bank)
    file_id = None
    name = None
    if update.message.photo:
        photo = update.message.photo[-1]
        file_id = photo.file_id
        name = "receipt.png"
    elif update.message.document:
        file_id = update.message.document.file_id
        name = update.message.document.file_name or "receipt.pdf"
    if not file_id:
        await update.message.reply_text(
            "Send a receipt screenshot (photo) or a PDF, with the bank in "
            "the caption if it is not Telebirr."
        )
        return
    await update.message.reply_text("\u231B Verifying receipt\u2026")
    import tempfile

    file = await context.bot.get_file(file_id)
    suffix = os.path.splitext(name)[1] or ".png"
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        await file.download_to_drive(path)
        report = _verify_file(bank, path)
    except Exception as exc:
        await update.message.reply_text(f"Could not verify: {exc}")
        return
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    await update.message.reply_text(format_verdict(report))


async def _start(update, context):
    await update.message.reply_text(
        "\U0001F6E1 *Zebebgna* \u2014 Ethiopian bank receipt guard.\n\n"
        "Send:\n"
        "\u2022 /verify cbe https://apps.cbe.com.et:100/?id=... \n"
        "\u2022 /verify tele CHQ0FJ403O\n"
        "\u2022 /verifytext <bank> <receipt text>\n"
        "\u2022 a receipt screenshot/PDF with bank name in the caption\n\n"
        "Covers CBE, Dashen, Awash, BOA, Zemen and Telebirr.",
        parse_mode="Markdown",
    )


def build_app(token=None, verify_fn=None, verify_text_fn=None,
              verify_file_fn=None):
    """Build the Telegram application (testable with injected functions)."""
    global _verify, _verify_text, _verify_file
    token = token or os.environ.get("ZEBEBGNA_TELEGRAM_TOKEN", "")
    if not token:
        raise ValueError(
            "ZEBEBGNA_TELEGRAM_TOKEN is not set"
        )
    if verify_fn:
        _verify = verify_fn
    if verify_text_fn:
        _verify_text = verify_text_fn
    if verify_file_fn:
        _verify_file = verify_file_fn

    from telegram.ext import Application, CommandHandler, MessageHandler, filters

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", _start))
    app.add_handler(CommandHandler("verify", _handle_verify))
    app.add_handler(CommandHandler(
        "verifytext", lambda u, c: _handle_verify(u, c, mode="text")))
    app.add_handler(MessageHandler(
        filters.PHOTO | filters.Document.PDF, _handle_file))
    return app


def main():
    token = os.environ.get("ZEBEBGNA_TELEGRAM_TOKEN")
    if not token:
        print("Error: set ZEBEBGNA_TELEGRAM_TOKEN first.")
        return 1
    app = build_app(token)
    app.run_polling()
    return 0


if __name__ == "__main__":
    sys.exit(main())