"""Tests for per-bank PDF receipt extractors (patterns over pdfplumber text)."""

from unittest import mock

from zebebgna.extractors import cbe as cbe_extractor


def _write_pdf(path, lines):
    """Render one text line per PDF line, top to bottom."""
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(path)
    y = 760
    for line in lines:
        c.drawString(72, y, line)
        y -= 15
    c.save()


def test_cbe_payer_receiver_stop_at_line_end(tmp_path):
    # The CBE PDF puts the account number on the line after "Account",
    # right below the name; the name captures must not leak the next
    # line's first letter ("ABEBE BEKELE\nA").
    pdf_path = str(tmp_path / "cbe.pdf")
    _write_pdf(pdf_path, [
        "Payer", "ABEBE BEKELE", "Account", "0123456789",
        "Receiver", "DAWIT TADESSE", "Account", "9876543210",
    ])
    with open(pdf_path, "rb") as fh:
        raw = fh.read()

    with mock.patch.object(cbe_extractor.fetcher, "fetch_pdf_bytes",
                           return_value=raw):
        data = cbe_extractor.extract_cbe_receipt_info(
            "https://example.com/cbe.pdf")

    assert data["payer"] == "ABEBE BEKELE"
    assert data["receiver"] == "DAWIT TADESSE"
    assert data["payer_account"] == "0123456789"
    assert data["receiver_account"] == "9876543210"
