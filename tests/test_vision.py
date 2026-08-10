"""Tests for offline image/PDF/text verification (Tier 2)."""

import io
import sys
from unittest import mock

import pytest

from zebebgna.report import VerificationReport
from zebebgna.vision import OCRUnavailable, extract_file_text, scan_fields


# -- field scanning -----------------------------------------------------------

def test_scan_cbe_text():
    text = (
        "CBE Receipt\nCustomer Name: ABEBE BEKELE\nBranch: Bole\n"
        "Payment Date & Time 01/15/2024, 09:30:00 AM\n"
        "Reference No: FT20240115123456\n"
        "Transferred Amount 1,000.00 ETB\n"
        "Commission or Service Charge 20.00 ETB\n"
        "Total amount debited from customers account 1,020.00 ETB\n"
        "Amount in Word ETB One Thousand Twenty Birr Only\n"
    )
    data = scan_fields("cbe", text)
    assert data["reference_no"] == "FT20240115123456"
    assert data["total_debited"] == "1,020.00"
    assert data["amount_in_words"] == "One Thousand Twenty Birr Only"
    assert data["customer_name"] == "ABEBE BEKELE"


def test_scan_empty_and_none():
    assert scan_fields("cbe", "") == {}
    assert scan_fields("cbe", None) == {}
    assert scan_fields("cbe", "   ") == {}


def test_scan_line_labels_for_awash():
    text = (
        "Awash Bank\nTransaction ID: AW1234567890\n"
        "Transaction Time: 10/05/2024, 11:20:00 AM\n"
        "Amount: 500.00\nCharge: 5.00\nVAT: 0.75\nTotal: 505.75\n"
        "Sender Name: ABEBE\nBeneficiary name: MULU\n"
    )
    data = scan_fields("awash", text)
    assert data["Transaction ID"] == "AW1234567890"
    assert data["Total"] == "505.75"
    assert data["Sender Name"] == "ABEBE"
    assert data["Beneficiary name"] == "MULU"


def test_scan_tele_text():
    text = (
        "TeleBirr Receipt\nReceipt No: CHQ0FJ403O\n"
        "Transaction Status: SUCCESS\nPayer Name: ABEBE BEKELE\n"
        "Payer Telebirr: +251911223344\nCredited Party name: MULU\n"
        "Service Charge: 0.00\nTotal Paid Amount: 250.00\n"
    )
    data = scan_fields("tele", text)
    assert data["reference_no"] == "CHQ0FJ403O"
    assert data["status"] == "SUCCESS"
    assert data["total_paid"] == "250.00"


def test_scan_zemen_with_amharic_words():
    text = (
        "Zemen Bank\nInvoice No.: 88123\n"
        "Date: 12-Sep-2023\nPayer name: ABEBE\n"
        "Reference No: ZM202309120001\nTransaction status: SUCCESS\n"
        "Settled Amount ETB 1,234.00\nService Charge ETB 5.00\n"
        "VAT 15% ETB 0.75\nTotal Amount Paid ETB 1,239.75\n"
        "Total amount in word: One Thousand Two Hundred Thirty Nine Birr Only\n"
    )
    data = scan_fields("zemen", text)
    assert data["Total Amount Paid"] == "1,239.75"
    assert data["Settled Amount"] == "1,234.00"
    assert data["Reference No"] == "ZM202309120001"


# -- file extraction ------------------------------------------------------------

def test_extract_pdf_text(tmp_path):
    import pdfplumber
    import reportlab  # noqa: F401 - only used if available
    from reportlab.pdfgen import canvas

    pdf_path = str(tmp_path / "receipt.pdf")
    c = canvas.Canvas(pdf_path)
    c.drawString(72, 720, "Reference No: FT1234567890")
    c.drawString(72, 700, "Total amount debited 1,000.00 ETB")
    c.save()

    text = extract_file_text(pdf_path)
    assert "FT1234567890" in text
    assert "1,000.00" in text


def test_extract_file_text_unsupported():
    with pytest.raises(ValueError):
        extract_file_text("receipt.exe")


def test_ocr_unavailable_when_no_tesseract(tmp_path):
    fake = tmp_path / "r.png"
    fake.write_bytes(b"not an image")
    with mock.patch("zebebgna.vision.Image", None), \
            mock.patch("zebebgna.vision.pytesseract", None):
        with pytest.raises(OCRUnavailable):
            extract_file_text(str(fake))


def test_verify_extracted_data_offline():
    from zebebgna import verify_extracted_data

    report = verify_extracted_data(
        "cbe",
        {
            "reference_no": "FT20240115123456",
            "payment_date": "01/15/2024",
            "transferred_amount": "1,000.00",
            "amount_in_words": "One Thousand Birr Only",
        },
        source="pasted-text",
    )
    assert report.bank == "cbe"
    assert any(f.category == "fetch" for f in report.findings)
    assert report.threat is not None
    assert report.score > 0


def test_verify_extracted_data_rejects_unknown_bank():
    from zebebgna import verify_extracted_data

    with pytest.raises(ValueError):
        verify_extracted_data("nope", {})


def test_verify_file_runs_qr_note(tmp_path):
    from zebebgna import verify_file

    pdf_path = tmp_path / "t.pdf"
    import pdfplumber
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(str(pdf_path))
    c.drawString(72, 720, "Receipt No: CHQ0FJ403O")
    c.drawString(72, 700, "Transaction Status: SUCCESS")
    c.drawString(72, 680, "Total Paid Amount: 250.00")
    c.save()

    report = verify_file("tele", str(pdf_path))
    assert report.data.get("reference_no") == "CHQ0FJ403O"
    assert any(f.category == "qr" for f in report.findings)
    assert report.threat is not None


def test_verify_cli_accepts_local_file(tmp_path):
    from zebebgna import cli

    pdf_path = tmp_path / "r.pdf"
    import pdfplumber
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(str(pdf_path))
    c.drawString(72, 720, "Receipt No: CHQ0FJ403O")
    c.drawString(72, 700, "Transaction Status: SUCCESS")
    c.drawString(72, 680, "Total Paid Amount: 250.00")
    c.save()

    with mock.patch.object(sys, "argv", ["zebebgna", "verify", "tele",
                                         str(pdf_path), "--no-save"]):
        assert cli.main() == 0


def test_verify_text_cli():
    from zebebgna import cli

    argv = [
        "zebebgna", "verify-text", "tele",
        "Receipt No: CHQ0FJ403O\nTransaction Status: SUCCESS\n"
        "Total Paid Amount: 250.00",
        "--no-save",
    ]
    with mock.patch.object(sys, "argv", argv):
        assert cli.main() == 0


def test_webapp_upload_path():
    from webapp import app

    client = app.test_client()
    try:
        import reportlab
        from reportlab.pdfgen import canvas
        from io import BytesIO

        buf = BytesIO()
        c = canvas.Canvas(buf)
        c.drawString(72, 720, "Receipt No: CHQ0FJ403O")
        c.drawString(72, 700, "Transaction Status: SUCCESS")
        c.drawString(72, 680, "Total Paid Amount: 250.00")
        c.save()
        data = buf.getvalue()
    except ImportError:  # pragma: no cover
        data = b"%PDF-1.4 placeholder"

    with mock.patch("webapp.verify_file") as fake_verify:
        fake_verify.return_value = VerificationReport(
            url="file:///tmp/receipt.pdf", bank="tele",
            data={"reference_no": "CHQ0FJ403O", "status": "SUCCESS"},
        )
        resp = client.post(
            "/verify",
            data={"bank": "tele",
                  "file": (io.BytesIO(data), "receipt.pdf")},
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    fake_verify.assert_called_once()
    assert b"Good" in resp.data
# -- QR decoding (Tier 4b) ---------------------------------------------------

def test_decode_qr_roundtrip(tmp_path):
    import qrcode
    from zebebgna.vision import decode_qr

    qr_path = tmp_path / "qr.png"
    img = qrcode.make("https://example.com/receipt/CHQ0FJ403O")
    img.save(str(qr_path))
    payload = decode_qr(str(qr_path))
    assert payload == "https://example.com/receipt/CHQ0FJ403O"


def test_decode_qr_no_qr_returns_none(tmp_path):
    from reportlab.pdfgen import canvas
    from zebebgna.vision import decode_qr

    img_path = tmp_path / "plain.png"
    from PIL import Image
    Image.new("RGB", (60, 60), "white").save(str(img_path))
    assert decode_qr(str(img_path)) is None


def test_decode_qr_missing_or_bad_file(tmp_path):
    from zebebgna.vision import decode_qr

    assert decode_qr(str(tmp_path / "nope.png")) is None
    text = tmp_path / "r.txt"
    text.write_text("x")
    assert decode_qr(str(text)) is None


def test_verify_file_records_qr_payload(tmp_path):
    from PIL import Image
    import qrcode
    from zebebgna import verify_file

    qr = qrcode.make("TOTAL:250.00 REF:CHQ0FJ403O")
    qr_path = tmp_path / "qr.png"
    qr.save(str(qr_path))

    import zebebgna.vision as vision_mod
    with mock.patch.object(vision_mod, "extract_file_text",
                           return_value="Receipt No: CHQ0FJ403O\n"
                           "Transaction Status: SUCCESS\n"
                           "Total Paid Amount: 250.00"):
        report = verify_file("tele", str(qr_path))
    assert report.data.get("qr_payload") == "TOTAL:250.00 REF:CHQ0FJ403O"
    qr_findings = [f for f in report.findings if f.category == "qr"]
    assert any("QR code decoded" in f.message for f in qr_findings)
