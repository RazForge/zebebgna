"""Offline image/PDF/text receipt verification.

Receipts are most often shared as screenshots or PDFs, not links. This
module extracts text from images (Tesseract, if installed), embedded
PDF text (pdfplumber), or pasted text, scans it into a bank's canonical
field set, and feeds the result through the normal per-bank fingerprint
and integrity pipeline.

OCR is optional: without a Tesseract binary the image path raises
:class:`OCRUnavailable` and the caller decides how to degrade (PDFs with
embedded text and pasted text always work).
"""

import os
import re

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

try:  # pragma: no cover - depends on the Tesseract binary
    from PIL import Image
    import pytesseract
except Exception:  # pragma: no cover
    Image = None
    pytesseract = None

try:  # pragma: no cover - depends on the zxing-cpp wheel
    import zxingcpp
except Exception:  # pragma: no cover
    zxingcpp = None


class OCRUnavailable(Exception):
    """Raised when image OCR is requested but Tesseract is not installed."""


# -- PDF / image text extraction --------------------------------------------

def extract_pdf_text(path):
    """Extract embedded text from a PDF file."""
    import pdfplumber

    with pdfplumber.open(path) as pdf:
        pages = [p.extract_text() or "" for p in pdf.pages]
    return "\n".join(pages)


def extract_image_text(path):
    """OCR an image file with Tesseract."""
    if pytesseract is None or Image is None:
        raise OCRUnavailable(
            "Image OCR requires Tesseract (install tesseract-ocr and "
            "'pip install pytesseract')"
        )
    with Image.open(path) as img:
        return pytesseract.image_to_string(img)


def extract_file_text(path):
    """Extract text from a PDF or image file (by extension)."""
    lower = path.lower()
    if not lower.endswith((".pdf", ".png", ".jpg", ".jpeg", ".bmp", ".tif",
                          ".tiff", ".webp")):
        raise ValueError(
            f"Unsupported file type: {path} (use PDF or an image file)"
        )
    file_size = os.path.getsize(path)
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"File too large: {file_size / 1024 / 1024:.1f} MB "
            f"(max {MAX_FILE_SIZE_BYTES / 1024 / 1024:.0f} MB)"
        )
    if lower.endswith((".pdf",)):
        return extract_pdf_text(path)
    if lower.endswith((".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff",
                       ".webp")):
        return extract_image_text(path)


def decode_qr(path):
    """Decode the first QR code found in an image (best effort).

    Returns the payload string, or ``None`` when no QR/barcode decodes.
    Requires the ``zxing-cpp`` wheel.
    """
    if zxingcpp is None or Image is None:
        return None
    if not os.path.exists(path) or not path.lower().endswith(
            (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp")):
        return None
    try:
        with Image.open(path) as img:
            results = zxingcpp.read_barcodes(img)
        if not results:
            return None
        best = None
        for r in results:
            if best is None or (r.valid and not best.valid):
                best = r
        return best.text if (best and best.valid) else None
    except Exception:
        return None


# -- Field scanning -----------------------------------------------------------

# Label -> canonical key for line-oriented receipts (Awash/BOA HTML and
# OCR'd line output).
LABEL_KEYS = {
    "transaction time": "Transaction Time",
    "transaction type": "Transaction Type",
    "amount": "Amount",
    "charge": "Charge",
    "vat": "VAT",
    "vat (15%)": "VAT",
    "vat 15%": "VAT",
    "total": "Total",
    "sender name": "Sender Name",
    "sender account": "Sender Account",
    "beneficiary name": "Beneficiary name",
    "beneficiary account": "Beneficiary Account",
    "beneficiary bank": "Beneficiary Bank",
    "reason": "Reason",
    "transaction id": "Transaction ID",
    "source account": "Source Account",
    "source account name": "Source Account Name",
    "receiver's account": "Receiver's Account",
    "receiver's name": "Receiver's Name",
    "transferred amount": "Transferred Amount",
    "service charge": "Service Charge",
    "transaction charge": "Service Charge",
    "total amount": "Total Amount",
    "total amount paid": "Total Amount Paid",
    "total paid amount": "total_paid",
    "transaction date": "Transaction Date",
    "transaction reference": "Transaction Reference",
    "transaction status": "status",
    "receipt no": "reference_no",
    "receipt number": "reference_no",
    "reference no": "Reference No",
    "reference number": "Reference No",
    "payer name": "payer_name",
    "payer telebirr": "payer_number",
    "credited party name": "credited_party",
    "credited party account no": "credited_party_number",
    "narrative": "Narrative",
    "service charge (etb)": "Service Charge",
    "settled amount": "Settled Amount",
    "vat 15% etb": "VAT",
    "total amount paid etb": "Total Amount Paid",
    "amount in words": "Amount in Words",
    "amount in word": "Amount in Words",
    "invoice no": "Invoice No",
    "date": "Date",
    "payer name:": None,
}

# Per-bank regex scanners for the classic "Label: value" PDF/extractor
# style, mirroring the on-line extractors so scanned text normalizes to
# the same canonical keys.
TEXT_SCANNERS = {
    "cbe": (
        # (key, regex) ordered; first match wins.
        ("reference_no", r"Reference\s*No[.:]?\s*([A-Z0-9]+)"),
        ("payment_date", r"(?i)Payment\s*Date\s*[&:]?\s*Time\s*([\d/:,\sAPMapm]+)"),
        ("customer_name", r"(?i)Customer\s*Name[.:]?\s*([^\n]+)"),
        ("branch", r"(?i)Branch[.:]?\s*([^\n]+)"),
        ("payer", r"(?i)Payer\s+([A-Z\s]+)"),
        ("receiver", r"(?i)Receiver\s+([A-Z\s]+)"),
        ("transferred_amount", r"(?i)Transferred\s*Amount\s*([\d,.]+)\s*ETB"),
        ("commission", r"(?i)Commission\s*or\s*Service\s*Charge\s*([\d,.]+)\s*ETB"),
        ("vat_on_commission", r"(?i)15%\s*VAT\s*on\s*Commission\s*([\d,.]+)\s*ETB"),
        ("total_debited", r"(?i)Total\s*amount\s*debited[^\n]*?\s*([\d,.]+)\s*ETB"),
        ("amount_in_words", r"(?i)Amount\s*in\s*Word\s*ETB\s*([^\n]+)"),
    ),
    "dashen": (
        ("transfer_reference", r"(?i)Transfer\s*Reference[.:]?\s*([^\n]+)"),
        ("transaction_reference", r"(?i)Transaction\s*Ref[.:]?\s*([^\n]+)"),
        ("transaction_date", r"(?i)Date[.:]?\s*([^\n]+)"),
        ("sender_name", r"(?i)Account\s*Holder\s*Name[.:]?\s*([^\n]+)"),
        ("beneficiary_name", r"(?i)Beneficiary\s*[^\n]*Name[.:]?\s*([^\n]+)"),
        ("beneficiary_account", r"(?i)Account\s*Number[.:]?\s*([\d]+)"),
        ("beneficiary_bank", r"(?i)Institution\s*Name[.:]?\s*([^\n]+)"),
        ("amount", r"(?i)Transaction\s*Amount\s*([\d,.]+)\s*ETB"),
        ("service_charge", r"(?i)Service\s*Charge\s*([\d,.]+)\s*ETB"),
        ("vat", r"(?i)VAT\s*([\d,.]+)\s*ETB"),
        ("total", r"(?i)Total\s*([\d,.]+)\s*ETB"),
        ("amount_in_words", r"(?i)Amount\s*in\s*words[.:]?\s*([^\n]+)"),
    ),
    "awash": (
        ("Transaction ID", r"(?i)Transaction\s*ID[.:]?\s*([^\n]+)"),
        ("Transaction Time", r"(?i)Transaction\s*Time[.:]?\s*([^\n]+)"),
        ("Transaction Type", r"(?i)Transaction\s*Type[.:]?\s*([^\n]+)"),
        ("Amount", r"(?i)^\s*Amount[.:]?\s*([\d,.]+)"),
        ("Charge", r"(?i)Charge[.:]?\s*([\d,.]+)"),
        ("VAT", r"(?i)VAT[.:]?\s*([\d,.]+)"),
        ("Total", r"(?i)^\s*Total[.:]?\s*([\d,.]+)"),
        ("Sender Name", r"(?i)Sender\s*Name[.:]?\s*([^\n]+)"),
        ("Sender Account", r"(?i)Sender\s*Account[.:]?\s*([^\n]+)"),
        ("Beneficiary name", r"(?i)Beneficiary\s*name[.:]?\s*([^\n]+)"),
        ("Beneficiary Account", r"(?i)Beneficiary\s*Account[.:]?\s*([^\n]+)"),
        ("Beneficiary Bank", r"(?i)Beneficiary\s*Bank[.:]?\s*([^\n]+)"),
        ("Reason", r"(?i)Reason[.:]?\s*([^\n]+)"),
    ),
    "boa": (
        ("Transaction Reference", r"(?i)Transaction\s*Reference[.:]?\s*([^\n]+)"),
        ("Transaction Date", r"(?i)Transaction\s*Date[.:]?\s*([^\n]+)"),
        ("Transaction Type", r"(?i)Transaction\s*Type[.:]?\s*([^\n]+)"),
        ("Transferred Amount", r"(?i)Transferred\s*[Aa]mount[.:]?\s*([\d,.]+)"),
        ("Service Charge", r"(?i)Service\s*Charge[.:]?\s*([\d,.]+)"),
        ("VAT", r"(?i)VAT[.:]?\s*([\d,.]+)"),
        ("Total Amount", r"(?i)Total\s*Amount[.:]?\s*([\d,.]+)"),
        ("Source Account", r"(?i)Source\s*Account[.:]?\s*([^\n]+)"),
        ("Source Account Name", r"(?i)Source\s*Account\s*Name[.:]?\s*([^\n]+)"),
        ("Receiver's Account", r"(?i)Receiver'?s\s*Account[.:]?\s*([^\n]+)"),
        ("Receiver's Name", r"(?i)Receiver'?s\s*Name[.:]?\s*([^\n]+)"),
        ("Narrative", r"(?i)Narrative[.:]?\s*([^\n]+)"),
    ),
    "tele": (
        ("reference_no", r"(?i)Receipt\s*No[.:]?\s*([A-Z0-9]+)"),
        ("status", r"(?i)Transaction\s*Status[.:]?\s*([^\n]+)"),
        ("payer_name", r"(?i)Payer\s*Name[.:]?\s*([^\n]+)"),
        ("payer_number", r"(?i)Payer\s*Telebirr[.:]?\s*([^\n]+)"),
        ("credited_party", r"(?i)Credited\s*Party\s*Name[.:]?\s*([^\n]+)"),
        ("credited_party_number", r"(?i)Credited\s*Party\s*Account\s*No[.:]?\s*([^\n]+)"),
        ("service_charge", r"(?i)Service\s*Charge[.:]?\s*([\d,.]+)"),
        ("total_paid", r"(?i)Total\s*Paid\s*Amount[.:]?\s*([\d,.]+)"),
    ),
    "zemen": (
        ("Invoice No", r"(?i)Invoice\s*No[.:]?\s*(\d+)"),
        ("Date", r"Date[:\s]+([0-9]{1,2}-[A-Za-z]{3}-[0-9]{4})"),
        ("Payer Name", r"(?i)Payer\s*name[.:]?\s*([A-Z\s]+)"),
        ("Payer Account No", r"(?i)Payer\s*account\s*no[.:]?\s*([\d\*()X]+)"),
        ("Recipient Name", r"(?i)Recipient\s*name[.:]?\s*([A-Za-z\s\.]+)"),
        ("Recipient Account No", r"(?i)Recipient\s*account\s*no[.:]?\s*([\d\*]+)"),
        ("Reference No", r"(?i)Reference\s*No[.:]?\s*([A-Z0-9]+)"),
        ("Transaction Status", r"(?i)Transaction\s*status[.:]?\s*(\w+)"),
        ("Settled Amount", r"(?i)Settled\s*Amount\s*ETB\s*([\d,]+\.\d{2})"),
        ("Service Charge", r"(?i)Service\s*Charge\s*ETB\s*([\d,]+\.\d{2})"),
        ("VAT", r"(?i)VAT\s*15%\s*ETB\s*([\d,]+\.\d{2})"),
        ("Total Amount Paid", r"(?i)Total\s*Amount\s*Paid\s*ETB\s*([\d,]+\.\d{2})"),
        ("Amount in Words", r"(?i)Total\s*amount\s*in\s*word[.:]?\s*([^\n]+)"),
    ),
}


def _line_fields(text):
    """Scan ``Label: value`` lines into the canonical key set."""
    data = {}
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r"^([^:]{2,40}?):\s*(.+)$", line)
        if not match:
            continue
        label, value = match.group(1).strip().lower(), match.group(2).strip()
        key = LABEL_KEYS.get(label)
        if key is None or not value:
            continue
        if key not in data:
            data[key] = value
    return data


def _regex_scanner(bank, text):
    data = {}
    for key, pattern in TEXT_SCANNERS.get(bank, ()):
        match = re.search(pattern, text)
        if match and key not in data:
            value = match.group(1).strip()
            if value:
                data[key] = value
    return data


def scan_fields(bank, text):
    """Scan OCR/extracted text into the bank's canonical field set."""
    if not text or not text.strip():
        return {}
    data = _regex_scanner(bank, text)
    data.update(_line_fields(text))
    return data