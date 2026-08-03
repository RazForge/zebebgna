"""Command-line interface for zabagna."""

import argparse
import json

from zabagna import audit_receipt_url, verify_receipt


def _print_report(report):
    payload = report.to_dict()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(
        f"\nSCORE: {payload['score']}/100   STATUS: {payload['status']}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "zabagna - defensive verification of Ethiopian bank "
            "receipts and security auditing of receipt endpoints."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser(
        "verify", help="Extract a receipt and verify its authenticity + security"
    )
    verify.add_argument(
        "bank",
        choices=["cbe", "dashen", "awash", "boa", "zemen", "tele"],
        help="Bank name",
    )
    verify.add_argument(
        "url_or_id", help="Receipt URL (or bare Telebirr receipt ID)"
    )

    audit = sub.add_parser(
        "audit", help="Audit a receipt URL's transport/URL security only"
    )
    audit.add_argument("url", help="Receipt endpoint URL")

    args = parser.parse_args()

    try:
        if args.command == "verify":
            report = verify_receipt(args.bank, args.url_or_id)
        else:
            report = audit_receipt_url(args.url)
    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
