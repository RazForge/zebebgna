"""Command-line interface for zebebgna."""

import argparse
import json

from zebebgna import audit_receipt_url, verify_receipt


def _save(report):
    from zebebgna import history

    history.record(report)


def _print_report(report):
    payload = report.to_dict()
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print(
        f"\nSCORE: {payload['score']}/100   STATUS: {payload['status']}"
    )
    threat = payload.get("threat")
    if threat:
        print(
            f"THREAT: {threat['risk_level']} ({threat['risk_score']}/100)"
        )
        if threat.get("scenario"):
            print(f"SCENARIO: {threat['scenario']}")
        for corr in threat.get("correlations", []):
            print(
                f"  - [{corr['rule_id']}] {corr['severity'].upper()}: "
                f"{corr['title']}"
            )


def _domain_feedback(url):
    from urllib.parse import urlparse

    from zebebgna import history
    from zebebgna.verifiers import phishing

    host = (urlparse(url).hostname or "").lower()
    if not host:
        return None
    return history.domain_feedback(phishing._registered_domain(host))


def _print_history_rows(rows):
    print(f"{'ID':<4} {'DATE':<20} {'BANK':<7} {'SCORE':<6} "
          f"{'STATUS':<7} {'RISK':<9} URL")
    for row in rows:
        print(
            f"{row['id']:<4} {row['ts']:<20} {(row['bank'] or '-'):<7} "
            f"{row['score']:<6} {row['status']:<7} "
            f"{(row['risk_level'] or '-'):<9} {row['url']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "zebebgna - defensive verification of Ethiopian bank "
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
    verify.add_argument(
        "--no-save", action="store_true",
        help="Do not store this check in the local history database",
    )

    audit = sub.add_parser(
        "audit", help="Audit a receipt URL's transport/URL security only"
    )
    audit.add_argument("url", help="Receipt endpoint URL")
    audit.add_argument(
        "--no-save", action="store_true",
        help="Do not store this check in the local history database",
    )

    batch = sub.add_parser(
        "batch", help="Verify multiple receipt links in one run"
    )
    batch.add_argument(
        "bank",
        choices=["cbe", "dashen", "awash", "boa", "zemen", "tele"],
        help="Bank name",
    )
    batch.add_argument(
        "urls", nargs="*", help="Receipt URLs (or bare Telebirr IDs)"
    )
    batch.add_argument(
        "--file", help="Read receipt links from a file (one per line)"
    )
    batch.add_argument(
        "--no-save", action="store_true",
        help="Do not store these checks in the local history database",
    )

    hist = sub.add_parser(
        "history", help="List past verification checks"
    )
    hist.add_argument("--limit", type=int, default=20, help="Max rows (default 20)")
    hist.add_argument("--clear", action="store_true", help="Delete all history")

    fb = sub.add_parser(
        "feedback", help="Mark a past check's verdict as correct or incorrect"
    )
    fb.add_argument("check_id", type=int, help="Check id from 'zebebgna history'")
    fb.add_argument("--correct", dest="correct", action="store_true",
                    help="The verdict was correct")
    fb.add_argument("--wrong", dest="correct", action="store_false",
                    help="The verdict was wrong (false positive/negative)")
    fb.set_defaults(correct=None)

    args = parser.parse_args()

    from zebebgna import history

    try:
        if args.command == "verify":
            report = verify_receipt(
                args.bank, args.url_or_id, feedback=_domain_feedback(args.url_or_id)
            )
            if not args.no_save:
                _save(report)
            _print_report(report)
        elif args.command == "audit":
            report = audit_receipt_url(
                args.url, feedback=_domain_feedback(args.url)
            )
            if not args.no_save:
                _save(report)
            _print_report(report)
        elif args.command == "batch":
            urls = list(args.urls)
            if args.file:
                with open(args.file, "r", encoding="utf-8") as fh:
                    urls.extend(
                        line.strip() for line in fh
                        if line.strip() and not line.startswith("#")
                    )
            if not urls:
                print("Error: no receipt links given (use positional args or --file)")
                return 1
            results = []
            for item in urls:
                report = verify_receipt(
                    args.bank, item, feedback=_domain_feedback(item)
                )
                if not args.no_save:
                    _save(report)
                payload = report.to_dict()
                results.append(payload)
                threat = payload.get("threat") or {}
                print(
                    f"[{payload['status']}] score={payload['score']}/100 "
                    f"threat={threat.get('risk_level', '-')} "
                    f"{payload['url']}"
                )
            print(json.dumps(results, indent=2, ensure_ascii=False))
        elif args.command == "history":
            if args.clear:
                removed = history.clear()
                print(f"History cleared ({removed} checks removed).")
            else:
                rows = history.list_checks(limit=args.limit)
                if not rows:
                    print("No checks stored yet. Run 'zebebgna verify' first.")
                else:
                    _print_history_rows(rows)
        elif args.command == "feedback":
            if args.correct is None:
                print("Error: pass either --correct or --wrong")
                return 1
            if not history.get_check(args.check_id):
                print(f"Error: no check with id {args.check_id} "
                      f"(see 'zebebgna history')")
                return 1
            history.record_feedback(args.check_id, args.correct)
            verdict = "correct" if args.correct else "incorrect"
            print(f"Check #{args.check_id} marked as {verdict}. "
                  f"This nudges future risk scores for the same domain.")
    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
