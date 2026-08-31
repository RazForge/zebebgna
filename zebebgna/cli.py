"""Command-line interface for zebebgna."""

import argparse
import json
import os
from datetime import datetime

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
    ai = payload.get("ai_review")
    if ai:
        conf = f" (confidence {ai['confidence']}%)" if ai.get("confidence") \
            else ""
        print(f"AI: {ai['verdict'].upper()}{conf}")
        print(f"  {ai['summary']}")
        for reason in ai.get("reasons", []):
            print(f"  - {reason}")


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
        "url_or_id_or_file",
        help="Receipt URL, bare Telebirr receipt ID, or a local "
             "PDF/image screenshot of the receipt",
    )
    verify.add_argument(
        "--no-save", action="store_true",
        help="Do not store this check in the local history database",
    )

    verifytext = sub.add_parser(
        "verify-text",
        help="Verify a pasted receipt (text copied from a PDF or screenshot)",
    )
    verifytext.add_argument(
        "bank",
        choices=["cbe", "dashen", "awash", "boa", "zemen", "tele"],
        help="Bank name",
    )
    verifytext.add_argument("text", help="The receipt text (quote it)")
    verifytext.add_argument(
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
    fb.add_argument(
        "--report-phish", metavar="REASON",
        help="Also add the checked domain to the community phishing "
             "database (use when a FAIL verdict was confirmed)",
    )
    fb.set_defaults(correct=None)

    tdb = sub.add_parser(
        "threatdb", help="Manage the community phishing-domain database"
    )
    tdb.add_argument("action", choices=["add", "remove", "list"],
                     help="add <domain> [reason] | remove <domain> | list")
    tdb.add_argument("domain", nargs="?", help="Registered domain")
    tdb.add_argument("reason", nargs="?", help="Why the domain is reported")

    watch = sub.add_parser(
        "watch", help="Re-verify a receipt link on a schedule"
    )
    watch.add_argument(
        "bank",
        choices=["cbe", "dashen", "awash", "boa", "zemen", "tele"],
        help="Bank name",
    )
    watch.add_argument(
        "url_or_id_or_file",
        help="Receipt URL, bare Telebirr receipt ID, or a local receipt file",
    )
    watch.add_argument(
        "--every", type=float, default=60.0,
        help="Seconds between checks (default 60)",
    )
    watch.add_argument(
        "--count", type=int, default=0,
        help="Number of checks to run (default: until Ctrl+C)",
    )
    watch.add_argument(
        "--no-save", action="store_true",
        help="Do not store these checks in the local history database",
    )

    backup = sub.add_parser(
        "backup", help="Export or restore the local history database"
    )
    backup.add_argument("action", choices=["export", "import"],
                        help="export <file> | import <file>")
    backup.add_argument("path", help="Backup file path")

    cfg = sub.add_parser(
        "config", help="Show the effective configuration"
    )
    cfg.add_argument("what", nargs="?", choices=["show"], default="show",
                     help="Currently only 'show' is supported")

    args = parser.parse_args()

    from zebebgna import history

    try:
        if args.command == "verify":
            target = args.url_or_id_or_file
            if os.path.exists(target):
                from zebebgna import verify_file

                report = verify_file(args.bank, target)
            else:
                report = verify_receipt(
                    args.bank, target, feedback=_domain_feedback(target)
                )
            if not args.no_save:
                _save(report)
            _print_report(report)
        elif args.command == "verify-text":
            from zebebgna import verify_extracted_data
            from zebebgna.vision import scan_fields

            report = verify_extracted_data(
                args.bank, scan_fields(args.bank, args.text),
                source="pasted-text", feedback=None,
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
            check = history.get_check(args.check_id)
            if not check:
                print(f"Error: no check with id {args.check_id} "
                      f"(see 'zebebgna history')")
                return 1
            history.record_feedback(args.check_id, args.correct)
            verdict = "correct" if args.correct else "incorrect"
            print(f"Check #{args.check_id} marked as {verdict}. "
                  f"This nudges future risk scores for the same domain.")
            if args.report_phish:
                from urllib.parse import urlparse

                from zebebgna.verifiers import phishing

                host = (urlparse(check["url"]).hostname or "").lower()
                domain = phishing._registered_domain(host) if host else None
                if not domain:
                    print("Error: could not derive a domain from the check URL")
                    return 1
                added = history.add_threat_domain(
                    domain, reason=args.report_phish, source=f"check#{args.check_id}"
                )
                if added:
                    print(f"Added {domain} to the community phishing database.")
                else:
                    print(f"{domain} was already in the phishing database.")
        elif args.command == "threatdb":
            action = args.action
            if action == "add":
                if not args.domain:
                    print("Error: threatdb add requires a domain")
                    return 1
                added = history.add_threat_domain(
                    args.domain, reason=args.reason, source="cli"
                )
                print(f"Added {args.domain} to the phishing database."
                      if added else
                      f"{args.domain} was already in the phishing database.")
            elif action == "remove":
                if not args.domain:
                    print("Error: threatdb remove requires a domain")
                    return 1
                removed = history.remove_threat_domain(args.domain)
                print(f"Removed {removed} domain(s) from the database.")
            else:
                rows = history.list_threat_domains()
                if not rows:
                    print("The phishing database is empty.")
                else:
                    for row in rows:
                        reason = f" - {row['reason']}" if row["reason"] else ""
                        print(f"{row['domain']} (since {row['ts']}){reason}")
        elif args.command == "watch":
            import time

            if args.every <= 0:
                print("Error: --every must be positive")
                return 1
            if args.count < 0:
                print("Error: --count must be >= 0")
                return 1
            target = args.url_or_id_or_file
            is_file = os.path.exists(target)
            run = 0
            while args.count == 0 or run < args.count:
                run += 1
                try:
                    if is_file:
                        from zebebgna import verify_file

                        report = verify_file(args.bank, target)
                    else:
                        report = verify_receipt(
                            args.bank, target,
                            feedback=_domain_feedback(target),
                        )
                except Exception as exc:
                    print(f"[{run}] ERROR: {exc}", flush=True)
                    if run >= args.count and args.count:
                        break
                    time.sleep(args.every)
                    continue
                if not args.no_save:
                    _save(report)
                threat = report.threat
                level = threat.risk_level if threat else "-"
                stamp = datetime.now().strftime("%H:%M:%S")
                print(
                    f"[{run}] {stamp} {report.status} "
                    f"score={report.score}/100 threat={level} "
                    f"{report.url}",
                    flush=True,
                )
                if run >= args.count and args.count:
                    break
                try:
                    time.sleep(args.every)
                except KeyboardInterrupt:
                    print("\nWatch stopped.")
                    break
        elif args.command == "backup":
            if args.action == "export":
                statements = history.export_sql(args.path)
                print(f"Exported {statements} SQL statements to {args.path}")
            else:
                statements = history.import_sql(args.path)
                print(f"Imported {statements} SQL statements from {args.path}")
        elif args.command == "config":
            import tempfile

            print(f"Database: {history.db_path()}")
            print(f"Database exists: {os.path.exists(history.db_path())}")
            db = os.environ.get("ZEBEBGNA_DB")
            if db:
                print(f"ZEBEBGNA_DB env: {db}")
            print(f"Threat domains: {len(history.list_threat_domains())}")
            print(f"History checks: {len(history.list_checks(limit=1000))}")
            for key in ("ZEBEBGNA_LLM_API_KEY", "ZEBEBGNA_TELEGRAM_TOKEN"):
                value = os.environ.get(key)
                print(f"{key}: {'set' if value else 'not set'}")
            print(f"Temp dir: {tempfile.gettempdir()}")
    except Exception as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
