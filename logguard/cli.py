"""Command-line interface for LogGuard AI.

Usage:
    logguard scan <path|owner/repo|url> [options]
    logguard rules
    logguard providers
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import (
    __version__,
    ai_module,
    github_scanner,
    input_manager,
    reporting,
    risk_engine,
)
from .engine import scan
from .models import Severity
from .secure_processing import ValidationError

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# (id, detector, severity, description) - mirrors docs/RULES.md
RULE_CATALOG = [
    ("LG001", "Logging", "Low", "print() used instead of a logger"),
    ("LG002", "Logging", "Low", "Eager f-string log formatting"),
    ("LG003", "Logging", "Medium", "Broad/bare exception handled without logging"),
    ("LG004", "Logging", "High", "Possible sensitive data in a log message"),
    ("EX001", "Exception", "High", "Bare 'except:' clause"),
    ("EX002", "Exception", "High/Med", "Swallowed exception (pass)"),
    ("EX003", "Exception", "Medium", "Overly broad 'except Exception'"),
    ("EX004", "Exception", "Low", "Re-raise loses the original traceback"),
    ("EX005", "Exception", "Low", "Raising a generic Exception"),
    ("SC001", "Secrets", "Crit/High", "Known secret pattern (AWS, Google, GitHub, ...)"),
    ("SC002", "Secrets", "High", "Generic hard-coded credential assignment"),
    ("CQ001", "Code Quality", "High", "eval() / exec()"),
    ("CQ002", "Code Quality", "High", "subprocess with shell=True"),
    ("CQ003", "Code Quality", "Medium", "os.system / os.popen"),
    ("CQ004", "Code Quality", "High", "Unsafe deserialization (pickle, ...)"),
    ("CQ005", "Code Quality", "High", "yaml.load without SafeLoader"),
    ("CQ007", "Code Quality", "Low", "Mutable default argument"),
    ("CQ008", "Code Quality", "Low", "== None / == True comparison"),
    ("CQ009", "Code Quality", "Medium", "HTTP request without timeout"),
    ("CQ010", "Code Quality", "Low", "Binding to 0.0.0.0"),
    ("CQ011", "Code Quality", "Low", "Weak hash (md5 / sha1)"),
    ("CQ013", "Code Quality", "Low", "Race-prone tempfile.mktemp()"),
    ("WS001", "Web Security", "High", "Possible SQL injection"),
    ("WS002", "Web Security", "High/Med", "TLS verification disabled"),
    ("WS003", "Web Security", "Medium", "Debug mode enabled"),
    ("WS004", "Web Security", "Medium", "Insecure random for a security value"),
    ("WS005", "Web Security", "Medium", "Weak cipher / ECB mode"),
    ("WS006", "Web Security", "Medium", "assert guarding an authorization check"),
]


def _load_target(target: str):
    path = Path(target)
    if path.is_dir():
        return input_manager.from_directory(path)
    if path.is_file():
        return input_manager.from_uploaded_file(path.name, path.read_bytes())
    return github_scanner.fetch_repo(target)


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        bundle = _load_target(args.target)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(f"Scanning {bundle.name} ({bundle.file_count} file(s))...")
    result = scan(bundle)

    if args.ai and result.findings:
        message = ai_module.enrich_findings(
            result.findings, provider=args.provider or None, limit=args.ai_limit
        )
        if not args.quiet:
            if message.ok:
                print(f"AI recommendations added via {message.provider}.")
            else:
                print(f"AI step skipped: {message.error}")

    min_rank = Severity(args.min_severity).rank
    shown = [f for f in result.findings if Severity(f.severity).rank >= min_rank]

    if args.json:
        Path(args.json).write_text(reporting.to_json(result), encoding="utf-8")
        if not args.quiet:
            print(f"JSON report written to {args.json}")
    if args.html:
        Path(args.html).write_text(reporting.to_html(result), encoding="utf-8")
        if not args.quiet:
            print(f"HTML report written to {args.html}")

    for f in shown:
        print(f"[{f.severity.upper():8}] {f.rule_id} {f.file}:{f.line} - {f.title}")
        if args.verbose and f.recommendation:
            print(f"           -> {f.recommendation}")
        if args.verbose and f.ai_fix:
            print(f"           AI fix: {f.ai_fix}")

    score = risk_engine.risk_score(result.findings)
    print(
        f"\n{len(result.findings)} finding(s) "
        f"({len(shown)} at/above {args.min_severity}) "
        f"across {result.files_scanned} file(s), {result.lines_scanned} line(s)."
    )
    print(f"Risk: {score}/100 ({risk_engine.risk_rating(score)})")

    if result.errors and not args.quiet:
        print(f"\n{len(result.errors)} scanner note(s):")
        for err in result.errors[:20]:
            print(f"  - {err}")

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        if any(Severity(f.severity).rank >= threshold for f in result.findings):
            print(f"Failing: findings at/above {args.fail_on}.", file=sys.stderr)
            return 1
    return 0


def _cmd_rules(_args: argparse.Namespace) -> int:
    print(f"{'ID':7} {'DETECTOR':14} {'SEVERITY':9} DESCRIPTION")
    for rule_id, detector, severity, description in RULE_CATALOG:
        print(f"{rule_id:7} {detector:14} {severity:9} {description}")
    return 0


def _cmd_providers(_args: argparse.Namespace) -> int:
    status = ai_module.providers_status()
    default = ai_module.default_provider()
    for name, ok in status.items():
        mark = "configured" if ok else "-"
        star = " (default)" if name == default else ""
        print(f"{name:8} {mark}{star}")
    if not any(status.values()):
        print("\nNo provider configured. Add a key to .env to enable AI features.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logguard",
        description="LogGuard AI - static analysis + AI recommendations for Python.",
    )
    parser.add_argument("--version", action="version", version=f"LogGuard AI {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a file, folder, or GitHub repository")
    scan_p.add_argument("target", help="path, owner/repo, or github.com URL")
    scan_p.add_argument("--json", metavar="PATH", help="write a JSON report")
    scan_p.add_argument("--html", metavar="PATH", help="write an HTML report")
    scan_p.add_argument("--ai", action="store_true", help="add AI recommendations")
    scan_p.add_argument("--provider", choices=["groq", "gemini", "xai"], help="LLM provider")
    scan_p.add_argument("--ai-limit", type=int, default=20, help="max findings to enrich")
    scan_p.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default="Info",
        help="only display findings at/above this severity",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        help="exit non-zero if any finding is at/above this severity (CI)",
    )
    scan_p.add_argument("-v", "--verbose", action="store_true", help="show recommendations")
    scan_p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    scan_p.set_defaults(func=_cmd_scan)

    sub.add_parser("rules", help="list detection rules").set_defaults(func=_cmd_rules)
    sub.add_parser("providers", help="show AI provider status").set_defaults(func=_cmd_providers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
