"""Command-line interface: ``uncloak scan|rules|version``."""
from __future__ import annotations

import argparse
import os
import sys

from . import engine
from .findings import Severity
from .report import json_report, sarif, terminal
from .rules import all_rules
from .version import __version__

_SEVERITIES = ["info", "low", "medium", "high", "critical"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="uncloak",
        description="Reveal hidden prompt injection & supply-chain risks in AI agent "
                    "extensions (skills, MCP servers, rules files).",
    )
    p.add_argument("--version", action="version", version=f"uncloak {__version__}")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("-f", "--format", choices=["terminal", "json", "sarif"],
                      default="terminal", help="output format (default: terminal)")
    scan.add_argument("--min-severity", choices=_SEVERITIES, default="low",
                      help="hide findings below this severity in output (default: low)")
    scan.add_argument("--fail-on", choices=_SEVERITIES, default="high",
                      help="exit non-zero when a finding at/above this severity exists (default: high)")
    scan.add_argument("-o", "--output", help="write report to FILE instead of stdout")
    scan.add_argument("--refs", action="store_true",
                      help="show OWASP/ATLAS/CWE references in terminal output")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    rules_p = sub.add_parser("rules", help="list the detection rule catalog")
    rules_p.add_argument("-f", "--format", choices=["table", "json"], default="table")

    sub.add_parser("version", help="print version")
    return p


def _cmd_scan(args) -> int:
    if args.no_color:
        os.environ["NO_COLOR"] = "1"
    if not os.path.exists(args.path):
        print(f"uncloak: path not found: {args.path}", file=sys.stderr)
        return 1

    result = engine.scan_path(args.path)
    min_sev = Severity.parse(args.min_severity)
    shown = result.filtered(min_sev)

    if args.format == "json":
        out = json_report.render(result, shown)
    elif args.format == "sarif":
        out = sarif.render(result, shown)
    else:
        out = terminal.render(result, shown, show_refs=args.refs)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"uncloak: report written to {args.output}", file=sys.stderr)
    else:
        print(out)

    fail_on = Severity.parse(args.fail_on)
    return 2 if result.worst() >= fail_on and any(f.severity >= fail_on for f in result.findings) else 0


def _cmd_rules(args) -> int:
    if args.format == "json":
        import json
        payload = [{
            "id": r.id, "title": r.title, "severity": r.severity.label,
            "category": r.category, "references": list(r.references),
            "detail": r.detail, "remediation": r.remediation,
        } for r in all_rules()]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    width = max(len(r.id) for r in all_rules())
    current = None
    for r in all_rules():
        if r.category != current:
            current = r.category
            print(f"\n{current}")
        print(f"  {r.id:<{width}}  [{r.severity.label:>8}]  {r.title}")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)
    if args.command == "version":
        print(f"uncloak {__version__}")
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
