"""Command-line interface: ``sqlite-snapshot-audit {scan,verify} <dir> [--json]``."""

from __future__ import annotations

import argparse
import json
import sys

from .audit import AuditError, has_problems, scan, verify

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqlite-snapshot-audit",
        description="Read-only audit of a directory of SQLite backup copies.",
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    for name, help_text in (
        ("scan", "classify SQLite databases and their -wal/-shm sidecars"),
        ("verify", "scan, then integrity-check a temporary copy of each database unit"),
    ):
        sub = commands.add_parser(name, help=help_text, description=help_text)
        sub.add_argument("dir", help="directory to audit (never modified)")
        sub.add_argument("--json", action="store_true", help="print a JSON list")
    return parser


def _printable(text: str) -> str:
    """Show undecodable file-name bytes (surrogate escapes) as ``\\xNN`` instead of failing."""
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:
        # a lone surrogate that is not an escaped byte
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _format_text(entries: list[dict]) -> str:
    lines = []
    for entry in entries:
        line = f"{entry['class']:<15} {entry['main']}"
        if entry["sidecars"]:
            line += " [+ " + ", ".join(entry["sidecars"]) + "]"
        line += f" - {entry['reason']}"
        if "integrity" in entry:
            line += f"; integrity: {entry['integrity']}"
            if entry["tables"]:
                line += "; tables: " + ", ".join(
                    f"{name}={count}" for name, count in entry["tables"].items()
                )
        lines.append(_printable(line))
    return "".join(line + "\n" for line in lines)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        entries = verify(args.dir) if args.command == "verify" else scan(args.dir)
    except (AuditError, OSError) as exc:
        # OSError: e.g. the temporary directory cannot be created
        print(f"sqlite-snapshot-audit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.json:
        sys.stdout.write(json.dumps(entries, indent=2) + "\n")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            # a non-UTF-8 terminal encoding must not turn names into a traceback
            sys.stdout.reconfigure(errors="backslashreplace")
        sys.stdout.write(_format_text(entries))

    if args.command == "verify" and has_problems(entries):
        return EXIT_PROBLEMS
    return EXIT_OK
