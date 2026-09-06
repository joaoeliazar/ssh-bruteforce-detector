"""
src/cli.py
Command-line interface.

    python main.py /var/log/auth.log --threshold 5 --window 10 --format json

Exit codes are meant for automation:
    0  ran successfully, no findings
    1  ran successfully, findings present
    2  fatal error (nothing readable)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src import __version__
from src.detector import DetectionConfig, run_detection
from src.reader import read_logs
from src.reporter import build_report, render_json, render_text, write_csv

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssh-bruteforce-detector",
        description=(
            "Detect SSH brute-force attacks, password spraying and "
            "post-attack logins in Linux authentication logs."
        ),
        epilog=(
            "Examples:\n"
            "  python main.py /var/log/auth.log\n"
            "  python main.py /var/log/auth.log --threshold 3 --window 5\n"
            "  python main.py /var/log/secure --format json -o report.json\n"
            "  python main.py tests/fixtures/sample_auth.log --format csv\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        help="log file(s) to analyze; rotated siblings are included by default",
    )

    detection = parser.add_argument_group("brute-force detection")
    detection.add_argument(
        "--threshold", type=int, default=5, metavar="N",
        help="failed attempts from one IP that trigger an alert (default: 5)",
    )
    detection.add_argument(
        "--window", type=int, default=10, metavar="MINUTES",
        help="sliding window length in minutes (default: 10)",
    )

    spraying = parser.add_argument_group("password spraying detection")
    spraying.add_argument(
        "--spray-users", type=int, default=8, metavar="N",
        help="distinct accounts one IP must touch to be flagged (default: 8)",
    )
    spraying.add_argument(
        "--spray-window", type=int, default=360, metavar="MINUTES",
        help="spraying window length in minutes (default: 360)",
    )
    spraying.add_argument(
        "--spray-max-per-user", type=float, default=3.0, metavar="N",
        help="above this average, treat as brute force instead (default: 3.0)",
    )

    tuning = parser.add_argument_group("tuning")
    tuning.add_argument(
        "--allowlist", nargs="*", default=[], metavar="IP",
        help="IPs that must never be flagged (monitoring, jump hosts, CI)",
    )
    tuning.add_argument(
        "--dedup-seconds", type=int, default=5, metavar="SECONDS",
        help="collapse the Invalid user / Failed password pair (default: 5, "
             "0 disables)",
    )
    tuning.add_argument(
        "--no-rotated", action="store_true",
        help="analyze only the given file, ignoring auth.log.1, .2.gz, ...",
    )
    tuning.add_argument(
        "--process", default="sshd", metavar="NAME",
        help="syslog process name to analyze (default: sshd)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "--format", choices=("text", "json", "csv"), default="text",
        help="output format (default: text)",
    )
    output.add_argument(
        "-o", "--output", type=Path, metavar="FILE",
        help="write to FILE instead of stdout",
    )
    output.add_argument(
        "--top", type=int, default=10, metavar="N",
        help="how many entries in the top-N tables (default: 10)",
    )
    output.add_argument(
        "-q", "--quiet", action="store_true",
        help="suppress the progress line on stderr",
    )
    output.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}",
    )

    return parser


def _validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Reject nonsensical parameters before doing any work."""
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.window < 1:
        parser.error("--window must be at least 1 minute")
    if args.spray_users < 2:
        parser.error("--spray-users must be at least 2")
    if args.spray_window < 1:
        parser.error("--spray-window must be at least 1 minute")
    if args.dedup_seconds < 0:
        parser.error("--dedup-seconds cannot be negative")
    if args.top < 1:
        parser.error("--top must be at least 1")


def _emit(text: str, destination: Path | None) -> None:
    if destination is None:
        sys.stdout.write(text)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    _validate(args, parser)

    config = DetectionConfig(
        failure_threshold=args.threshold,
        window_minutes=args.window,
        spray_user_threshold=args.spray_users,
        spray_window_minutes=args.spray_window,
        spray_max_attempts_per_user=args.spray_max_per_user,
        dedup_seconds=args.dedup_seconds,
        allowlist=frozenset(args.allowlist),
    )

    try:
        events, read_stats = read_logs(
            args.paths,
            include_rotated=not args.no_rotated,
            process_filter=args.process,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR

    # Nothing readable at all is a usage error, not an empty result.
    if not read_stats.files_read:
        for entry in read_stats.unreadable_files:
            print(
                f"error: {entry['file']}: {entry['reason']}", file=sys.stderr
            )
        if not read_stats.unreadable_files:
            print("error: no readable log files", file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        print(
            f"Analyzed {read_stats.total_lines} lines across "
            f"{len(read_stats.files_read)} file(s).",
            file=sys.stderr,
        )

    result = run_detection(events, config)
    report = build_report(events, read_stats, result, config, top_n=args.top)

    if args.format == "json":
        _emit(render_json(report) + "\n", args.output)
    elif args.format == "csv":
        if args.output is None:
            write_csv(report, sys.stdout)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w", encoding="utf-8", newline="") as handle:
                write_csv(report, handle)
    else:
        _emit(render_text(report), args.output)

    return EXIT_FINDINGS if result.has_findings else EXIT_CLEAN