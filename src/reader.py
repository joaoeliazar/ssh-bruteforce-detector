"""
src/reader.py
Turns log files on disk into a chronologically ordered list of AuthEvent
objects.

Responsibilities:
  - discover rotated files (auth.log, auth.log.1, auth.log.2.gz, ...)
  - transparently decompress .gz
  - infer the missing year in classic syslog timestamps
  - survive unreadable files and malformed lines without aborting

This module knows nothing about attacks or thresholds.
"""

from __future__ import annotations

import gzip
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TextIO

from src.parser import MONTHS, SYSLOG_LINE, AuthEvent, ParseError, parse_line


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# logrotate's numeric suffix: ".1", ".2.gz", ".14.gz"
ROTATION_SUFFIX = re.compile(r"\.(?P<index>\d+)(?:\.gz)?$")

# A backward jump of this many months cannot come from out-of-order buffered
# writes. It can only mean the calendar year rolled over.
MONTH_JUMP_THRESHOLD = 6

# How many malformed lines to keep as evidence before we stop collecting.
MAX_MALFORMED_SAMPLES = 20


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@dataclass
class ReadStats:
    """Everything that happened during reading, for the final report.

    "40,000 lines processed, 6 malformed" has operational meaning: if that
    number spikes, either the log format changed (the parser is blind) or
    someone is injecting junk on purpose.
    """

    files_read: list[str] = field(default_factory=list)
    total_lines: int = 0
    parsed_events: int = 0
    ignored_lines: int = 0
    malformed_lines: int = 0
    malformed_samples: list[dict[str, str]] = field(default_factory=list)
    year_rollovers: int = 0
    unreadable_files: list[dict[str, str]] = field(default_factory=list)

    def record_malformed(
        self, path: Path, lineno: int, line: str, reason: str
    ) -> None:
        self.malformed_lines += 1
        if len(self.malformed_samples) < MAX_MALFORMED_SAMPLES:
            self.malformed_samples.append({
                "file": str(path),
                "line_number": str(lineno),
                "reason": reason,
                "raw": line.strip()[:200],
            })

    def record_unreadable(self, path: Path, reason: str) -> None:
        self.unreadable_files.append({"file": str(path), "reason": reason})

    def to_dict(self) -> dict:
        return {
            "files_read": self.files_read,
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "ignored_lines": self.ignored_lines,
            "malformed_lines": self.malformed_lines,
            "year_rollovers": self.year_rollovers,
            "unreadable_files": self.unreadable_files,
        }


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def rotation_index(path: Path) -> int:
    """Return logrotate's numeric index; 0 for the live (current) file."""
    match = ROTATION_SUFFIX.search(path.name)
    return int(match.group("index")) if match else 0


def discover_log_files(path: Path, include_rotated: bool = True) -> list[Path]:
    """Return the file plus its rotated siblings, oldest first.

    logrotate numbers backwards in time: auth.log is newest, auth.log.1 is
    older, auth.log.2.gz older still. Sorting by descending index therefore
    yields chronological order, which is exactly what the year-rollover
    logic requires.
    """
    if not include_rotated:
        return [path] if path.is_file() else []

    candidates: list[Path] = []
    if path.is_file():
        candidates.append(path)

    for sibling in path.parent.glob(f"{path.name}.*"):
        if sibling.is_file() and ROTATION_SUFFIX.search(sibling.name):
            candidates.append(sibling)

    return sorted(candidates, key=lambda item: -rotation_index(item))


# ---------------------------------------------------------------------------
# Opening (plain or gzip)
# ---------------------------------------------------------------------------

def open_text(path: Path) -> TextIO:
    """Open a log file as text, transparently handling gzip.

    errors="replace" is not cosmetic. Usernames are attacker-controlled
    input and routinely contain invalid UTF-8. Without it, one hostile byte
    raises UnicodeDecodeError and kills the whole run — the attacker turns
    the detector off for free.
    """
    if path.suffix == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return path.open(mode="r", encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Year inference
# ---------------------------------------------------------------------------

def classic_month(line: str) -> int | None:
    """Month number of a classic syslog line, or None (blank / ISO / junk)."""
    match = SYSLOG_LINE.match(line)
    if match is None:
        return None
    return MONTHS.get(match.group("month"))


def peek_first_month(path: Path) -> int | None:
    """Month of the first classic syslog line in the file."""
    with open_text(path) as handle:
        for line in handle:
            month = classic_month(line)
            if month is not None:
                return month
    return None


def infer_start_year(path: Path) -> int:
    """Best guess for the year of the FIRST entry in the file.

    Anchored on mtime, never on datetime.now(): now() works for the live
    auth.log and breaks on every rotated file, since auth.log.4.gz may be
    from December of last year.

    mtime tells us when the LAST line was written. If the first line's month
    is later in the calendar than mtime's month, the file started a year
    earlier:

        mtime    = 2026-03-14  (month 3)
        1st line = "Dec ..."   (month 12)  ->  file starts in 2025
    """
    modified = datetime.fromtimestamp(path.stat().st_mtime)
    first_month = peek_first_month(path)

    if first_month is not None and first_month > modified.month:
        return modified.year - 1
    return modified.year


# ---------------------------------------------------------------------------
# Reading a single file
# ---------------------------------------------------------------------------

def read_file(
    path: Path,
    stats: ReadStats,
    process_filter: str = "sshd",
) -> Iterator[AuthEvent]:
    """Yield AuthEvent objects from one log file. Never raises on bad lines.

    Generator by design: processes line by line without loading the file
    into memory.
    """
    year = infer_start_year(path)
    previous_month: int | None = None

    with open_text(path) as handle:
        for lineno, line in enumerate(handle, start=1):
            stats.total_lines += 1

            month = classic_month(line)
            if month is not None:
                # Reading chronologically, timestamps only increase. A sharp
                # drop means the year rolled over:
                #     Dec 31 23:59:58  (month 12)
                #     Jan  1 00:00:03  (month 1)   -> year + 1
                #
                # The test cannot be "earlier than the previous timestamp":
                # real logs are a few seconds out of order because multiple
                # processes share the buffer. Comparing months at a 6-month
                # distance cannot be produced by that noise.
                if (
                    previous_month is not None
                    and month < previous_month - MONTH_JUMP_THRESHOLD
                ):
                    year += 1
                    stats.year_rollovers += 1
                previous_month = month

            try:
                event = parse_line(line, year=year, process_filter=process_filter)
            except ParseError as exc:
                # Feb 29 exists only in leap years. If the inferred year is
                # off by one, a perfectly valid line would be silently
                # discarded — the worst failure mode for a security tool.
                # Retry once before declaring the line malformed.
                try:
                    event = parse_line(
                        line, year=year - 1, process_filter=process_filter
                    )
                except ParseError:
                    stats.record_malformed(path, lineno, line, str(exc))
                    continue

            if event is None:
                stats.ignored_lines += 1
                continue

            stats.parsed_events += 1
            yield event


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def read_logs(
    paths: list[Path],
    include_rotated: bool = True,
    process_filter: str = "sshd",
) -> tuple[list[AuthEvent], ReadStats]:
    """Read every given path (and its rotated siblings) into sorted events.

    Every failure category gets a named reason. "Could not read auth.log.3.gz
    because the archive is truncated" is actionable; "error" is not.
    """
    stats = ReadStats()
    events: list[AuthEvent] = []
    seen: set[Path] = set()

    for raw_path in paths:
        base_path = Path(raw_path)

        if not base_path.exists():
            stats.record_unreadable(base_path, "file not found")
            continue

        if base_path.is_dir():
            stats.record_unreadable(base_path, "path is a directory")
            continue

        for target in discover_log_files(base_path, include_rotated):
            resolved = target.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)

            try:
                events.extend(read_file(target, stats, process_filter))
            except PermissionError:
                stats.record_unreadable(target, "permission denied")
                continue
            except gzip.BadGzipFile:
                stats.record_unreadable(target, "corrupted gzip archive")
                continue
            except EOFError:
                # Happens when logrotate was interrupted mid-compression.
                stats.record_unreadable(target, "truncated gzip archive")
                continue
            except OSError as exc:
                stats.record_unreadable(target, f"OS error: {exc}")
                continue

            stats.files_read.append(str(target))

    # Files are read oldest-first, but a global sort protects against
    # out-of-order writes and overlapping rotated files. The sliding window
    # is only correct on chronologically ordered input.
    events.sort(key=lambda event: event.timestamp)
    return events, stats