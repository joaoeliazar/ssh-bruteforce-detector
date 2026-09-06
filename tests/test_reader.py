"""Unit tests for src/reader.py — file handling, rotation, gzip, year logic."""

from __future__ import annotations

import gzip
import os
import stat
import sys
from datetime import datetime
from pathlib import Path

import pytest

from src.reader import (
    ReadStats,
    discover_log_files,
    infer_start_year,
    read_logs,
    rotation_index,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample_auth.log"


# ---------------------------------------------------------------------------
# The bundled fixture
# ---------------------------------------------------------------------------

def test_fixture_exists():
    assert FIXTURE.is_file(), "tests/fixtures/sample_auth.log is missing"


def test_fixture_counts_are_exact():
    events, stats = read_logs([FIXTURE])

    assert stats.total_lines == 46
    assert stats.parsed_events == 39
    assert stats.malformed_lines == 2
    assert stats.ignored_lines == 5
    assert stats.year_rollovers == 0
    assert len(events) == 39


def test_fixture_events_are_chronological():
    events, _ = read_logs([FIXTURE])
    timestamps = [event.timestamp for event in events]
    assert timestamps == sorted(timestamps)


def test_fixture_malformed_lines_keep_evidence():
    _, stats = read_logs([FIXTURE])

    assert len(stats.malformed_samples) == 2
    for sample in stats.malformed_samples:
        assert "invalid timestamp" in sample["reason"]
        assert sample["raw"]
        assert sample["line_number"].isdigit()


def test_one_bad_line_never_aborts_the_file():
    """The malformed lines sit before the last valid line in the fixture."""
    events, stats = read_logs([FIXTURE])
    assert stats.malformed_lines > 0
    assert len(events) == 39


def test_fixture_sources_are_all_present():
    events, _ = read_logs([FIXTURE])
    ips = {event.ip for event in events}
    assert ips == {
        "10.0.0.15",
        "10.0.0.42",
        "203.0.113.5",
        "198.51.100.7",
        "192.0.2.99",
    }


# ---------------------------------------------------------------------------
# Rotation discovery
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "name, expected",
    [
        ("auth.log", 0),
        ("auth.log.1", 1),
        ("auth.log.2.gz", 2),
        ("auth.log.14.gz", 14),
    ],
)
def test_rotation_index(name, expected):
    assert rotation_index(Path(name)) == expected


def test_discovery_returns_oldest_first(tmp_path):
    """logrotate numbers backwards in time, so descending index is oldest-first."""
    base = tmp_path / "auth.log"
    base.write_text("current\n", encoding="utf-8")
    (tmp_path / "auth.log.1").write_text("older\n", encoding="utf-8")
    with gzip.open(tmp_path / "auth.log.2.gz", "wt", encoding="utf-8") as handle:
        handle.write("oldest\n")

    names = [path.name for path in discover_log_files(base)]
    assert names == ["auth.log.2.gz", "auth.log.1", "auth.log"]


def test_no_rotated_returns_only_the_given_file(tmp_path):
    base = tmp_path / "auth.log"
    base.write_text("current\n", encoding="utf-8")
    (tmp_path / "auth.log.1").write_text("older\n", encoding="utf-8")

    assert discover_log_files(base, include_rotated=False) == [base]


def test_gzip_is_read_transparently(tmp_path):
    base = tmp_path / "auth.log"
    base.write_text(
        "Mar 10 10:00:00 web sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )
    with gzip.open(tmp_path / "auth.log.1.gz", "wt", encoding="utf-8") as handle:
        handle.write(
            "Mar 09 09:00:00 web sshd[2]: Failed password for root "
            "from 5.6.7.8 port 22 ssh2\n"
        )

    events, stats = read_logs([base])
    assert len(stats.files_read) == 2
    assert {event.ip for event in events} == {"1.2.3.4", "5.6.7.8"}


def test_same_file_is_never_processed_twice(tmp_path):
    base = tmp_path / "auth.log"
    base.write_text(
        "Mar 10 10:00:00 web sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )
    events, _ = read_logs([base, base])
    assert len(events) == 1


# ---------------------------------------------------------------------------
# Year inference and rollover
# ---------------------------------------------------------------------------

def test_year_rollover_is_detected(tmp_path):
    """A 6+ month backward jump can only mean the calendar year changed."""
    path = tmp_path / "auth.log"
    path.write_text(
        "Dec 31 23:59:58 web sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n"
        "Jan  1 00:00:03 web sshd[2]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    events, stats = read_logs([path])
    assert stats.year_rollovers == 1
    assert events[1].timestamp.year == events[0].timestamp.year + 1


def test_small_out_of_order_jump_is_not_a_rollover(tmp_path):
    """Real logs are seconds out of order; that must not trigger a rollover."""
    path = tmp_path / "auth.log"
    path.write_text(
        "Mar 10 10:00:05 web sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n"
        "Mar 10 10:00:02 web sshd[2]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    _, stats = read_logs([path])
    assert stats.year_rollovers == 0


def test_start_year_is_anchored_on_mtime(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "Mar 10 10:00:00 web sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )
    reference = datetime(2021, 6, 15, 12, 0, 0).timestamp()
    os.utime(path, (reference, reference))

    assert infer_start_year(path) == 2021


def test_start_year_steps_back_when_file_crosses_new_year(tmp_path):
    """First line in December but mtime in March means the file started earlier."""
    path = tmp_path / "auth.log"
    path.write_text(
        "Dec 20 10:00:00 web sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )
    reference = datetime(2022, 3, 14, 12, 0, 0).timestamp()
    os.utime(path, (reference, reference))

    assert infer_start_year(path) == 2021


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_missing_file_is_reported_not_raised(tmp_path):
    events, stats = read_logs([tmp_path / "does-not-exist.log"])

    assert events == []
    assert stats.files_read == []
    assert stats.unreadable_files[0]["reason"] == "file not found"


def test_directory_is_reported_not_raised(tmp_path):
    _, stats = read_logs([tmp_path])
    assert stats.unreadable_files[0]["reason"] == "path is a directory"


def test_empty_file_produces_no_events(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("", encoding="utf-8")

    events, stats = read_logs([path])
    assert events == []
    assert stats.total_lines == 0
    assert stats.files_read == [str(path)]


def test_corrupted_gzip_is_reported(tmp_path):
    base = tmp_path / "auth.log"
    base.write_text("", encoding="utf-8")
    (tmp_path / "auth.log.1.gz").write_bytes(b"this is not gzip data at all")

    _, stats = read_logs([base])
    reasons = {entry["reason"] for entry in stats.unreadable_files}
    assert "corrupted gzip archive" in reasons


def test_invalid_utf8_does_not_abort_the_run(tmp_path):
    """Usernames are attacker-controlled and may contain invalid bytes."""
    path = tmp_path / "auth.log"
    path.write_bytes(
        b"Mar 10 10:00:00 web sshd[1]: Failed password for ro\xffot "
        b"from 1.2.3.4 port 22 ssh2\n"
        b"Mar 10 10:00:05 web sshd[2]: Failed password for root "
        b"from 1.2.3.4 port 22 ssh2\n"
    )

    events, stats = read_logs([path])
    assert stats.total_lines == 2
    assert len(events) == 2


@pytest.mark.skipif(
    sys.platform.startswith("win") or os.geteuid() == 0,
    reason="POSIX permissions; root bypasses them",
)
def test_permission_denied_is_reported(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text(
        "Mar 10 10:00:00 web sshd[1]: Failed password for root "
        "from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )
    path.chmod(stat.S_IWUSR)

    try:
        _, stats = read_logs([path])
        reasons = {entry["reason"] for entry in stats.unreadable_files}
        assert "permission denied" in reasons
    finally:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_read_stats_starts_empty():
    stats = ReadStats()
    assert stats.total_lines == 0
    assert stats.malformed_samples == []