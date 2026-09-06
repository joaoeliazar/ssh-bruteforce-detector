"""Unit tests for src/parser.py — single-line parsing only."""

from __future__ import annotations

from datetime import datetime

import pytest

from src.parser import (
    AuthEvent,
    EventType,
    ParseError,
    parse_line,
)

YEAR = 2026


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_failed_password():
    line = (
        "Mar 10 13:45:12 webserver sshd[12345]: Failed password for root "
        "from 192.168.1.50 port 54321 ssh2"
    )
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type is EventType.FAILED_PASSWORD
    assert event.timestamp == datetime(2026, 3, 10, 13, 45, 12)
    assert event.host == "webserver"
    assert event.pid == 12345
    assert event.user == "root"
    assert event.ip == "192.168.1.50"
    assert event.port == 54321
    assert event.invalid_user is False
    assert event.is_failure and not event.is_success


def test_failed_password_for_invalid_user():
    """The optional 'invalid user ' group must not swallow the username."""
    line = (
        "Mar 10 13:45:14 web sshd[12346]: Failed password for invalid user "
        "admin from 203.0.113.5 port 40122 ssh2"
    )
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type is EventType.FAILED_PASSWORD
    assert event.user == "admin"
    assert event.invalid_user is True


def test_invalid_user_without_port():
    line = "Mar 10 13:45:20 web sshd[12347]: Invalid user oracle from 203.0.113.5"
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type is EventType.INVALID_USER
    assert event.user == "oracle"
    assert event.port is None
    assert event.invalid_user is True


def test_accepted_password():
    line = (
        "Mar 10 13:46:00 web sshd[12349]: Accepted password for joao "
        "from 10.0.0.15 port 51230 ssh2"
    )
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type is EventType.ACCEPTED_PASSWORD
    assert event.is_success and not event.is_failure


def test_accepted_publickey():
    line = (
        "Mar 10 13:46:01 web sshd[12350]: Accepted publickey for joao "
        "from 10.0.0.15 port 51234 ssh2: RSA SHA256:abcdef"
    )
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type is EventType.ACCEPTED_PUBLICKEY
    assert event.user == "joao"


@pytest.mark.parametrize("qualifier", ["authenticating", "invalid"])
def test_connection_closed_preauth(qualifier):
    line = (
        f"Mar 10 13:47:00 web sshd[12360]: Connection closed by {qualifier} "
        f"user root 203.0.113.5 port 40200 [preauth]"
    )
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.event_type is EventType.CONNECTION_CLOSED_PREAUTH
    assert event.is_failure


def test_iso_timestamp_supplies_its_own_year():
    """ISO lines carry a year, so the `year` argument must be ignored."""
    line = (
        "2024-07-04T09:30:15.482611-04:00 web sshd[900]: Accepted publickey "
        "for joao from 10.0.0.15 port 51999 ssh2: RSA SHA256:abc"
    )
    event = parse_line(line, year=YEAR)

    assert event is not None
    assert event.timestamp == datetime(2024, 7, 4, 9, 30, 15)
    assert event.timestamp.tzinfo is None


def test_ipv6_source_address():
    line = (
        "Mar 10 13:45:12 web sshd[1]: Failed password for root "
        "from 2001:db8::1 port 40000 ssh2"
    )
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.ip == "2001:db8::1"


def test_missing_pid_is_tolerated():
    line = (
        "Mar 10 13:45:12 web sshd: Failed password for root "
        "from 192.168.1.50 port 54321 ssh2"
    )
    event = parse_line(line, YEAR)

    assert event is not None
    assert event.pid is None


# ---------------------------------------------------------------------------
# Lines that are not events (must return None, never raise)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "totally broken line with no structure",
        "Mar 10 13:48:00 web CRON[400]: session opened for user root",
        "Mar 10 13:48:00 web sudo[401]: joao : COMMAND=/bin/ls",
        "Mar 10 13:49:00 web sshd[402]: Server listening on 0.0.0.0 port 22.",
        "Mar 10 13:50:00 web sshd[403]: Failed password for",
    ],
)
def test_non_events_return_none(line):
    assert parse_line(line, YEAR) is None


def test_process_filter_is_respected():
    line = "Mar 10 13:45:12 web dropbear[1]: Failed password for root from 1.2.3.4 port 22"
    assert parse_line(line, YEAR) is None
    assert parse_line(line, YEAR, process_filter="dropbear") is not None


# ---------------------------------------------------------------------------
# Malformed but recognizable (must raise ParseError)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "timestamp",
    ["Mar 32 10:00:00", "Feb 30 10:00:00", "Xyz 10 10:00:00", "Mar 10 25:61:99"],
)
def test_invalid_timestamp_raises(timestamp):
    line = (
        f"{timestamp} web sshd[999]: Failed password for root "
        f"from 10.0.0.9 port 22 ssh2"
    )
    with pytest.raises(ParseError):
        parse_line(line, YEAR)


def test_invalid_iso_timestamp_raises():
    line = (
        "2026-13-45T99:99:99 web sshd[1]: Failed password for root "
        "from 10.0.0.9 port 22 ssh2"
    )
    with pytest.raises(ParseError):
        parse_line(line, YEAR)


# ---------------------------------------------------------------------------
# AuthEvent contract
# ---------------------------------------------------------------------------

def test_event_is_frozen_and_hashable():
    event = parse_line(
        "Mar 10 13:45:12 web sshd[1]: Failed password for root "
        "from 10.0.0.9 port 22 ssh2",
        YEAR,
    )
    assert event is not None
    assert {event, event} == {event}

    with pytest.raises(Exception):
        event.ip = "0.0.0.0"  # type: ignore[misc]


def test_event_type_compares_to_plain_string():
    assert EventType.FAILED_PASSWORD == "failed_password"


def test_raw_line_is_preserved_as_evidence():
    line = (
        "Mar 10 13:45:12 web sshd[1]: Failed password for root "
        "from 10.0.0.9 port 22 ssh2"
    )
    event = parse_line(line, YEAR)
    assert event is not None
    assert event.raw == line


def test_to_dict_is_json_safe():
    import json

    event = parse_line(
        "Mar 10 13:45:12 web sshd[1]: Failed password for root "
        "from 10.0.0.9 port 22 ssh2",
        YEAR,
    )
    assert event is not None
    assert json.loads(json.dumps(event.to_dict()))["event_type"] == "failed_password"


def test_auth_event_can_be_constructed_directly():
    """Guards the dataclass signature used by the detector's test helpers."""
    event = AuthEvent(
        timestamp=datetime(2026, 1, 1),
        host="h",
        pid=1,
        event_type=EventType.FAILED_PASSWORD,
        user="u",
        ip="1.2.3.4",
        port=22,
    )
    assert event.is_failure