"""
src/parser.py
Extracts SSH authentication events from syslog lines.

Single responsibility: string -> AuthEvent | None.
This module does not read files, does not count anything, and does not
decide what qualifies as an attack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

class EventType(str, Enum):
    """sshd event kinds we care about.

    Inherits from `str` so it serializes straight to JSON with no custom
    encoder, while still comparing equal to its plain string value.
    """

    FAILED_PASSWORD = "failed_password"
    INVALID_USER = "invalid_user"
    ACCEPTED_PASSWORD = "accepted_password"
    ACCEPTED_PUBLICKEY = "accepted_publickey"
    CONNECTION_CLOSED_PREAUTH = "connection_closed_preauth"


FAILURE_TYPES = frozenset({
    EventType.FAILED_PASSWORD,
    EventType.INVALID_USER,
    EventType.CONNECTION_CLOSED_PREAUTH,
})

SUCCESS_TYPES = frozenset({
    EventType.ACCEPTED_PASSWORD,
    EventType.ACCEPTED_PUBLICKEY,
})


# ---------------------------------------------------------------------------
# Event structure
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One parsed authentication event.

    frozen=True makes it immutable and hashable, so it can be placed in a
    set and no module can mutate an event another module already processed.
    slots=True drops the per-instance __dict__, which matters when a single
    log file yields hundreds of thousands of these.
    """

    timestamp: datetime
    host: str
    pid: int | None
    event_type: EventType
    user: str | None
    ip: str
    port: int | None
    invalid_user: bool = False
    raw: str = ""

    @property
    def is_failure(self) -> bool:
        return self.event_type in FAILURE_TYPES

    @property
    def is_success(self) -> bool:
        return self.event_type in SUCCESS_TYPES

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "pid": self.pid,
            "event_type": self.event_type.value,
            "user": self.user,
            "ip": self.ip,
            "port": self.port,
            "invalid_user": self.invalid_user,
        }


class ParseError(ValueError):
    """The line looks like an sshd entry, but one of its fields is invalid.

    Distinct from "not an event": a cron line is irrelevant, not broken.
    Conflating the two floods the malformed-line counter with normal noise.
    """


# ---------------------------------------------------------------------------
# Reusable regex building blocks
#
# Each fragment is defined exactly once and composed into the full patterns
# with f-strings. Improving IPv6 support means editing _IP alone; all five
# message patterns inherit the fix.
# ---------------------------------------------------------------------------

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

_TIMESTAMP = (
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)
_HOST = r"(?P<host>[\w.\-]+)"
_PROCESS = r"(?P<process>[\w\-/]+)(?:\[(?P<pid>\d+)\])?"

_USER = r"(?P<user>\S+)"
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]*)"
_PORT = r"(?P<port>\d{1,5})"
_INVALID = r"(?P<invalid>invalid\s+user\s+)?"


# Classic RFC 3164 envelope, common to every syslog daemon:
# "Mar 10 13:45:12 webserver sshd[12345]: <message>"
SYSLOG_LINE = re.compile(
    rf"^{_TIMESTAMP}\s+{_HOST}\s+{_PROCESS}:\s+(?P<message>.*)$"
)

# Modern RFC 3339 envelope, emitted by journald and by rsyslog configured
# with RSYSLOG_FileFormat. Carries its own year and timezone.
# "2026-03-10T13:45:12.482611-04:00 webserver sshd[12345]: <message>"
ISO_SYSLOG_LINE = re.compile(
    rf"^(?P<iso>\d{{4}}-\d{{2}}-\d{{2}}[T ]\d{{2}}:\d{{2}}:\d{{2}}"
    rf"(?:\.\d+)?(?:Z|[+-]\d{{2}}:?\d{{2}})?)"
    rf"\s+{_HOST}\s+{_PROCESS}:\s+(?P<message>.*)$"
)


# ---------------------------------------------------------------------------
# sshd message patterns
#
# Order matters: "Failed password for invalid user bob" contains both the
# "Failed password" and the "invalid user" ideas. Testing the more specific
# pattern first guarantees correct classification.
# ---------------------------------------------------------------------------

MESSAGE_PATTERNS: list[tuple[EventType, re.Pattern[str]]] = [
    (
        EventType.FAILED_PASSWORD,
        re.compile(
            rf"^Failed\s+password\s+for\s+{_INVALID}{_USER}"
            rf"\s+from\s+{_IP}\s+port\s+{_PORT}"
        ),
    ),
    (
        EventType.ACCEPTED_PASSWORD,
        re.compile(
            rf"^Accepted\s+password\s+for\s+{_USER}"
            rf"\s+from\s+{_IP}\s+port\s+{_PORT}"
        ),
    ),
    (
        EventType.ACCEPTED_PUBLICKEY,
        re.compile(
            rf"^Accepted\s+publickey\s+for\s+{_USER}"
            rf"\s+from\s+{_IP}\s+port\s+{_PORT}"
        ),
    ),
    (
        EventType.INVALID_USER,
        re.compile(
            rf"^Invalid\s+user\s+{_USER}\s+from\s+{_IP}"
            rf"(?:\s+port\s+{_PORT})?"
        ),
    ),
    (
        EventType.CONNECTION_CLOSED_PREAUTH,
        re.compile(
            rf"^Connection\s+closed\s+by\s+(?:authenticating|invalid)\s+user\s+"
            rf"{_USER}\s+{_IP}\s+port\s+{_PORT}"
        ),
    ),
]


# ---------------------------------------------------------------------------
# Timestamp construction
# ---------------------------------------------------------------------------

def build_timestamp(month: str, day: str, time_str: str, year: int) -> datetime:
    """Build a datetime from classic syslog fields.

    Deliberately avoids strptime('%b'), which is locale-dependent: on a host
    with LC_TIME=pt_BR it expects 'Abr' and crashes on the log's 'Apr'. The
    daemon writes in the C locale but this script runs in the user's locale,
    so that bug only appears on someone else's machine.
    """
    try:
        hour, minute, second = (int(part) for part in time_str.split(":"))
        return datetime(year, MONTHS[month], int(day), hour, minute, second)
    except (KeyError, ValueError) as exc:
        raise ParseError(
            f"invalid timestamp: {month} {day} {time_str} (year={year})"
        ) from exc


def parse_iso_timestamp(value: str) -> datetime:
    """Parse an RFC 3339 timestamp and normalize it to a naive datetime.

    Timezone info is dropped on purpose: comparing aware and naive datetimes
    raises TypeError, and the sliding-window detector compares timestamps
    constantly. Keeping every event naive is the safest single contract.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError(f"invalid ISO timestamp: {value}") from exc
    return parsed.replace(tzinfo=None)


def match_envelope(line: str) -> tuple[re.Match[str] | None, bool]:
    """Try both envelope formats. Returns (match, is_iso)."""
    match = ISO_SYSLOG_LINE.match(line)
    if match is not None:
        return match, True

    match = SYSLOG_LINE.match(line)
    if match is not None:
        return match, False

    return None, False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse_line(
    line: str,
    year: int,
    process_filter: str = "sshd",
) -> AuthEvent | None:
    """Convert one log line into an AuthEvent.

    Returns None when the line is not a relevant sshd authentication event.
    Raises ParseError when the line IS an sshd entry but a field is invalid.

    `year` is only consulted for classic syslog timestamps, which carry no
    year of their own. ISO 8601 lines supply theirs and ignore it.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    envelope, is_iso = match_envelope(line)
    if envelope is None:
        return None

    # A plain string comparison, done before trying five regexes. On a
    # cron-heavy log this is the difference between one match and six.
    if envelope.group("process") != process_filter:
        return None

    message = envelope.group("message")

    for event_type, pattern in MESSAGE_PATTERNS:
        match = pattern.match(message)
        if match is None:
            continue

        fields = match.groupdict()
        port = fields.get("port")
        pid = envelope.group("pid")

        if is_iso:
            timestamp = parse_iso_timestamp(envelope.group("iso"))
        else:
            timestamp = build_timestamp(
                envelope.group("month"),
                envelope.group("day"),
                envelope.group("time"),
                year,
            )

        return AuthEvent(
            timestamp=timestamp,
            host=envelope.group("host"),
            pid=int(pid) if pid else None,
            event_type=event_type,
            user=fields.get("user"),
            ip=fields["ip"],
            port=int(port) if port else None,
            invalid_user=(
                bool(fields.get("invalid"))
                or event_type is EventType.INVALID_USER
            ),
            raw=line,
        )

    return None