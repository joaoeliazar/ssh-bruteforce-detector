"""Unit tests for src/detector.py — detection rules in isolation."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.detector import (
    DetectionConfig,
    deduplicate_failures,
    detect_brute_force,
    detect_compromise,
    detect_password_spraying,
    prepare_failures,
    run_detection,
)
from src.parser import AuthEvent, EventType
from src.reader import read_logs

BASE = datetime(2026, 9, 1, 10, 0, 0)
FIXTURE = Path(__file__).parent / "fixtures" / "sample_auth.log"


def make(
    offset_seconds: int,
    ip: str,
    user: str,
    event_type: EventType = EventType.FAILED_PASSWORD,
    pid: int = 1000,
) -> AuthEvent:
    """Build a synthetic event at BASE + offset."""
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=offset_seconds),
        host="web",
        pid=pid,
        event_type=event_type,
        user=user,
        ip=ip,
        port=40000,
        invalid_user=event_type is EventType.INVALID_USER,
        raw=f"<synthetic {ip} {user}>",
    )


@pytest.fixture
def config() -> DetectionConfig:
    return DetectionConfig()


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_invalid_user_pair_counts_as_one_attempt():
    events = [
        make(0, "1.2.3.4", "oracle", EventType.INVALID_USER, pid=77),
        make(2, "1.2.3.4", "oracle", EventType.FAILED_PASSWORD, pid=77),
    ]
    kept, dropped = deduplicate_failures(events, dedup_seconds=5)

    assert dropped == 1
    assert len(kept) == 1
    assert kept[0].event_type is EventType.FAILED_PASSWORD


def test_standalone_invalid_user_is_preserved():
    """No password line means the client disconnected — still a real attempt."""
    events = [make(0, "1.2.3.4", "oracle", EventType.INVALID_USER, pid=77)]
    kept, dropped = deduplicate_failures(events, dedup_seconds=5)

    assert dropped == 0
    assert len(kept) == 1


def test_different_pid_is_not_a_duplicate():
    """Different pid means a different connection, so two real attempts."""
    events = [
        make(0, "1.2.3.4", "oracle", EventType.INVALID_USER, pid=77),
        make(2, "1.2.3.4", "oracle", EventType.FAILED_PASSWORD, pid=88),
    ]
    _, dropped = deduplicate_failures(events, dedup_seconds=5)
    assert dropped == 0


def test_dedup_can_be_disabled():
    events = [
        make(0, "1.2.3.4", "oracle", EventType.INVALID_USER, pid=77),
        make(2, "1.2.3.4", "oracle", EventType.FAILED_PASSWORD, pid=77),
    ]
    kept, dropped = deduplicate_failures(events, dedup_seconds=0)
    assert dropped == 0 and len(kept) == 2


# ---------------------------------------------------------------------------
# Rule 1 — brute force
# ---------------------------------------------------------------------------

def test_below_threshold_is_not_flagged(config):
    events = [make(index * 10, "10.0.0.15", "joao") for index in range(4)]
    assert detect_brute_force(events, config) == []


def test_burst_is_flagged_once(config):
    events = [make(index * 5, "203.0.113.5", "root") for index in range(30)]
    incidents = detect_brute_force(events, config)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.ip == "203.0.113.5"
    assert incident.failure_count == 30
    assert incident.peak_in_window == 30
    assert incident.targeted_users == ["root"]
    assert incident.attempts_per_minute > 10


def test_slow_attacker_stays_under_the_window(config):
    """6 attempts over 50 minutes never reach 5 within any 10-minute window."""
    events = [make(index * 600, "198.51.100.7", "admin") for index in range(6)]
    assert detect_brute_force(events, config) == []


def test_boundary_attack_that_fixed_blocks_would_miss():
    """
    Eight failures straddling a 10-minute block edge. Fixed-block counting
    would see 4 + 4 and stay silent; the sliding window sees 8 together.
    """
    config = DetectionConfig(failure_threshold=5, window_minutes=10)
    offsets = [480, 510, 540, 570, 630, 660, 690, 720]
    events = [make(offset, "203.0.113.5", "root") for offset in offsets]

    incidents = detect_brute_force(events, config)
    assert len(incidents) == 1
    assert incidents[0].failure_count == 8


def test_separate_bursts_are_separate_incidents():
    config = DetectionConfig(failure_threshold=5, window_minutes=1)
    first = [make(index * 5, "203.0.113.5", "root") for index in range(6)]
    second = [make(3600 + index * 5, "203.0.113.5", "root") for index in range(6)]

    incidents = detect_brute_force(first + second, config)
    assert len(incidents) == 2


def test_failures_from_different_ips_do_not_combine(config):
    """Five IPs failing once each is not an attack."""
    events = [make(index * 10, f"10.0.0.{index}", "joao") for index in range(6)]
    assert detect_brute_force(events, config) == []


def test_allowlisted_ip_is_never_flagged():
    config = DetectionConfig(allowlist=frozenset({"10.0.0.99"}))
    events = [make(index * 5, "10.0.0.99", "monitor") for index in range(30)]

    failures, _ = prepare_failures(events, config)
    assert detect_brute_force(failures, config) == []


# ---------------------------------------------------------------------------
# Rule 2 — password spraying
# ---------------------------------------------------------------------------

SPRAY_USERS = [
    "admin", "backup", "deploy", "ftp", "git", "guest",
    "jenkins", "mysql", "postgres", "ubuntu",
]


def _spray_events(ip: str = "192.0.2.99") -> list[AuthEvent]:
    """10 accounts, 2 attempts each, 6 minutes apart."""
    events: list[AuthEvent] = []
    for round_index in range(2):
        for user_index, user in enumerate(SPRAY_USERS):
            offset = (round_index * 10 + user_index) * 360
            events.append(make(offset, ip, user, pid=5000 + len(events)))
    return sorted(events, key=lambda event: event.timestamp)


def test_spraying_is_flagged(config):
    incidents = detect_password_spraying(_spray_events(), config)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.distinct_users == 10
    assert incident.total_attempts == 20
    assert incident.attempts_per_user == pytest.approx(2.0)


def test_spraying_is_invisible_to_the_brute_force_rule(config):
    """That invisibility is exactly why the second rule has to exist."""
    assert detect_brute_force(_spray_events(), config) == []


def test_few_accounts_are_not_spraying(config):
    events = [
        make(index * 360, "192.0.2.99", SPRAY_USERS[index % 3])
        for index in range(20)
    ]
    assert detect_password_spraying(events, config) == []


def test_deep_and_narrow_is_not_reported_as_spraying(config):
    """One IP, 10 accounts, 10 attempts each: brute force owns this shape."""
    events: list[AuthEvent] = []
    for user_index, user in enumerate(SPRAY_USERS):
        for attempt in range(10):
            events.append(
                make((user_index * 10 + attempt) * 60, "192.0.2.99", user)
            )
    events.sort(key=lambda event: event.timestamp)

    assert detect_password_spraying(events, config) == []


def test_spraying_beyond_the_window_is_not_flagged():
    """Spread the same 10 accounts over 10 days and the window never holds 8."""
    config = DetectionConfig(spray_window_minutes=60)
    events = [
        make(index * 86400, "192.0.2.99", user)
        for index, user in enumerate(SPRAY_USERS)
    ]
    assert detect_password_spraying(events, config) == []


# ---------------------------------------------------------------------------
# Rule 3 — post-attack success
# ---------------------------------------------------------------------------

def test_success_after_attack_is_a_compromise(config):
    attack = [make(index * 5, "203.0.113.5", "root") for index in range(30)]
    success = make(400, "203.0.113.5", "root", EventType.ACCEPTED_PASSWORD)
    events = attack + [success]

    brute_force = detect_brute_force(attack, config)
    compromises = detect_compromise(events, brute_force, [], config)

    assert len(compromises) == 1
    assert compromises[0].user == "root"
    assert compromises[0].auth_method == "password"
    assert compromises[0].prior_failures == 30
    assert compromises[0].seconds_since_first_activity == 400


def test_success_before_attack_is_not_a_compromise(config):
    """
    Shared NAT and CGNAT put real users behind the same public IP as an
    attacker. A login that precedes the attack is a legitimate session.
    """
    early_success = make(0, "203.0.113.5", "joao", EventType.ACCEPTED_PUBLICKEY)
    attack = [make(600 + index * 5, "203.0.113.5", "root") for index in range(30)]

    brute_force = detect_brute_force(attack, config)
    compromises = detect_compromise([early_success] + attack, brute_force, [], config)

    assert compromises == []


def test_success_from_a_clean_ip_is_not_flagged(config):
    attack = [make(index * 5, "203.0.113.5", "root") for index in range(30)]
    clean = make(400, "10.0.0.15", "joao", EventType.ACCEPTED_PUBLICKEY)

    brute_force = detect_brute_force(attack, config)
    compromises = detect_compromise(attack + [clean], brute_force, [], config)

    assert compromises == []


def test_compromise_after_spraying_is_flagged(config):
    events = _spray_events()
    success = make(10000, "192.0.2.99", "guest", EventType.ACCEPTED_PASSWORD)

    spraying = detect_password_spraying(events, config)
    compromises = detect_compromise(events + [success], [], spraying, config)

    assert len(compromises) == 1
    assert "password spraying" in compromises[0].reasons[0]


# ---------------------------------------------------------------------------
# End to end, on the bundled fixture
# ---------------------------------------------------------------------------

def test_fixture_end_to_end():
    events, _ = read_logs([FIXTURE])
    result = run_detection(events, DetectionConfig())

    assert result.analyzed_failures == 34
    assert result.deduplicated_events == 1

    assert len(result.brute_force) == 1
    assert result.brute_force[0].ip == "203.0.113.5"
    assert result.brute_force[0].failure_count == 12

    assert len(result.spraying) == 1
    assert result.spraying[0].ip == "192.0.2.99"
    assert result.spraying[0].distinct_users == 10
    assert result.spraying[0].total_attempts == 20

    assert len(result.compromises) == 1
    assert result.compromises[0].ip == "203.0.113.5"
    assert result.compromises[0].user == "root"

    assert result.suspicious_ips == {"203.0.113.5", "192.0.2.99"}
    assert result.has_findings


def test_fixture_legitimate_traffic_is_never_flagged():
    events, _ = read_logs([FIXTURE])
    result = run_detection(events, DetectionConfig())

    assert "10.0.0.15" not in result.suspicious_ips
    assert "10.0.0.42" not in result.suspicious_ips
    assert "198.51.100.7" not in result.suspicious_ips


def test_findings_are_ordered_most_severe_first():
    events, _ = read_logs([FIXTURE])
    result = run_detection(events, DetectionConfig())

    assert result.all_findings()[0]["severity"] == "critical"


def test_empty_input_produces_no_findings():
    result = run_detection([], DetectionConfig())
    assert not result.has_findings
    assert result.total_findings == 0