"""
src/detector.py
Detection rules applied to a stream of parsed authentication events.

Three rules:
  1. brute force        — one IP, many attempts against few accounts
  2. password spraying  — one IP, few attempts against many accounts
  3. post-attack success — a login that worked from an already-hostile IP

This module never reads files and never formats output. Events in,
findings out, which keeps every rule unit-testable in isolation.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from src.parser import AuthEvent, EventType


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DetectionConfig:
    """Tunable parameters for every detection rule.

    Defaults are deliberately conservative: they catch obvious automated
    attacks with close to zero false positives on a normal host.
    """

    # --- brute force -------------------------------------------------------
    failure_threshold: int = 5
    window_minutes: int = 10

    # --- password spraying -------------------------------------------------
    # Minimum number of DISTINCT usernames one IP must touch.
    spray_user_threshold: int = 8
    # Spraying is slow by design and needs a far wider window than brute
    # force. Six hours covers a full working shift.
    spray_window_minutes: int = 360
    # Average attempts per user. Above this it stops looking like spraying
    # and starts looking like brute force, which the other rule owns.
    spray_max_attempts_per_user: float = 3.0

    # --- shared ------------------------------------------------------------
    # sshd logs an "Invalid user" line AND a "Failed password for invalid
    # user" line for a single attempt. Two log lines, one real attempt.
    # Collapse them when they share (pid, ip, user) within this many seconds.
    dedup_seconds: int = 5

    # IPs that must never be flagged: monitoring probes, jump hosts, CI.
    allowlist: frozenset[str] = frozenset()

    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)

    def spray_window(self) -> timedelta:
        return timedelta(minutes=self.spray_window_minutes)

    def to_dict(self) -> dict:
        return {
            "failure_threshold": self.failure_threshold,
            "window_minutes": self.window_minutes,
            "spray_user_threshold": self.spray_user_threshold,
            "spray_window_minutes": self.spray_window_minutes,
            "spray_max_attempts_per_user": self.spray_max_attempts_per_user,
            "dedup_seconds": self.dedup_seconds,
            "allowlist": sorted(self.allowlist),
        }


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class BruteForceIncident:
    """One continuous burst of failed logins from a single IP.

    Reported as ONE incident rather than one finding per failed attempt.
    An analyst wants "203.0.113.5 made 47 attempts over 4 minutes", not 47
    near-identical alert rows — alert fatigue is the number one reason real
    alerts get ignored.
    """

    ip: str
    first_seen: datetime
    last_seen: datetime
    failure_count: int
    peak_in_window: int
    targeted_users: list[str] = field(default_factory=list)
    sample_raw: str = ""

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def attempts_per_minute(self) -> float:
        """Attack rate. Humans mistyping rarely exceed 2; bots run far above."""
        minutes = self.duration_seconds / 60
        if minutes <= 0:
            return float(self.failure_count)
        return self.failure_count / minutes

    def to_dict(self) -> dict:
        return {
            "type": "brute_force",
            "severity": "high",
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": round(self.duration_seconds, 1),
            "failure_count": self.failure_count,
            "peak_in_window": self.peak_in_window,
            "attempts_per_minute": round(self.attempts_per_minute, 2),
            "distinct_users": len(self.targeted_users),
            "targeted_users": self.targeted_users,
            "sample_raw": self.sample_raw,
        }


@dataclass(slots=True)
class SprayIncident:
    """One IP probing many distinct accounts with few attempts each."""

    ip: str
    first_seen: datetime
    last_seen: datetime
    distinct_users: int
    total_attempts: int
    targeted_users: list[str] = field(default_factory=list)
    sample_raw: str = ""

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    @property
    def attempts_per_user(self) -> float:
        """Low values are the signature of spraying: broad, not deep."""
        if self.distinct_users == 0:
            return 0.0
        return self.total_attempts / self.distinct_users

    def to_dict(self) -> dict:
        return {
            "type": "password_spraying",
            "severity": "high",
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": round(self.duration_seconds, 1),
            "failure_count": self.total_attempts,
            "distinct_users": self.distinct_users,
            "attempts_per_user": round(self.attempts_per_user, 2),
            "targeted_users": self.targeted_users,
            "sample_raw": self.sample_raw,
        }


@dataclass(slots=True)
class CompromiseIncident:
    """A successful login from an IP that was already flagged as hostile.

    The highest-severity finding this tool produces. Everything else
    describes an attempt; this one describes an attempt that WORKED.
    """

    ip: str
    user: str
    timestamp: datetime
    auth_method: str
    prior_failures: int
    first_hostile_activity: datetime
    reasons: list[str] = field(default_factory=list)
    sample_raw: str = ""

    @property
    def seconds_since_first_activity(self) -> float:
        return (self.timestamp - self.first_hostile_activity).total_seconds()

    def to_dict(self) -> dict:
        return {
            "type": "post_attack_success",
            "severity": "critical",
            "ip": self.ip,
            "user": self.user,
            "timestamp": self.timestamp.isoformat(),
            "first_seen": self.first_hostile_activity.isoformat(),
            "last_seen": self.timestamp.isoformat(),
            "auth_method": self.auth_method,
            "prior_failures": self.prior_failures,
            "seconds_since_first_activity": round(
                self.seconds_since_first_activity, 1
            ),
            "reasons": self.reasons,
            "sample_raw": self.sample_raw,
        }


@dataclass(slots=True)
class DetectionResult:
    """Everything the detection stage produced."""

    brute_force: list[BruteForceIncident] = field(default_factory=list)
    spraying: list[SprayIncident] = field(default_factory=list)
    compromises: list[CompromiseIncident] = field(default_factory=list)
    suspicious_ips: set[str] = field(default_factory=set)
    deduplicated_events: int = 0
    analyzed_failures: int = 0

    @property
    def has_findings(self) -> bool:
        return bool(self.brute_force or self.spraying or self.compromises)

    @property
    def total_findings(self) -> int:
        return len(self.brute_force) + len(self.spraying) + len(self.compromises)

    def all_findings(self) -> list[dict]:
        """Every finding as a dict, most severe first."""
        return (
            [item.to_dict() for item in self.compromises]
            + [item.to_dict() for item in self.brute_force]
            + [item.to_dict() for item in self.spraying]
        )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_failures(
    failures: list[AuthEvent],
    dedup_seconds: int,
) -> tuple[list[AuthEvent], int]:
    """Collapse the "Invalid user" + "Failed password" pair into one attempt.

    Both lines share the same sshd pid, source IP and target user, because
    sshd forks one process per connection. That pid is a correlation key
    already present in the log, for free.

    Counting both would make the threshold effectively half — and only for
    nonexistent usernames, making the detector inconsistent: more sensitive
    to typo'd names than to root.

    A standalone INVALID_USER (client disconnected before sending a
    password) is preserved: it is a real attempt, and it is the strongest
    signal of user enumeration, which the spraying rule depends on.
    """
    if dedup_seconds <= 0:
        return failures, 0

    limit = float(dedup_seconds)
    kept: list[AuthEvent] = []
    dropped = 0

    # Index password failures so each candidate lookup is O(1).
    password_failures: dict[
        tuple[int | None, str, str | None], list[datetime]
    ] = defaultdict(list)

    for event in failures:
        if event.event_type is EventType.FAILED_PASSWORD:
            password_failures[(event.pid, event.ip, event.user)].append(
                event.timestamp
            )

    for event in failures:
        if event.event_type is not EventType.INVALID_USER:
            kept.append(event)
            continue

        partner_times = password_failures.get((event.pid, event.ip, event.user), ())
        has_partner = any(
            abs((partner - event.timestamp).total_seconds()) <= limit
            for partner in partner_times
        )

        if has_partner:
            dropped += 1
        else:
            kept.append(event)

    return kept, dropped


def prepare_failures(
    events: list[AuthEvent],
    config: DetectionConfig,
) -> tuple[list[AuthEvent], int]:
    """Filter to failures, drop allowlisted IPs, then deduplicate."""
    failures = [
        event
        for event in events
        if event.is_failure and event.ip not in config.allowlist
    ]
    return deduplicate_failures(failures, config.dedup_seconds)


# ---------------------------------------------------------------------------
# Rule 1 — brute force (sliding window)
# ---------------------------------------------------------------------------

def _close_incident(
    ip: str,
    events: list[AuthEvent],
    peak: int,
) -> BruteForceIncident:
    """Turn a burst of events into a reportable incident."""
    users = sorted({event.user for event in events if event.user})
    return BruteForceIncident(
        ip=ip,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        failure_count=len(events),
        peak_in_window=peak,
        targeted_users=users,
        sample_raw=events[0].raw,
    )


def _scan_single_ip(
    ip: str,
    failures: list[AuthEvent],
    config: DetectionConfig,
) -> list[BruteForceIncident]:
    """Slide a time window over one IP's failures and cut out the bursts.

    The deque holds only the failures currently inside the window. Old
    events are evicted from the left as the window advances, so len(window)
    is always the live count of "failures in the last M minutes".

    deque, not list: list.pop(0) is O(n) because it shifts every remaining
    element left. Doing that once per event makes the whole scan quadratic.
    deque.popleft() is O(1) — it is a doubly linked list of blocks, and
    removing from an end is a pointer adjustment.

    The eviction is correct only because events arrive time-ordered:
    everything that must leave the window is always at the front.
    """
    window: deque[AuthEvent] = deque()
    span = config.window()
    incidents: list[BruteForceIncident] = []

    active: list[AuthEvent] | None = None
    peak = 0

    for event in failures:
        window.append(event)

        cutoff = event.timestamp - span
        while window and window[0].timestamp < cutoff:
            window.popleft()

        count = len(window)

        if count >= config.failure_threshold:
            if active is None:
                # Burst opens: adopt the whole window, since every event
                # in it belongs to the same attack.
                active = list(window)
                peak = count
            else:
                active.append(event)
                peak = max(peak, count)
        elif active is not None:
            incidents.append(_close_incident(ip, active, peak))
            active = None
            peak = 0

    if active is not None:
        incidents.append(_close_incident(ip, active, peak))

    return incidents


def detect_brute_force(
    failures: list[AuthEvent],
    config: DetectionConfig,
) -> list[BruteForceIncident]:
    """Find IPs exceeding the failure threshold inside the time window.

    Grouped per IP first: a global window would fire when five different
    IPs each failed once, which is not an attack. An attack is attributed
    to a single origin, so each IP gets its own independent window.
    """
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.ip].append(event)

    incidents: list[BruteForceIncident] = []
    for ip, ip_failures in by_ip.items():
        ip_failures.sort(key=lambda event: event.timestamp)
        incidents.extend(_scan_single_ip(ip, ip_failures, config))

    incidents.sort(
        key=lambda incident: (-incident.failure_count, incident.first_seen)
    )
    return incidents


# ---------------------------------------------------------------------------
# Rule 2 — password spraying
# ---------------------------------------------------------------------------

def _scan_spray_for_ip(
    ip: str,
    failures: list[AuthEvent],
    config: DetectionConfig,
) -> SprayIncident | None:
    """Slide a wide window over one IP, watching DISTINCT usernames.

    Brute force counts events; spraying counts unique targets. Recounting
    the window on every event would be O(k) per event — quadratic overall.
    Instead a Counter shadows the deque: increment on append, decrement on
    eviction, and delete the key when it hits zero. len(live_users) is then
    always the exact distinct count in O(1).

    The explicit `del` is mandatory: a user left at count 0 would keep its
    key and inflate len() forever.
    """
    window: deque[AuthEvent] = deque()
    live_users: Counter[str] = Counter()
    span = config.spray_window()

    best: SprayIncident | None = None

    for event in failures:
        if not event.user:
            continue

        window.append(event)
        live_users[event.user] += 1

        cutoff = event.timestamp - span
        while window and window[0].timestamp < cutoff:
            evicted = window.popleft()
            if evicted.user:
                live_users[evicted.user] -= 1
                if live_users[evicted.user] <= 0:
                    del live_users[evicted.user]

        distinct = len(live_users)
        attempts = len(window)

        if distinct < config.spray_user_threshold:
            continue

        # Deep and narrow is brute force, not spraying. Letting the other
        # rule own that case avoids two alerts for one behaviour.
        if attempts / distinct > config.spray_max_attempts_per_user:
            continue

        candidate = SprayIncident(
            ip=ip,
            first_seen=window[0].timestamp,
            last_seen=event.timestamp,
            distinct_users=distinct,
            total_attempts=attempts,
            targeted_users=sorted(live_users),
            sample_raw=window[0].raw,
        )

        # Keep the widest spray seen, breaking ties on total attempts so the
        # report shows the most complete picture of the enumeration.
        current_key = (candidate.distinct_users, candidate.total_attempts)
        best_key = (
            (best.distinct_users, best.total_attempts)
            if best is not None
            else (-1, -1)
        )
        if current_key > best_key:
            best = candidate

    return best


def detect_password_spraying(
    failures: list[AuthEvent],
    config: DetectionConfig,
) -> list[SprayIncident]:
    """Find IPs probing many accounts shallowly. Expects deduplicated input.

    Spraying is the geometric inverse of brute force: one password
    ("Summer2026!") against many accounts, rather than many passwords
    against one account. It exists precisely to stay under the brute-force
    threshold — and under Active Directory lockout policy. One rule can
    never cover both shapes, which is why the windows differ by design
    (10 minutes vs 6 hours).
    """
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in failures:
        by_ip[event.ip].append(event)

    incidents: list[SprayIncident] = []
    for ip, ip_failures in by_ip.items():
        ip_failures.sort(key=lambda event: event.timestamp)
        incident = _scan_spray_for_ip(ip, ip_failures, config)
        if incident is not None:
            incidents.append(incident)

    incidents.sort(key=lambda item: (-item.distinct_users, item.first_seen))
    return incidents


# ---------------------------------------------------------------------------
# Rule 3 — successful login from an already-hostile IP
# ---------------------------------------------------------------------------

AUTH_METHOD_LABELS = {
    EventType.ACCEPTED_PASSWORD: "password",
    EventType.ACCEPTED_PUBLICKEY: "publickey",
}


def detect_compromise(
    events: list[AuthEvent],
    brute_force: list[BruteForceIncident],
    spraying: list[SprayIncident],
    config: DetectionConfig,
) -> list[CompromiseIncident]:
    """Flag successful logins from IPs flagged hostile EARLIER in time.

    The ordering test is the whole rule. A success BEFORE the hostile
    activity is a legitimate session that merely preceded an attack from
    the same address — corporate NAT, carrier CGNAT and commercial VPNs
    put tens of thousands of people behind one public IP, so you and an
    attacker can share an address.

    Without the ordering test the tool would report that a real user was
    compromised because someone else behind the same NAT attacked later.
    That kind of false positive destroys trust: the analyst investigates
    twice, finds nothing, and stops opening the alert.
    """
    first_hostile: dict[str, datetime] = {}
    reasons: dict[str, list[str]] = defaultdict(list)
    failure_counts: dict[str, int] = defaultdict(int)

    for incident in brute_force:
        current = first_hostile.get(incident.ip)
        if current is None or incident.first_seen < current:
            first_hostile[incident.ip] = incident.first_seen
        failure_counts[incident.ip] += incident.failure_count
        reasons[incident.ip].append(
            f"brute force: {incident.failure_count} failures "
            f"(peak {incident.peak_in_window} within window)"
        )

    for incident in spraying:
        current = first_hostile.get(incident.ip)
        if current is None or incident.first_seen < current:
            first_hostile[incident.ip] = incident.first_seen
        failure_counts[incident.ip] += incident.total_attempts
        reasons[incident.ip].append(
            f"password spraying: {incident.distinct_users} distinct users"
        )

    compromises: list[CompromiseIncident] = []

    for event in events:
        if not event.is_success or event.ip in config.allowlist:
            continue

        hostile_since = first_hostile.get(event.ip)
        if hostile_since is None or event.timestamp < hostile_since:
            continue

        compromises.append(
            CompromiseIncident(
                ip=event.ip,
                user=event.user or "<unknown>",
                timestamp=event.timestamp,
                auth_method=AUTH_METHOD_LABELS.get(event.event_type, "unknown"),
                prior_failures=failure_counts[event.ip],
                first_hostile_activity=hostile_since,
                reasons=list(reasons[event.ip]),
                sample_raw=event.raw,
            )
        )

    compromises.sort(key=lambda item: item.timestamp)
    return compromises


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_detection(
    events: list[AuthEvent],
    config: DetectionConfig | None = None,
) -> DetectionResult:
    """Run every detection rule in dependency order.

    Compromise detection runs last: it consumes the output of the two rules
    before it to know which IPs are already considered hostile. Keeping that
    dependency here — rather than hidden inside detect_compromise — is what
    lets each rule stay a pure, independently testable function.
    """
    config = config or DetectionConfig()
    result = DetectionResult()

    failures, dropped = prepare_failures(events, config)
    result.deduplicated_events = dropped
    result.analyzed_failures = len(failures)

    result.brute_force = detect_brute_force(failures, config)
    result.spraying = detect_password_spraying(failures, config)

    for incident in result.brute_force:
        result.suspicious_ips.add(incident.ip)
    for incident in result.spraying:
        result.suspicious_ips.add(incident.ip)

    result.compromises = detect_compromise(
        events, result.brute_force, result.spraying, config
    )

    return result