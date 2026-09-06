"""
src/reporter.py
Aggregates events and findings into a report, and renders it as text,
JSON or CSV.

This module makes no detection decisions. It receives what the reader and
the detector produced and turns it into something a human or a pipeline
can consume.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime
from typing import TextIO

from src import __version__
from src.detector import DetectionConfig, DetectionResult
from src.parser import AuthEvent
from src.reader import ReadStats

TOP_N = 10

CSV_COLUMNS = [
    "type",
    "severity",
    "ip",
    "user",
    "first_seen",
    "last_seen",
    "failure_count",
    "distinct_users",
    "targeted_users",
    "attempts_per_minute",
    "attempts_per_user",
    "auth_method",
    "detail",
]


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _hourly_distribution(events: list[AuthEvent]) -> list[dict]:
    """Bucket events by calendar hour.

    Hourly is the right granularity for a portfolio-scale report: fine
    enough to expose a burst, coarse enough to stay readable in a terminal.
    """
    buckets: Counter[str] = Counter()
    failures: Counter[str] = Counter()

    for event in events:
        key = event.timestamp.strftime("%Y-%m-%d %H:00")
        buckets[key] += 1
        if event.is_failure:
            failures[key] += 1

    return [
        {"hour": hour, "events": count, "failures": failures.get(hour, 0)}
        for hour, count in sorted(buckets.items())
    ]


def build_report(
    events: list[AuthEvent],
    read_stats: ReadStats,
    result: DetectionResult,
    config: DetectionConfig,
    top_n: int = TOP_N,
) -> dict:
    """Assemble the complete report as a plain dict.

    A dict rather than a bespoke object: it is what json.dump wants, what
    the CSV writer iterates, and what a downstream SIEM would ingest.
    """
    by_type: Counter[str] = Counter()
    failures_by_ip: Counter[str] = Counter()
    targeted_users: Counter[str] = Counter()
    successes_by_user: Counter[str] = Counter()

    for event in events:
        by_type[event.event_type.value] += 1
        if event.is_failure:
            failures_by_ip[event.ip] += 1
            if event.user:
                targeted_users[event.user] += 1
        elif event.is_success and event.user:
            successes_by_user[event.user] += 1

    first_event = events[0].timestamp.isoformat() if events else None
    last_event = events[-1].timestamp.isoformat() if events else None

    return {
        "metadata": {
            "tool": "ssh-bruteforce-detector",
            "version": __version__,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "config": config.to_dict(),
        },
        "statistics": {
            **read_stats.to_dict(),
            "analyzed_failures": result.analyzed_failures,
            "deduplicated_events": result.deduplicated_events,
        },
        "summary": {
            "total_events": len(events),
            "first_event": first_event,
            "last_event": last_event,
            "events_by_type": dict(by_type.most_common()),
            "total_findings": result.total_findings,
            "brute_force_incidents": len(result.brute_force),
            "spraying_incidents": len(result.spraying),
            "compromise_incidents": len(result.compromises),
            "suspicious_ips": sorted(result.suspicious_ips),
        },
        "top_offender_ips": [
            {
                "ip": ip,
                "failures": count,
                "flagged": ip in result.suspicious_ips,
            }
            for ip, count in failures_by_ip.most_common(top_n)
        ],
        "top_targeted_users": [
            {"user": user, "failures": count}
            for user, count in targeted_users.most_common(top_n)
        ],
        "successful_logins_by_user": [
            {"user": user, "successes": count}
            for user, count in successes_by_user.most_common(top_n)
        ],
        "hourly_distribution": _hourly_distribution(events),
        "findings": result.all_findings(),
        "malformed_samples": read_stats.malformed_samples,
    }


# ---------------------------------------------------------------------------
# Rendering — JSON
# ---------------------------------------------------------------------------

def render_json(report: dict, indent: int = 2) -> str:
    """Serialize the report. EventType inherits str, so no custom encoder."""
    return json.dumps(report, indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Rendering — CSV
# ---------------------------------------------------------------------------

def write_csv(report: dict, handle: TextIO) -> None:
    """Write one flat row per finding.

    CSV is for pipelines and spreadsheets, so the shape is deliberately
    rectangular: every finding type shares the same columns and leaves the
    irrelevant ones empty, rather than each type inventing its own header.
    """
    writer = csv.DictWriter(
        handle, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()

    for finding in report["findings"]:
        users = finding.get("targeted_users") or []
        detail = "; ".join(finding.get("reasons", []))

        writer.writerow({
            "type": finding.get("type", ""),
            "severity": finding.get("severity", ""),
            "ip": finding.get("ip", ""),
            "user": finding.get("user", ""),
            "first_seen": finding.get("first_seen", ""),
            "last_seen": finding.get("last_seen", ""),
            "failure_count": finding.get(
                "failure_count", finding.get("prior_failures", "")
            ),
            "distinct_users": finding.get("distinct_users", ""),
            "targeted_users": "|".join(users),
            "attempts_per_minute": finding.get("attempts_per_minute", ""),
            "attempts_per_user": finding.get("attempts_per_user", ""),
            "auth_method": finding.get("auth_method", ""),
            "detail": detail,
        })


# ---------------------------------------------------------------------------
# Rendering — human-readable text
# ---------------------------------------------------------------------------

def _rule(title: str, width: int = 74) -> str:
    return f"\n{title}\n{'-' * width}"


def _sparkline(counts: list[int]) -> str:
    """Tiny inline bar chart for the hourly distribution."""
    if not counts:
        return ""
    blocks = " ▁▂▃▄▅▆▇█"
    peak = max(counts) or 1
    return "".join(blocks[min(8, round(value / peak * 8))] for value in counts)


def render_text(report: dict) -> str:
    """Render the report for a terminal."""
    lines: list[str] = []
    summary = report["summary"]
    stats = report["statistics"]

    lines.append("=" * 74)
    lines.append("  SSH AUTHENTICATION LOG ANALYSIS")
    lines.append("=" * 74)

    # --- processing ------------------------------------------------------
    lines.append(_rule("PROCESSING"))
    lines.append(f"  Files read           : {len(stats['files_read'])}")
    for path in stats["files_read"]:
        lines.append(f"      - {path}")
    lines.append(f"  Lines processed      : {stats['total_lines']}")
    lines.append(f"  Events parsed        : {stats['parsed_events']}")
    lines.append(f"  Lines ignored        : {stats['ignored_lines']}")
    lines.append(f"  Malformed lines      : {stats['malformed_lines']}")
    lines.append(f"  Year rollovers       : {stats['year_rollovers']}")
    lines.append(f"  Duplicate pairs      : {stats['deduplicated_events']}")
    lines.append(f"  Failures analyzed    : {stats['analyzed_failures']}")

    for entry in stats["unreadable_files"]:
        lines.append(f"  ! unreadable: {entry['file']} ({entry['reason']})")

    if summary["total_events"] == 0:
        lines.append(_rule("RESULT"))
        lines.append("  No authentication events found. Nothing to analyze.")
        return "\n".join(lines)

    # --- summary ---------------------------------------------------------
    lines.append(_rule("SUMMARY"))
    lines.append(f"  Time range           : {summary['first_event']}")
    lines.append(f"                    to   {summary['last_event']}")
    lines.append(f"  Total events         : {summary['total_events']}")
    for name, count in summary["events_by_type"].items():
        lines.append(f"      {name:<28} {count:>6}")

    # --- findings --------------------------------------------------------
    lines.append(_rule("FINDINGS"))
    if not report["findings"]:
        lines.append("  No suspicious activity detected.")
    else:
        lines.append(
            f"  {summary['compromise_incidents']} compromise | "
            f"{summary['brute_force_incidents']} brute force | "
            f"{summary['spraying_incidents']} spraying"
        )
        for finding in report["findings"]:
            lines.append("")
            lines.append(
                f"  [{finding['severity'].upper()}] "
                f"{finding['type'].replace('_', ' ')} - {finding['ip']}"
            )
            lines.append(f"      window   : {finding['first_seen']}")
            lines.append(f"                 {finding['last_seen']}")

            if finding["type"] == "post_attack_success":
                lines.append(
                    f"      account  : {finding['user']} "
                    f"via {finding['auth_method']}"
                )
                lines.append(
                    f"      breached : "
                    f"{finding['seconds_since_first_activity']}s after "
                    f"{finding['prior_failures']} failed attempts"
                )
                for reason in finding["reasons"]:
                    lines.append(f"      context  : {reason}")
            elif finding["type"] == "brute_force":
                lines.append(
                    f"      failures : {finding['failure_count']} "
                    f"(peak {finding['peak_in_window']} in window, "
                    f"{finding['attempts_per_minute']}/min)"
                )
                lines.append(
                    f"      targets  : {', '.join(finding['targeted_users'])}"
                )
            else:
                lines.append(
                    f"      attempts : {finding['failure_count']} across "
                    f"{finding['distinct_users']} accounts "
                    f"({finding['attempts_per_user']} per account)"
                )
                lines.append(
                    f"      targets  : {', '.join(finding['targeted_users'])}"
                )

    # --- top offenders ---------------------------------------------------
    lines.append(_rule("TOP OFFENDING IPS"))
    if not report["top_offender_ips"]:
        lines.append("  None.")
    for entry in report["top_offender_ips"]:
        marker = "FLAGGED" if entry["flagged"] else ""
        lines.append(
            f"  {entry['ip']:<40} {entry['failures']:>6}  {marker}"
        )

    # --- top targets -----------------------------------------------------
    lines.append(_rule("TOP TARGETED ACCOUNTS"))
    if not report["top_targeted_users"]:
        lines.append("  None.")
    for entry in report["top_targeted_users"]:
        lines.append(f"  {entry['user']:<40} {entry['failures']:>6}")

    # --- timeline --------------------------------------------------------
    lines.append(_rule("HOURLY DISTRIBUTION"))
    buckets = report["hourly_distribution"]
    if buckets:
        lines.append(
            f"  {_sparkline([bucket['events'] for bucket in buckets])}"
        )
        peak = max(buckets, key=lambda bucket: bucket["events"])
        lines.append(
            f"  {len(buckets)} hourly buckets, peak {peak['events']} "
            f"events at {peak['hour']}"
        )
        for bucket in buckets:
            bar = "#" * min(40, bucket["events"])
            lines.append(
                f"  {bucket['hour']}  {bucket['events']:>5}  "
                f"({bucket['failures']} fail)  {bar}"
            )

    # --- malformed evidence ----------------------------------------------
    if report["malformed_samples"]:
        lines.append(_rule("MALFORMED LINE SAMPLES"))
        for sample in report["malformed_samples"]:
            lines.append(f"  line {sample['line_number']}: {sample['reason']}")
            lines.append(f"      {sample['raw']}")

    lines.append("")
    return "\n".join(lines)