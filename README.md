![Tests](https://github.com/joaoeliazar/ssh-bruteforce-detector/actions/workflows/tests.yml/badge.svg)
# SSH Brute-Force Detector

A Python security tool that parses Linux authentication logs and detects SSH brute-force attacks, password spraying, and successful logins originating from previously hostile IP addresses.

Built entirely with the Python standard library, with no runtime dependencies.

---

## Features

* Parses common OpenSSH `sshd` authentication log formats
* Supports both classic RFC 3164 syslog timestamps and RFC 3339 / journald timestamps
* Sliding-window brute-force detection with configurable threshold and time window
* Password spraying detection across multiple user accounts
* Detects successful logins that occur after hostile activity from the same IP
* Deduplicates OpenSSH's double-logged `Invalid user` / `Failed password` attempts
* Reads rotated authentication logs automatically
* Supports gzip-compressed logs such as `auth.log.2.gz`
* Infers missing years from classic syslog timestamps, including New Year rollover
* Supports allowlisting trusted or noisy IP addresses
* Produces text, JSON, and CSV reports
* Tracks top attacking IPs, targeted users, hourly activity, and detection statistics
* Gracefully handles malformed lines, unreadable files, and invalid UTF-8

---

## How to Run

### Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
```

The detector has no runtime dependencies.

Install `pytest` only if you want to run the test suite:

```bash
pip install pytest
```

### Run

Analyze a Linux authentication log:

```bash
python main.py /var/log/auth.log
```

Try the detector using the included synthetic fixture:

```bash
python main.py tests/fixtures/sample_auth.log
```

Use a more aggressive detection threshold:

```bash
python main.py /var/log/auth.log --threshold 3 --window 5
```

Export the report as JSON:

```bash
python main.py /var/log/auth.log --format json -o reports/auth.json
```

Export CSV to stdout:

```bash
python main.py /var/log/auth.log --format csv
```

Analyze RHEL / CentOS authentication logs:

```bash
python main.py /var/log/secure
```

Exclude trusted or known-noisy sources:

```bash
python main.py /var/log/auth.log --allowlist 10.0.0.5 10.0.0.6
```

Analyze only the specified file instead of including rotated logs:

```bash
python main.py /var/log/auth.log --no-rotated
```

### Test

```bash
pytest
pytest -v
pytest tests/test_detector.py
```

> Reading `/var/log/auth.log` normally requires elevated privileges. Prefer copying the log into a working directory instead of running the entire detector as root.

---

## Command-Line Options

| Option         |  Default | Description                                                  |
| -------------- | -------: | ------------------------------------------------------------ |
| `logfile`      | required | Authentication log to analyze                                |
| `--threshold`  |      `5` | Number of failures required to trigger brute-force detection |
| `--window`     |     `10` | Detection window in minutes                                  |
| `--format`     |   `text` | Report format: text, JSON, or CSV                            |
| `-o`           |   stdout | Write the generated report to a file                         |
| `--allowlist`  |        — | IP addresses that should be excluded from detection          |
| `--no-rotated` |      off | Analyze only the specified file and ignore rotated siblings  |
| `-q`           |      off | Quiet mode, useful for automation                            |

---

## Detection Rules

### Brute Force

Detects repeated authentication failures from the same IP inside a configurable sliding time window.

Default rule:

```text
5 failed attempts within 10 minutes
```

Unlike fixed time blocks, the sliding window moves with every authentication event, preventing attacks from avoiding detection by crossing arbitrary time boundaries.

### Password Spraying

Detects a single IP attempting authentication against many different usernames while keeping the number of attempts against each account relatively low.

This catches behavior such as:

```text
203.0.113.20 -> admin
203.0.113.20 -> root
203.0.113.20 -> oracle
203.0.113.20 -> postgres
203.0.113.20 -> backup
```

A traditional per-user brute-force rule could miss this pattern because no individual account receives enough failures.

### Post-Attack Success

Flags a successful authentication when the source IP previously generated hostile activity.

Temporal ordering is enforced:

```text
failures -> attack detected -> successful login
```

A legitimate login that occurred before the attack is not treated as a compromise.

---

## Exit Codes

| Code | Meaning                                                    |
| ---: | ---------------------------------------------------------- |
|  `0` | Analysis completed successfully with no findings           |
|  `1` | Analysis completed successfully and findings were detected |
|  `2` | Fatal error; no readable input was available               |

This makes the detector usable in scripts, CI pipelines, and scheduled monitoring:

```bash
python main.py /var/log/auth.log -q || alert
```

---

## Sample Results

The included `tests/fixtures/sample_auth.log` contains legitimate traffic, attack activity, malformed input, SSH noise, a brute-force burst, password spraying, and a successful login following hostile activity.

Running the detector against the fixture is expected to produce:

```text
46 log lines
39 parsed authentication events
2 malformed lines
5 ignored lines

1 brute-force incident
1 password-spraying incident
1 post-attack successful login
```

The fixture also contains an OpenSSH `Invalid user` / `Failed password` pair that must count as a single authentication attempt.

---

## Project Structure

```text
ssh-bruteforce-detector/
├── src/
│   ├── parser.py          # regex parsing: log line -> AuthEvent
│   ├── reader.py          # files, rotation, gzip, and year inference
│   ├── detector.py        # sliding windows and detection rules
│   ├── reporter.py        # aggregation and text / JSON / CSV output
│   └── cli.py             # argparse configuration and exit codes
├── tests/
│   ├── fixtures/
│   │   └── sample_auth.log
│   ├── test_parser.py
│   ├── test_reader.py
│   └── test_detector.py
├── conftest.py
├── main.py
└── README.md
```

`reader.py` and `parser.py` are intentionally separated.

The parser is responsible for understanding the contents of an authentication log line, while the reader handles filesystem concerns such as rotation, compression, encoding, and timestamp context. Keeping those responsibilities separate creates cleaner test boundaries and prevents unrelated filesystem logic from leaking into parsing code.

---

## Technologies

* Python 3.11+
* Standard library only — no runtime dependencies
* Regular expressions for structured SSH log parsing
* `dataclasses` for authentication event modelling
* `collections.deque` for efficient sliding windows
* `collections.Counter` for live password-spraying statistics
* `datetime` for timestamp normalization and year inference
* `gzip` for compressed rotated logs
* `argparse` for the command-line interface
* `json` and `csv` for structured reporting
* `pytest` for the test suite

---

## Design Decisions

### Sliding windows instead of fixed time blocks

A fixed-block detector divides time into intervals such as:

```text
10:00 - 10:10
10:10 - 10:20
```

That creates a blind spot.

An attacker could generate four failures immediately before the boundary and another four immediately after it:

```text
10:08:00   attempt
10:08:30   attempt
10:09:00   attempt
10:09:30   attempt

------------ boundary ------------

10:10:30   attempt
10:11:00   attempt
10:11:30   attempt
10:12:00   attempt
```

Each block contains only four failures even though eight attempts occurred within four minutes.

A sliding window instead asks:

```text
How many failures occurred during the last M minutes?
```

There are no exploitable block boundaries.

---

### `deque` instead of a list

The detector constantly removes expired events from the beginning of each IP's active window.

Using:

```python
list.pop(0)
```

is `O(n)` because every remaining element must be shifted.

Using:

```python
deque.popleft()
```

is `O(1)`.

Because authentication events are processed chronologically, expired events always exist at the front of the deque.

This keeps window maintenance efficient even when processing large logs.

---

### `Counter` for password spraying

Brute-force detection needs the number of authentication attempts.

Password spraying needs something different:

```text
How many distinct users is this IP attacking?
```

A `Counter` tracks how many live attempts belong to each username while the deque maintains the active time window.

When an event expires:

```text
counter[user] -= 1
```

If its count reaches zero, the key is removed.

That allows:

```python
len(live_users)
```

to remain an exact `O(1)` count of currently targeted usernames.

---

### Year inference for classic syslog timestamps

Traditional RFC 3164 timestamps look like:

```text
Mar 10 13:45:12
```

There is no year.

Using the current year would work for the live `auth.log`, but would produce incorrect timestamps when analyzing older rotated files.

The detector instead anchors inference to the log file's modification time.

It also detects year rollover when a file contains events such as:

```text
Dec 31 23:59:58
Jan  1 00:00:03
```

RFC 3339 / ISO 8601 log entries already contain a year and bypass this inference entirely.

---

### Explicit month mapping instead of `strptime("%b")`

`%b` depends on the operating system's locale.

A system configured with:

```text
LC_TIME=pt_BR
```

may expect localized month abbreviations even though system daemons typically write logs using English month names.

An explicit month dictionary avoids that dependency and produces deterministic behavior across machines.

---

### Deduplicating OpenSSH events

OpenSSH may generate two log entries for a single authentication attempt against a nonexistent user:

```text
Invalid user oracle from 203.0.113.5 port 40130
Failed password for invalid user oracle from 203.0.113.5 port 40130 ssh2
```

Counting both would effectively cut the brute-force threshold in half for invalid usernames.

The detector correlates events using:

```text
(pid, ip, user)
```

Because `sshd` forks a process for each connection, the PID provides a useful correlation identifier.

Standalone `Invalid user` events are preserved because they can indicate account enumeration.

---

### Temporal ordering for compromise detection

A successful login from an IP does not automatically mean that account was compromised.

NAT, VPN services, and carrier-grade NAT can place many unrelated users behind the same public address.

Therefore:

```text
successful login -> attack
```

is not considered compromise evidence.

Only:

```text
attack -> successful login
```

creates a post-attack success finding.

This reduces false positives significantly.

---

### One incident per attack burst

Without incident grouping, an attack containing 30 failures could create dozens of nearly identical alerts after the configured threshold is crossed.

Instead, an incident opens when the threshold is crossed and closes once the sliding window drops below the threshold.

Each incident can therefore contain useful context such as:

```text
first_seen
last_seen
failure_count
peak_in_window
attempts_per_minute
```

The result is one meaningful detection rather than an alert for every additional packet.

---

## Testing

The test suite uses a synthetic authentication log instead of real production credentials or system logs.

The fixture includes:

* legitimate SSH traffic
* an ordinary password typo
* `cron` and `sudo` noise that should be ignored
* a clear brute-force attack
* a successful login after the attack
* an `Invalid user` / `Failed password` duplicate pair
* password spraying across ten accounts
* malformed dates
* truncated SSH entries
* garbage input
* blank lines

Expected fixture results:

```text
46 lines
39 authentication events
2 malformed lines
5 ignored lines
1 brute-force incident
1 password-spraying incident
1 post-attack success
```

This tests not only whether attacks are detected, but also whether normal activity and malformed input are handled correctly.

---

## Concepts Practiced

* Linux authentication log analysis
* OpenSSH logging behavior
* Regular-expression parsing
* Defensive security detection engineering
* Brute-force detection
* Password-spraying detection
* Sliding-window algorithms
* Efficient queue operations with `deque`
* Frequency tracking with `Counter`
* Timestamp normalization and year inference
* Log rotation and gzip processing
* Event correlation
* False-positive reduction
* Security alert aggregation
* CLI design with `argparse`
* JSON and CSV reporting
* Defensive handling of malformed and untrusted input
* Unit testing with synthetic security data

---

## Choosing a Detection Threshold

There is no universally correct brute-force threshold.

A lower threshold detects attacks earlier but increases false positives:

```text
lower threshold
      ↓
higher sensitivity
      ↓
more false positives
```

A higher threshold produces more trustworthy alerts but gives slow attackers more room to operate:

```text
higher threshold
      ↓
lower noise
      ↓
greater chance of missing slow attacks
```

Example starting points:

| Environment                | Threshold / Window | Reason                                                                |
| -------------------------- | ------------------ | --------------------------------------------------------------------- |
| Internet-facing server     | `5 / 10 min`       | Quickly catches common automated SSH bots                             |
| Internal corporate network | `10 / 15 min`      | Allows more room for stale credentials and VPN clients                |
| Key-only SSH server        | `3 / 10 min`       | Password failures should be uncommon                                  |
| Slow-attack hunting        | `10 / 24 h`        | Detects attackers intentionally operating below short-term thresholds |

The best approach is to baseline normal activity and tune the detector for the environment being monitored.

---

## Known Limitations

* A single authentication log spanning more than twelve months can break year inference
* Date-based rotation formats such as `auth.log-20260301.gz` are not recognized
* Unknown `sshd` message formats are classified as ignored rather than malformed
* IPv6 matching is permissive and does not perform complete address validation
* Detection is primarily per source IP
* Distributed botnets using very few attempts from each address can evade the current rules
* CSV written directly to stdout on Windows may contain additional carriage returns
* Detection is log-based rather than real-time network monitoring

---

## Security Note

Never commit real authentication logs to a public repository.

Authentication logs may expose:

* valid usernames
* internal IP addresses
* public IP addresses
* hostnames
* login timestamps
* infrastructure information

The repository should ignore real `*.log` files while explicitly allowing only synthetic fixtures used by the test suite.

---

## Roadmap

* [ ] Correlation of distributed attacks across multiple source IPs
* [ ] Stricter IPv6 validation
* [ ] Support additional Linux authentication log formats
* [ ] Support date-based rotated log filenames
* [ ] Multiple detection profiles for fast and slow attacks
* [ ] Severity scoring using attack rate and peak window activity
* [ ] Optional real-time / streaming log monitoring
* [ ] Expanded reporting and visualization
