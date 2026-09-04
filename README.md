# SysGuard — Linux Security Audit & Account Intelligence CLI

> An async Python CLI that audits Linux user accounts, passwords, sudoers rules, and filesystem permissions — producing structured, risk-ranked security findings with JSON/CSV/text export.

---

## Table of Contents
1. [Problem Statement](#problem-statement)
2. [How It Solves the Problem](#how-it-solves-the-problem)
3. [Architecture](#architecture)
4. [Features](#features)
5. [Requirements](#requirements)
6. [Installation & Quick Start](#installation--quick-start)
7. [Usage](#usage)
8. [Risk Model](#risk-model)
9. [Output Formats](#output-formats)
10. [Logging & Audit Trail](#logging--audit-trail)
11. [Troubleshooting](#troubleshooting)
12. [Security Hardening Notes](#security-hardening-notes)
13. [Legal Disclaimer](#legal-disclaimer)

---

## Problem Statement

Auditing Linux account security manually requires correlating data scattered across `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/`, and the entire filesystem permission tree:

- **No single source of truth** — `chage -l`, `getent group`, `visudo -c`, and `find / -perm -4000` each show one slice of the picture.
- **Manual correlation is slow and error-prone** — cross-referencing "which sudo users have no password set" requires joining three different data sources by hand.
- **No risk ranking** — raw command output gives facts, not priorities. A security team needs to know what's *critical* versus merely *suboptimal*.
- **Filesystem-wide permission audits are expensive and easy to get wrong** — naive `find /` scans block for minutes and provide no progress feedback or timeout protection.
- **No structured output for tooling integration** — compliance pipelines, SIEMs, and ticketing systems need JSON/CSV, not terminal text.
- **No accountability trail for the audit process itself** — "who ran this scan and when" is rarely tracked.

## How It Solves the Problem

SysGuard performs a **unified async scan** across all account and permission data sources, normalizes everything into typed models, runs a battery of security analyzers in parallel, and produces a risk-ranked report.

| Concern | Solution |
|---|---|
| **Unified data model** | `UserAccount`, `GroupInfo`, `SudoersRule` dataclasses merge `/etc/passwd` + `/etc/shadow` + `/etc/group` + sudoers into one coherent view |
| **Speed** | Async I/O throughout; user policy analysis, sudoers analysis, and group analysis run concurrently via `asyncio.gather()` |
| **Memory efficiency** | Async generators (`AsyncIterator`) stream parse results and findings one record at a time — file scans never load the full result set into memory |
| **Risk ranking** | 6-tier `RiskLevel` enum (CLEAN → CRITICAL) drives sorting, filtering, and exit codes for CI/CD gating |
| **Bounded filesystem scan** | Semaphore-limited concurrent `stat()` calls, configurable timeout, max-file cap — won't hang on huge filesystems |
| **Structured export** | JSON (machine-readable), CSV (spreadsheet-friendly), and plain text (human-readable) — pick what your pipeline needs |
| **Accountability** | Every scan and export emits an async audit log record (JSON-lines) with timestamp, action, and result |
| **CIS Benchmark references** | Findings cite the relevant CIS Linux Benchmark control where applicable |

---

## Architecture

```
sysguard/
├── run.sh                          # Bootstrap: venv setup, dependency install, launcher
├── setup.py / setup.cfg            # Package metadata, entry point: `sysguard` command
├── requirements.txt                # pytest, pytest-asyncio
├── sysguard/
│   ├── core/
│   │   ├── exceptions.py           # OOP exception hierarchy, error codes, severities
│   │   ├── logger.py               # QueueHandler/QueueListener async-safe logging
│   │   └── config.py               # Central config (env-var overridable)
│   ├── models/
│   │   └── accounts.py             # UserAccount, GroupInfo, SudoersRule, SecurityFinding, ScanResult
│   ├── services/
│   │   ├── parsers.py              # Async generators: parse /etc/passwd, shadow, group, sudoers
│   │   ├── scanner.py              # Orchestrates parallel analysis, builds ScanResult
│   │   └── reporter.py             # JSON / CSV / text export, console report renderer
│   ├── analyzers/
│   │   └── security.py             # Async analyzers: password policy, sudoers, group membership, filesystem
│   └── cli/
│       └── main.py                 # argparse + interactive REPL entrypoint
└── tests/
    └── test_sysguard.py            # 92 tests: dunders, analyzers, reporter, config
```

### Data flow

```
/etc/passwd ──┐
/etc/shadow ──┼──► parsers.py (async generators) ──► UserAccount / GroupInfo / SudoersRule
/etc/group  ──┤
/etc/sudoers ─┘
                                          │
                                          ▼
                              scanner.py (asyncio.gather)
                                          │
              ┌───────────────┬──────────┼──────────────┬─────────────────┐
              ▼               ▼          ▼               ▼
     analyze_all_users  analyze_sudoers  analyze_group_   scan_filesystem
     (semaphore-bounded)                 memberships      (optional, semaphore-
                                                            bounded stat() calls)
              │               │          │               │
              └───────────────┴──────────┴───────────────┘
                                          │
                                          ▼
                                    ScanResult
                                          │
                              ┌───────────┼───────────┐
                              ▼           ▼           ▼
                         console      JSON/CSV     text report
                         report       export
```

### Concurrency model

- **Parsing**: `pwd.getpwall()` / `grp.getgrall()` run in a thread pool via `asyncio.to_thread()`; shadow and sudoers files are read line-by-line with `await asyncio.sleep(0)` yields every 100 lines.
- **Analysis**: User policy analysis runs one task per user, bounded by `asyncio.Semaphore(max_workers)`, collected with `asyncio.as_completed()`.
- **Filesystem scan**: A breadth-first directory queue with bounded concurrent `os.lstat()` calls (`Semaphore(max_workers * 2)`), a wall-clock timeout, and a max-file cap to guarantee termination.

---

## Features

- **Account analysis**: empty/locked passwords, password aging policy, missing max-age, weak warn-days, expired passwords, shell validity, missing home directories, weak home directory permissions
- **Sudoers analysis**: `NOPASSWD: ALL` detection (CRITICAL), unrestricted `ALL` access (HIGH), `NOPASSWD` partial rules (MEDIUM); parses both `/etc/sudoers` and `/etc/sudoers.d/*`
- **Group membership analysis**: flags users in `sudo`, `wheel`, `docker`, `shadow`, `adm`, `disk`, and other privileged groups
- **Filesystem permission audit** (optional, `--filesystem`): world-writable files, SUID/SGID binaries, files owned by non-existent UIDs
- **Risk-ranked reporting**: CLEAN / INFO / LOW / MEDIUM / HIGH / CRITICAL, with CIS Benchmark references where applicable
- **Three export formats**: JSON (full structured dump), CSV (findings + users, spreadsheet-ready), plain text (human-readable summary)
- **Interactive REPL**: `scan`, `report`, `export`, `users`, `findings`, `logs`, `config` commands
- **Exit code gating**: returns `1` if any CRITICAL finding exists — usable as a CI/CD security gate

---

## Requirements

| Component | Minimum |
|---|---|
| OS | Linux |
| Python | 3.11+ |
| Privileges | Best run as `root` (or `sudo`) for full `/etc/shadow` and sudoers access; runs in degraded mode without root |
| Dependencies | Standard library only for runtime (no third-party packages required); `pytest`, `pytest-asyncio` for tests |

---

## Installation & Quick Start

```bash
# 1. Clone or download
git clone https://github.com/kavineksith/SysGuard-Linux-Security-Audit-Account-Intelligence-CLI.git
cd SysGuard-Linux-Security-Audit-Account-Intelligence-CLI

# 2. Run the bootstrap (creates venv, installs package, launches)
sudo bash run.sh --help

# 3. Run a full scan
sudo bash run.sh scan

# 4. Run interactively
sudo bash run.sh --interactive
```

`run.sh` automatically:
- Locates a Python 3.11+ interpreter
- Creates a `.venv/` virtual environment (idempotent — skips if already set up)
- Installs the `sysguard` package in editable mode + test dependencies
- Hands off all arguments to `python -m sysguard.cli.main`

You can also install manually:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
sudo .venv/bin/sysguard scan
```

---

## Usage

### Basic scan

```bash
sudo bash run.sh scan
```

### Scan with filesystem permission audit

```bash
sudo bash run.sh scan --filesystem --scan-root /home
```

> ⚠️ Scanning `/` (default root) can take significant time on large filesystems. Use `--scan-root` to limit scope, and the scan auto-terminates at the configured timeout (default 60s) or 50,000 files, whichever comes first.

### Filter by minimum risk

```bash
sudo bash run.sh scan --min-risk HIGH
```

### Export reports

```bash
# Single format
sudo bash run.sh scan --json
sudo bash run.sh scan --csv
sudo bash run.sh scan --text

# All formats at once
sudo bash run.sh scan --all-formats --export-dir /var/reports/sysguard
```

### Verbose logging

```bash
sudo bash run.sh scan --log-level DEBUG
```

### Interactive mode

```bash
sudo bash run.sh --interactive
```

```
  sysguard ▶ scan
  sysguard ▶ findings --min HIGH
  sysguard ▶ export json
  sysguard ▶ users
  sysguard ▶ logs
  sysguard ▶ exit
```

### CI/CD gating example

```bash
#!/bin/bash
sudo bash run.sh scan --min-risk CRITICAL --json
if [[ $? -ne 0 ]]; then
    echo "Critical security findings detected — failing build"
    exit 1
fi
```

---

## Risk Model

| Level | Meaning | Examples |
|---|---|---|
| `CRITICAL` | Immediate exploitable risk | Sudo user with no password; `NOPASSWD: ALL` sudoers rule |
| `HIGH` | Significant exposure | World-writable file; sudo group membership; unrestricted `ALL` sudo access |
| `MEDIUM` | Notable misconfiguration | Expired password; user in `docker`/`adm` group; locked account with active shell |
| `LOW` | Best-practice deviation | No password max-age set; shell not in `/etc/shells` |
| `INFO` | Informational only | (reserved for future findings) |
| `CLEAN` | No issues found | — |

Findings reference relevant **CIS Linux Benchmark** controls where applicable (e.g., `CIS Benchmark L1: 5.4.1`).

---

## Output Formats

### JSON (`--json`)
Full structured dump: `summary`, `users[]`, `groups[]`, `findings[]`, `sudoers[]`, `errors[]`. Ideal for SIEM ingestion or programmatic processing.

### CSV (`--csv`)
Two files: `findings_<timestamp>.csv` (risk, category, title, target, detail, remediation, reference) and `users_<timestamp>.csv` (username, uid, status, sudo_access, groups, risk_level). Spreadsheet-ready.

### Text (`--text`)
Human-readable plain-text summary, suitable for email or ticket attachments — no ANSI codes.

### Console report
Always printed by default — colour-coded by risk level, includes executive summary, sorted findings list, and per-user risk table.

---

## Logging & Audit Trail

Logs are written to `<log_dir>/sysguard.log` (plain text) and `<log_dir>/audit.jsonl` (structured JSON-lines), default `/tmp/sysguard/logs/`.

Override with:
```bash
sudo bash run.sh scan --log-dir /var/log/sysguard
```

**Sample audit.jsonl record:**
```json
{
  "timestamp": "2026-06-30T04:39:16Z",
  "epoch": 1751258356.37,
  "level": "INFO",
  "logger": "sysguard.services.scanner",
  "message": "AUDIT action=SCAN_COMPLETE target=system result=OK",
  "action": "SCAN_COMPLETE",
  "target": "system",
  "result": "OK",
  "users": 23,
  "findings": 5,
  "critical": 0,
  "duration": "0.42s"
}
```

Query with `jq`:
```bash
jq 'select(.action == "SCAN_COMPLETE")' /tmp/sysguard/logs/audit.jsonl
jq 'select(.level == "ERROR")' /tmp/sysguard/logs/sysguard.log
```

---

## Troubleshooting

### "Not running as root" warning, shadow checks skipped
Shadow file analysis (password age, locked status) requires root. Run with `sudo bash run.sh ...` for a complete audit. Without root, SysGuard still analyzes `/etc/passwd`, `/etc/group`, and sudoers drop-ins that are world-readable.

### Filesystem scan times out
Increase the timeout or narrow the scope:
```bash
SYSGUARD_SCAN_TIMEOUT=120 sudo bash run.sh scan --filesystem --scan-root /home
```
Or scan a smaller root, e.g. `--scan-root /home` instead of `/`.

### "Python 3.11+ not found"
Install a modern Python:
```bash
# Ubuntu/Debian
sudo apt install python3.11 python3.11-venv

# Or via pyenv
pyenv install 3.12.0 && pyenv local 3.12.0
```

### Tests fail with "Queue has no attribute"
This was a known bug in early builds (`logging.handlers.Queue` doesn't exist — the correct import is `queue.Queue`). Ensure you're running the latest `sysguard/core/logger.py`; this is fixed in v1.0.0.

### High memory use during large filesystem scans
The scanner streams findings via async generators and never holds the full file tree in memory — but `max_files` (default 50,000) and `scan_timeout` (default 60s) caps exist as safety valves. Tune via environment variables:
```bash
export SYSGUARD_MAX_FILES=200000
export SYSGUARD_SCAN_TIMEOUT=300
```

### Export directory not writable
```bash
sudo bash run.sh scan --export-dir /tmp/my-reports
```

---

## Security Hardening Notes

1. **This tool reads `/etc/shadow`.** Treat any JSON/CSV export containing user account data as sensitive — exports do not include password hashes, but do include usernames, sudo status, and group membership, which is itself useful reconnaissance data for an attacker.

2. **Run scans from a trusted, patched host.** SysGuard parses sudoers files with a permissive line-based parser; it is read-only and does not modify any system file, but always review findings before acting on remediation suggestions.

3. **CIS Benchmark references are guidance, not guarantees.** Validate remediation steps in a staging environment before applying to production.

4. **Audit log retention**: configure `logrotate` for `/tmp/sysguard/logs/*.jsonl` in production, or redirect `SYSGUARD_LOG_DIR` to a persistent, access-controlled location.

5. **Filesystem scans can be I/O intensive.** On production systems, prefer scoped scans (`--scan-root /home`, `--scan-root /srv`) over full-root scans during business hours.

---

## Legal Disclaimer

> **This software is provided for educational, defensive security, and legitimate system administration purposes only.**
>
> SysGuard is a **read-only analysis tool** — it does not modify user accounts, passwords, permissions, or sudoers files. It only reads system files and reports findings.
>
> - The authors assume **no liability** for actions taken based on SysGuard's findings, including any remediation steps performed manually by the operator.
> - This tool must only be used by authorized personnel on systems they own or are explicitly authorized to audit.
> - Running this tool against systems without authorization may violate computer crime laws in your jurisdiction.
> - CIS Benchmark references are provided for context only and do not constitute a compliance certification.
> - Always verify findings independently before taking remediation action on production systems.

---

*SysGuard — Linux Security Audit & Account Intelligence CLI — v1.0.0*
