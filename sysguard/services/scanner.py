"""
sysguard/services/scanner.py
─────────────────────────────
Orchestrates all async analyzers in parallel.
Builds the final ScanResult by collecting from async generators
and asyncio.gather() for maximum throughput.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from typing import Any

from sysguard.analyzers.security import (
    analyze_all_users, analyze_group_memberships,
    analyze_sudoers, scan_filesystem,
)
from sysguard.core.config import SysGuardConfig
from sysguard.core.exceptions import ScanError, SysGuardErrorGroup, Severity
from sysguard.core.logger import AsyncAuditLogger, get_logger
from sysguard.models.accounts import (
    GroupInfo, SecurityFinding, SudoersRule, UserAccount, ScanResult
)
from sysguard.services.parsers import (
    parse_group, parse_passwd, parse_shadow,
    parse_sudoers, parse_valid_shells,
)

log = get_logger(__name__)
audit = AsyncAuditLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Data loading phase (read system files)
# ─────────────────────────────────────────────────────────────

async def _load_users(cfg: SysGuardConfig) -> list[UserAccount]:
    """Load and merge /etc/passwd + /etc/shadow into UserAccount list."""
    users: dict[str, UserAccount] = {}

    # passwd
    async for user in parse_passwd(cfg.passwd_file):
        users[user.username] = user

    # shadow (enrich users, skip if not readable)
    shadow_data: dict[str, dict] = {}
    try:
        async for record in parse_shadow(cfg.shadow_file):
            shadow_data[record["username"]] = record
    except Exception as exc:
        log.warning("Shadow file not readable: %s", exc)

    for username, shadow in shadow_data.items():
        if username in users:
            u = users[username]
            u.password_hash  = shadow["hash"]
            u.status         = shadow["status"] if shadow["status"].name == "LOCKED" else u.status
            u.last_changed   = shadow["last_changed"]
            u.min_age        = shadow["min_age"]
            u.max_age        = shadow["max_age"]
            u.warn_days      = shadow["warn_days"]
            u.inactive_days  = shadow["inactive_days"]
            u.expire_date    = shadow["expire_date"]

    return list(users.values())


async def _load_groups(cfg: SysGuardConfig) -> list[GroupInfo]:
    groups: list[GroupInfo] = []
    async for g in parse_group(cfg.group_file):
        groups.append(g)
    return groups


async def _enrich_sudo_membership(
    users: list[UserAccount],
    groups: list[GroupInfo],
) -> None:
    """Mark users who belong to sudo/wheel as having sudo access."""
    sudo_groups = {"sudo", "wheel", "admin"}
    sudo_members: set[str] = set()

    for g in groups:
        if g.name in sudo_groups:
            sudo_members.update(g.members)

    for u in users:
        u.sudo_access = u.username in sudo_members
        # Populate supplementary groups
        u.supplementary_groups = [
            g.name for g in groups if u.username in g.members
        ]

    await asyncio.sleep(0)


async def _load_sudoers(cfg: SysGuardConfig) -> list[SudoersRule]:
    rules: list[SudoersRule] = []
    try:
        async for rule in parse_sudoers(cfg.sudoers_file, cfg.sudoers_dir):
            rules.append(rule)
    except Exception as exc:
        log.warning("Sudoers parse issue: %s", exc)
    return rules


# ─────────────────────────────────────────────────────────────
# Main scan orchestrator
# ─────────────────────────────────────────────────────────────

async def run_scan(
    cfg: SysGuardConfig,
    scan_filesystem_flag: bool = False,
    scan_root: Path = Path("/"),
    progress_cb: Any = None,         # optional callback(step: str, pct: int)
) -> ScanResult:
    """
    Full async scan. Steps run in parallel where possible:
      1. Load system files (passwd, shadow, group, sudoers, shells) — sequential (I/O bound)
      2. Enrich user objects
      3. Analyze all users in parallel (bounded semaphore)
      4. Analyze sudoers rules
      5. Analyze group memberships
      6. (Optional) Scan filesystem for permission issues

    Returns a ScanResult with all findings.
    """
    start = time.monotonic()
    errors: list[str] = []
    all_findings: list[SecurityFinding] = []

    def _progress(step: str, pct: int) -> None:
        if progress_cb:
            progress_cb(step, pct)
        log.debug("Scan progress [%d%%]: %s", pct, step)

    await audit.audit("SCAN_START", "system",
                       filesystem=str(scan_filesystem_flag),
                       root=str(scan_root))

    # ── Phase 1: load data (I/O — run concurrently) ───────────
    _progress("Loading system files", 5)
    try:
        users, groups, sudoers, valid_shells = await asyncio.gather(
            _load_users(cfg),
            _load_groups(cfg),
            _load_sudoers(cfg),
            parse_valid_shells(cfg.shells_file),
        )
    except Exception as exc:
        raise ScanError(
            message=f"Failed to load system files: {exc}",
            code=ScanError.__dataclass_fields__["code"].default,
        ) from exc

    log.info("Loaded: %d users, %d groups, %d sudoers rules", len(users), len(groups), len(sudoers))
    _progress("Enriching user data", 20)

    # ── Phase 2: enrich ───────────────────────────────────────
    await _enrich_sudo_membership(users, groups)

    # Filter to regular users for analysis
    regular_users = [u for u in users if cfg.min_uid <= u.uid <= cfg.max_uid]
    log.info("Analyzing %d regular users", len(regular_users))

    # ── Phase 3: parallel analysis ────────────────────────────
    _progress("Analyzing user policies", 35)

    async def _collect_async_gen(agen) -> list[SecurityFinding]:
        """Drain an async generator into a list."""
        results = []
        async for item in agen:
            results.append(item)
        return results

    # Run user analysis + sudoers analysis + group analysis concurrently
    user_findings_task = asyncio.create_task(
        _collect_async_gen(analyze_all_users(regular_users, cfg, valid_shells))
    )
    sudoers_findings_task = asyncio.create_task(
        _collect_async_gen(analyze_sudoers(sudoers))
    )
    group_findings_task = asyncio.create_task(
        _collect_async_gen(analyze_group_memberships(regular_users))
    )

    _progress("Running policy analyzers", 50)

    gathered = await asyncio.gather(
        user_findings_task,
        sudoers_findings_task,
        group_findings_task,
        return_exceptions=True,
    )

    for result in gathered:
        if isinstance(result, BaseException):
            errors.append(str(result))
            log.error("Analyzer error: %s", result)
        else:
            all_findings.extend(result)

    _progress("Analysis complete", 70)

    # ── Phase 4: optional filesystem scan ─────────────────────
    if scan_filesystem_flag:
        _progress(f"Scanning filesystem: {scan_root}", 75)
        known_uids = frozenset(u.uid for u in users)
        try:
            async for finding in scan_filesystem(scan_root, cfg, known_uids):
                all_findings.append(finding)
        except ScanError as exc:
            errors.append(str(exc))
            log.warning("Filesystem scan incomplete: %s", exc)
        except Exception as exc:
            errors.append(str(exc))
            log.error("Filesystem scan failed: %s", exc)

    _progress("Building report", 95)

    duration = time.monotonic() - start
    result = ScanResult(
        users=users,
        groups=groups,
        findings=all_findings,
        sudoers=sudoers,
        scan_time=time.time(),
        duration=duration,
        errors=errors,
    )

    await audit.audit(
        "SCAN_COMPLETE", "system",
        users=len(users),
        findings=len(all_findings),
        critical=result.critical_count,
        duration=f"{duration:.2f}s",
        errors=len(errors),
    )

    _progress("Done", 100)
    log.info("Scan complete in %.2fs — %d findings (%d critical)",
             duration, len(all_findings), result.critical_count)
    return result
