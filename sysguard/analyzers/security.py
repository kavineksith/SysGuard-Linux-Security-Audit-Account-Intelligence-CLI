"""
sysguard/analyzers/security.py
────────────────────────────────
Async security analysis engines.

Design:
  • Each analyzer is an async generator yielding SecurityFinding objects
  • File-system scan uses asyncio.gather() + semaphore for bounded parallelism
  • Memory-efficient: processes files in chunks, never loads full directory trees
"""
from __future__ import annotations

import asyncio
import os
import stat
import time
from pathlib import Path
from typing import AsyncIterator

from sysguard.core.config import SysGuardConfig
from sysguard.core.exceptions import ScanError, ErrorCode
from sysguard.core.logger import get_logger
from sysguard.models.accounts import (
    AccountStatus, FindingCategory, RiskLevel, SecurityFinding,
    SudoersRule, UserAccount,
)

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# User & password policy analyzer
# ─────────────────────────────────────────────────────────────

async def analyze_user_policy(
    user: UserAccount,
    cfg: SysGuardConfig,
    valid_shells: frozenset[str],
) -> AsyncIterator[SecurityFinding]:
    """
    Async generator: yields SecurityFinding objects for a single user.
    """
    await asyncio.sleep(0)  # yield control

    today_days = int(time.time() / 86400)

    # ── 1. Locked but has login shell ─────────────────────────
    if user.status == AccountStatus.LOCKED and user.shell not in (
        "/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
    ):
        yield SecurityFinding(
            category=FindingCategory.ACCOUNT_STATUS,
            risk=RiskLevel.MEDIUM,
            title="Locked account with login shell",
            detail=f"Account is locked but shell is {user.shell!r}",
            target=user.username,
            remediation=f"sudo usermod -s /usr/sbin/nologin {user.username}",
        )

    # ── 2. Shell not in /etc/shells ───────────────────────────
    if (not user.is_system
            and user.shell not in valid_shells
            and user.shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")):
        yield SecurityFinding(
            category=FindingCategory.SHELL_POLICY,
            risk=RiskLevel.LOW,
            title="Shell not listed in /etc/shells",
            detail=f"Shell {user.shell!r} is not in /etc/shells",
            target=user.username,
            remediation="Add the shell to /etc/shells or change it to a valid shell",
        )

    # ── 3. Password never set / empty ─────────────────────────
    if user.password_hash in ("", "!!", "*"):
        if not user.is_system:
            yield SecurityFinding(
                category=FindingCategory.PASSWORD_POLICY,
                risk=RiskLevel.HIGH,
                title="Account has no password set",
                detail="Password hash is empty or unset — account may be accessible without authentication",
                target=user.username,
                remediation=f"sudo passwd {user.username}  # or lock: sudo passwd -l {user.username}",
                reference="CIS Benchmark L1: 5.4.1",
            )

    # ── 4. Password age exceeds max ───────────────────────────
    if user.last_changed and user.max_age < 99999:
        age = today_days - user.last_changed
        if age > user.max_age:
            yield SecurityFinding(
                category=FindingCategory.PASSWORD_POLICY,
                risk=RiskLevel.MEDIUM,
                title="Password expired",
                detail=f"Password is {age} days old (max: {user.max_age})",
                target=user.username,
                remediation=f"sudo chage --lastday 0 {user.username}  # force change on next login",
                reference="CIS Benchmark L1: 5.4.1.1",
            )

    # ── 5. No password max age configured ────────────────────
    if user.max_age >= 99999 and not user.is_system and user.status == AccountStatus.ACTIVE:
        yield SecurityFinding(
            category=FindingCategory.PASSWORD_POLICY,
            risk=RiskLevel.LOW,
            title="No password max age set",
            detail="Password never expires — user can keep the same password indefinitely",
            target=user.username,
            remediation=f"sudo chage --maxdays {cfg.pass_max_age} {user.username}",
            reference="CIS Benchmark L1: 5.4.1.1",
        )

    # ── 6. Warn days not configured ──────────────────────────
    if user.warn_days <= 0 and not user.is_system:
        yield SecurityFinding(
            category=FindingCategory.PASSWORD_POLICY,
            risk=RiskLevel.LOW,
            title="No password expiry warning days",
            detail="Users will not be warned before their password expires",
            target=user.username,
            remediation=f"sudo chage --warndays 7 {user.username}",
        )

    # ── 7. Sudo + no password ─────────────────────────────────
    if user.sudo_access and user.password_hash in ("", "!!", "*"):
        yield SecurityFinding(
            category=FindingCategory.SUDOERS,
            risk=RiskLevel.CRITICAL,
            title="Sudo user with no password",
            detail="Account has sudo access but no password is set",
            target=user.username,
            remediation=f"sudo passwd {user.username}  # set a strong password",
            reference="CIS Benchmark L1: 5.4",
        )

    # ── 8. Home directory missing ─────────────────────────────
    if (not user.is_system
            and user.status == AccountStatus.ACTIVE
            and user.home not in ("/", "/dev/null")
            and not Path(user.home).exists()):
        yield SecurityFinding(
            category=FindingCategory.HOME_DIRECTORY,
            risk=RiskLevel.MEDIUM,
            title="Home directory does not exist",
            detail=f"Configured home {user.home!r} is missing",
            target=user.username,
            remediation=f"sudo mkdir -p {user.home} && sudo chown {user.username}:{user.username} {user.home}",
        )

    # ── 9. Weak home dir permissions ─────────────────────────
    home = Path(user.home)
    if home.exists() and not user.is_system:
        try:
            mode = home.stat().st_mode
            if mode & stat.S_IWGRP or mode & stat.S_IWOTH:
                yield SecurityFinding(
                    category=FindingCategory.HOME_DIRECTORY,
                    risk=RiskLevel.HIGH,
                    title="Home directory is group/world writable",
                    detail=f"Permissions: {oct(mode & 0o777)} — {home}",
                    target=str(home),
                    remediation=f"sudo chmod 700 {home}",
                    reference="CIS Benchmark L1: 6.2.7",
                )
        except OSError:
            pass


async def analyze_all_users(
    users: list[UserAccount],
    cfg: SysGuardConfig,
    valid_shells: frozenset[str],
) -> AsyncIterator[SecurityFinding]:
    """
    Async generator: run user policy analysis for all users concurrently,
    bounded by a semaphore. Yields findings as they arrive.
    """
    sem = asyncio.Semaphore(cfg.max_workers)

    async def _bounded(user: UserAccount) -> list[SecurityFinding]:
        async with sem:
            results: list[SecurityFinding] = []
            async for finding in analyze_user_policy(user, cfg, valid_shells):
                results.append(finding)
            return results

    tasks = [asyncio.create_task(_bounded(u)) for u in users]
    for coro in asyncio.as_completed(tasks):
        findings = await coro
        for f in findings:
            yield f


# ─────────────────────────────────────────────────────────────
# Sudoers analyzer
# ─────────────────────────────────────────────────────────────

async def analyze_sudoers(
    rules: list[SudoersRule],
) -> AsyncIterator[SecurityFinding]:
    """Async generator: yield findings for dangerous sudoers rules."""
    for rule in rules:
        await asyncio.sleep(0)

        if rule.risk == RiskLevel.CRITICAL:
            yield SecurityFinding(
                category=FindingCategory.SUDOERS,
                risk=RiskLevel.CRITICAL,
                title="NOPASSWD ALL sudo rule",
                detail=f"Subject {rule.subject!r} can run ALL commands as root without password",
                target=rule.subject,
                remediation="Remove NOPASSWD: ALL and require password for sudo",
                reference="CIS Benchmark L1: 5.3",
                extra={"rule": rule.raw, "source": rule.source_file},
            )
        elif rule.risk == RiskLevel.HIGH:
            yield SecurityFinding(
                category=FindingCategory.SUDOERS,
                risk=RiskLevel.HIGH,
                title="Unrestricted sudo access",
                detail=f"Subject {rule.subject!r} has sudo ALL or dangerous command access",
                target=rule.subject,
                remediation="Restrict commands to only what is required (principle of least privilege)",
                extra={"rule": rule.raw, "source": rule.source_file},
            )
        elif rule.risk == RiskLevel.MEDIUM:
            yield SecurityFinding(
                category=FindingCategory.SUDOERS,
                risk=RiskLevel.MEDIUM,
                title="NOPASSWD sudo rule",
                detail=f"Subject {rule.subject!r} can run commands without password: {rule.commands}",
                target=rule.subject,
                remediation="Add password requirement: remove NOPASSWD tag",
                extra={"rule": rule.raw, "commands": rule.commands},
            )


# ─────────────────────────────────────────────────────────────
# File permission scanner
# ─────────────────────────────────────────────────────────────

async def _stat_file(path: str) -> os.stat_result | None:
    try:
        return await asyncio.to_thread(os.lstat, path)
    except OSError:
        return None


async def scan_filesystem(
    root: Path,
    cfg: SysGuardConfig,
    known_uids: frozenset[int],
) -> AsyncIterator[SecurityFinding]:
    """
    Async generator: walk the filesystem and yield SecurityFinding objects
    for world-writable files, SUID/SGID binaries, and unowned files.

    Uses os.scandir() in a thread pool for non-blocking I/O.
    Bounded by a semaphore to limit concurrent stat() calls.
    """
    sem = asyncio.Semaphore(cfg.max_workers * 2)
    skip_paths = frozenset(cfg.skip_paths)
    scanned = 0
    start = time.monotonic()

    async def _process_entry(entry_path: str, entry_stat: os.stat_result) -> list[SecurityFinding]:
        local_findings: list[SecurityFinding] = []
        mode = entry_stat.st_mode
        uid = entry_stat.st_uid
        octal = oct(mode & 0o7777)

        # World-writable (skip symlinks and /tmp)
        if (not stat.S_ISLNK(mode)
                and (mode & stat.S_IWOTH)
                and "/tmp" not in entry_path
                and "/var/tmp" not in entry_path):
            local_findings.append(SecurityFinding(
                category=FindingCategory.WORLD_WRITABLE,
                risk=RiskLevel.HIGH,
                title="World-writable file/directory",
                detail=f"Mode {octal} — any user can write to this",
                target=entry_path,
                remediation=f"chmod o-w {entry_path!r}",
                reference="CIS Benchmark L1: 6.1.2",
            ))

        # SUID
        if stat.S_ISREG(mode) and (mode & stat.S_ISUID):
            risk = RiskLevel.MEDIUM if "/usr/bin" in entry_path else RiskLevel.HIGH
            local_findings.append(SecurityFinding(
                category=FindingCategory.SUID_SGID,
                risk=risk,
                title="SUID bit set",
                detail=f"File mode {octal} — executes as file owner (potential privilege escalation)",
                target=entry_path,
                remediation=f"chmod u-s {entry_path!r}  # if SUID is not required",
                reference="CIS Benchmark L1: 6.1.13",
            ))

        # SGID
        if stat.S_ISREG(mode) and (mode & stat.S_ISGID):
            local_findings.append(SecurityFinding(
                category=FindingCategory.SUID_SGID,
                risk=RiskLevel.LOW,
                title="SGID bit set",
                detail=f"File mode {octal} — executes as file group",
                target=entry_path,
                remediation=f"chmod g-s {entry_path!r}  # if SGID is not required",
            ))

        # Unowned file
        if uid not in known_uids:
            local_findings.append(SecurityFinding(
                category=FindingCategory.UNOWNED_FILE,
                risk=RiskLevel.MEDIUM,
                title="File owned by non-existent UID",
                detail=f"UID {uid} has no corresponding account",
                target=entry_path,
                remediation=f"chown <appropriate_user> {entry_path!r}  # or remove the file",
                reference="CIS Benchmark L1: 6.1.11",
            ))

        return local_findings

    # ── Directory walker ──────────────────────────────────────
    queue: asyncio.Queue[str] = asyncio.Queue()
    await queue.put(str(root))
    pending_tasks: list[asyncio.Task] = []

    while not queue.empty() or pending_tasks:
        # Check timeout
        if time.monotonic() - start > cfg.scan_timeout:
            log.warning("Filesystem scan timed out at %d files", scanned)
            raise ScanError(
                message=f"Scan timed out after {cfg.scan_timeout}s",
                code=ErrorCode.SCAN_TIMEOUT,
                scan_target=str(root),
                scanned=scanned,
            )

        # Drain completed tasks
        done: list[asyncio.Task] = []
        still: list[asyncio.Task] = []
        for t in pending_tasks:
            if t.done():
                done.append(t)
            else:
                still.append(t)
        pending_tasks = still

        for t in done:
            try:
                for f in t.result():
                    yield f
            except Exception as exc:
                log.debug("Scan task error: %s", exc)

        # Process next directory
        if not queue.empty():
            dirpath = await queue.get()

            # Skip excluded paths
            if any(dirpath.startswith(skip) for skip in skip_paths):
                continue

            try:
                entries = await asyncio.to_thread(list, os.scandir(dirpath))
            except OSError:
                continue

            for entry in entries:
                scanned += 1
                if scanned > cfg.max_files:
                    log.warning("Max file limit (%d) reached", cfg.max_files)
                    return

                if entry.is_dir(follow_symlinks=False):
                    await queue.put(entry.path)
                    continue

                async def _task(path: str = entry.path) -> list[SecurityFinding]:
                    async with sem:
                        st = await _stat_file(path)
                        if st is None:
                            return []
                        return await _process_entry(path, st)

                pending_tasks.append(asyncio.create_task(_task()))

        else:
            if pending_tasks:
                await asyncio.sleep(0.01)

    # Final drain
    for t in pending_tasks:
        try:
            results = await t
            for f in results:
                yield f
        except Exception:
            pass

    log.info("Filesystem scan complete: %d files scanned", scanned)


# ─────────────────────────────────────────────────────────────
# Group membership analyzer
# ─────────────────────────────────────────────────────────────

_SENSITIVE_GROUPS = frozenset({
    "sudo", "wheel", "root", "shadow", "adm", "admin",
    "docker", "disk", "video", "audio",
})


async def analyze_group_memberships(
    users: list[UserAccount],
) -> AsyncIterator[SecurityFinding]:
    """Yield findings for suspicious group memberships."""
    for user in users:
        await asyncio.sleep(0)
        if user.is_system:
            continue
        for group in user.supplementary_groups:
            if group in _SENSITIVE_GROUPS:
                risk = RiskLevel.HIGH if group in ("sudo", "wheel", "shadow", "docker") else RiskLevel.MEDIUM
                yield SecurityFinding(
                    category=FindingCategory.GROUP_MEMBERSHIP,
                    risk=risk,
                    title=f"User in sensitive group: {group!r}",
                    detail=f"{user.username} is a member of privileged group {group!r}",
                    target=user.username,
                    remediation=f"Review if {user.username} requires {group!r} access; "
                                f"remove with: sudo gpasswd -d {user.username} {group}",
                    extra={"group": group},
                )
