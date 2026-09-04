"""
sysguard/services/parsers.py
─────────────────────────────
Async generators that parse Linux system files lazily,
yielding one record at a time for memory-efficient processing.
"""
from __future__ import annotations

import asyncio
import os
import pwd
import grp
from pathlib import Path
from typing import AsyncIterator

from sysguard.core.exceptions import ParseError, SystemAccessError, ErrorCode
from sysguard.core.logger import get_logger
from sysguard.models.accounts import (
    AccountStatus, GroupInfo, SudoersRule, UserAccount, RiskLevel
)

log = get_logger(__name__)


# ─────────────────────────────────────────────────────────────
# Low-level async line reader (yields lines, non-blocking)
# ─────────────────────────────────────────────────────────────

async def _read_lines(path: Path, encoding: str = "utf-8") -> AsyncIterator[tuple[int, str]]:
    """
    Async generator: yields (line_number, stripped_line) from a file.
    Reads synchronously but yields control every 100 lines so the event
    loop stays responsive during large file reads.
    """
    if not path.exists():
        raise ParseError(
            message=f"File not found: {path}",
            code=ErrorCode.FILE_NOT_FOUND,
            line_number=0,
        )
    if not os.access(str(path), os.R_OK):
        raise SystemAccessError(
            message=f"Cannot read {path} — permission denied",
            context={"path": str(path)},
        )
    try:
        with path.open(encoding=encoding, errors="replace") as fh:
            for lineno, raw in enumerate(fh, start=1):
                if lineno % 100 == 0:
                    await asyncio.sleep(0)   # yield control
                line = raw.strip()
                if line:
                    yield lineno, line
    except OSError as exc:
        raise SystemAccessError(
            message=f"Cannot read {path}: {exc}",
            context={"path": str(path), "error": str(exc)},
        ) from exc


# ─────────────────────────────────────────────────────────────
# /etc/passwd parser
# ─────────────────────────────────────────────────────────────

async def parse_passwd(path: Path) -> AsyncIterator[UserAccount]:
    """
    Async generator: yields UserAccount objects from /etc/passwd.
    Uses the OS pwd module for correctness, then yields one at a time.
    """
    try:
        entries = await asyncio.to_thread(pwd.getpwall)
    except Exception as exc:
        raise ParseError(
            message=f"pwd.getpwall failed: {exc}",
            code=ErrorCode.PARSE_ERROR,
        ) from exc

    for i, entry in enumerate(entries):
        if i % 50 == 0:
            await asyncio.sleep(0)

        shell = entry.pw_shell or "/bin/sh"
        # Determine status from shell
        status = AccountStatus.SYSTEM if entry.pw_uid < 1000 else AccountStatus.ACTIVE
        if shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/dev/null"):
            status = AccountStatus.NO_LOGIN if entry.pw_uid >= 1000 else AccountStatus.SYSTEM

        yield UserAccount(
            username=entry.pw_name,
            uid=entry.pw_uid,
            gid=entry.pw_gid,
            comment=entry.pw_gecos,
            home=entry.pw_dir,
            shell=shell,
            status=status,
        )


# ─────────────────────────────────────────────────────────────
# /etc/shadow parser
# ─────────────────────────────────────────────────────────────

async def parse_shadow(path: Path) -> AsyncIterator[dict]:
    """
    Async generator: yields shadow record dicts.
    Fields: username, hash, last_changed, min_age, max_age,
            warn_days, inactive_days, expire_date
    """
    try:
        async for lineno, line in _read_lines(path):
            parts = line.split(":")
            if len(parts) < 2:
                log.debug("shadow: skipping malformed line %d", lineno)
                continue

            def _int(v: str, default: int = 0) -> int:
                try:
                    return int(v) if v.strip() else default
                except ValueError:
                    return default

            pw_hash = parts[1] if len(parts) > 1 else "x"
            status = AccountStatus.ACTIVE
            if pw_hash.startswith("!") or pw_hash.startswith("*"):
                status = AccountStatus.LOCKED
            elif pw_hash == "":
                status = AccountStatus.ACTIVE  # empty = no password (unsafe)

            yield {
                "username":     parts[0],
                "hash":         pw_hash,
                "status":       status,
                "last_changed": _int(parts[2] if len(parts) > 2 else ""),
                "min_age":      _int(parts[3] if len(parts) > 3 else ""),
                "max_age":      _int(parts[4] if len(parts) > 4 else "", default=99999),
                "warn_days":    _int(parts[5] if len(parts) > 5 else "", default=7),
                "inactive_days": _int(parts[6] if len(parts) > 6 else "", default=-1),
                "expire_date":  _int(parts[7] if len(parts) > 7 else "", default=-1),
            }
    except SystemAccessError:
        log.warning("Cannot read shadow file — running without root? Shadow checks skipped.")
        return


# ─────────────────────────────────────────────────────────────
# /etc/group parser
# ─────────────────────────────────────────────────────────────

async def parse_group(path: Path) -> AsyncIterator[GroupInfo]:
    """Async generator: yields GroupInfo objects from /etc/group."""
    try:
        entries = await asyncio.to_thread(grp.getgrall)
    except Exception as exc:
        raise ParseError(
            message=f"grp.getgrall failed: {exc}",
            code=ErrorCode.PARSE_ERROR,
        ) from exc

    for i, entry in enumerate(entries):
        if i % 50 == 0:
            await asyncio.sleep(0)
        yield GroupInfo(
            name=entry.gr_name,
            gid=entry.gr_gid,
            members=list(entry.gr_mem),
        )


# ─────────────────────────────────────────────────────────────
# /etc/sudoers + /etc/sudoers.d parser
# ─────────────────────────────────────────────────────────────

_DANGEROUS_CMDS = frozenset({
    "ALL", "/bin/bash", "/bin/sh", "/usr/bin/python",
    "/usr/bin/python3", "/bin/vi", "/bin/vim", "/bin/nano",
    "/usr/bin/less", "/bin/more", "/usr/bin/find",
    "/usr/bin/tee", "/usr/bin/awk", "/usr/bin/perl",
})
_DANGEROUS_PATTERNS = ["(ALL)", "NOPASSWD: ALL", "/bin/*", "/usr/bin/*"]


def _assess_rule_risk(rule: SudoersRule) -> RiskLevel:
    if "ALL" in rule.commands and rule.nopasswd:
        return RiskLevel.CRITICAL
    if "ALL" in rule.commands:
        return RiskLevel.HIGH
    if rule.nopasswd and any(c in _DANGEROUS_CMDS for c in rule.commands):
        return RiskLevel.HIGH
    if rule.nopasswd:
        return RiskLevel.MEDIUM
    if any(c in _DANGEROUS_CMDS for c in rule.commands):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


async def _parse_sudoers_file(path: Path) -> AsyncIterator[SudoersRule]:
    """Yield parsed SudoersRule objects from a single sudoers file."""
    try:
        async for lineno, line in _read_lines(path):
            # Skip comments, Defaults, aliases
            if line.startswith(("#", "Defaults", "User_Alias", "Cmnd_Alias", "Host_Alias", "Runas_Alias")):
                continue
            if "=" not in line:
                continue

            try:
                # Format: subject hosts = (runas) [tags] commands
                subject, rest = line.split(None, 1)
                is_group = subject.startswith("%")

                # Split on '='
                host_part, cmd_part = rest.split("=", 1)
                hosts = host_part.strip()

                # Parse (runas) if present
                runas = "root"
                if cmd_part.strip().startswith("("):
                    end = cmd_part.index(")")
                    runas = cmd_part[1:end].strip()
                    cmd_part = cmd_part[end + 1:]

                # Tags
                tags: list[str] = []
                nopasswd = False
                for tag in ("NOPASSWD:", "PASSWD:", "NOEXEC:", "EXEC:", "SETENV:", "NOSETENV:"):
                    if tag in cmd_part:
                        tags.append(tag.rstrip(":"))
                        if tag == "NOPASSWD:":
                            nopasswd = True
                        cmd_part = cmd_part.replace(tag, "")

                commands = [c.strip() for c in cmd_part.split(",") if c.strip()]

                rule = SudoersRule(
                    source_file=str(path),
                    raw=line,
                    subject=subject,
                    hosts=hosts,
                    runas=runas,
                    tags=tags,
                    commands=commands,
                    is_group=is_group,
                    nopasswd=nopasswd,
                )
                rule.risk = _assess_rule_risk(rule)
                rule.is_dangerous = rule.risk >= RiskLevel.HIGH
                yield rule
            except (ValueError, IndexError):
                log.debug("sudoers: could not parse line %d in %s", lineno, path)
    except (SystemAccessError, ParseError) as exc:
        log.warning("Could not parse %s: %s", path, exc)
        return


async def parse_sudoers(sudoers_file: Path, sudoers_dir: Path) -> AsyncIterator[SudoersRule]:
    """
    Async generator: yields SudoersRule objects from /etc/sudoers
    and all files in /etc/sudoers.d/.
    """
    # Main file
    if sudoers_file.exists():
        async for rule in _parse_sudoers_file(sudoers_file):
            yield rule

    # Drop-ins
    if sudoers_dir.exists():
        try:
            dropin_files = sorted(sudoers_dir.iterdir())
        except PermissionError:
            log.warning("Cannot list %s — skipping drop-ins", sudoers_dir)
            return

        for dropin in dropin_files:
            if dropin.is_file() and not dropin.name.startswith("."):
                async for rule in _parse_sudoers_file(dropin):
                    yield rule
                await asyncio.sleep(0)


# ─────────────────────────────────────────────────────────────
# /etc/shells
# ─────────────────────────────────────────────────────────────

async def parse_valid_shells(path: Path) -> frozenset[str]:
    """Return frozenset of valid shells from /etc/shells."""
    shells: set[str] = set()
    try:
        async for _, line in _read_lines(path):
            if line.startswith("/"):
                shells.add(line)
    except (ParseError, SystemAccessError):
        # Fallback
        shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish",
                  "/usr/bin/zsh", "/usr/bin/fish"}
    return frozenset(shells)
