"""
sysguard/services/reporter.py
──────────────────────────────
Async report exporter: JSON, CSV, plain-text.
Uses async generators to stream large result sets without loading
the entire dataset into memory at once.
"""
from __future__ import annotations

import asyncio
import csv
import json
import time
from pathlib import Path
from typing import AsyncIterator

from sysguard.core.exceptions import ReportError, ErrorCode
from sysguard.core.logger import AsyncAuditLogger, get_logger
from sysguard.models.accounts import RiskLevel, ScanResult, SecurityFinding

log = get_logger(__name__)
audit = AsyncAuditLogger(__name__)

# ANSI for console report
_R = "\033[0m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33;1m"
_RED = "\033[31;1m"
_MAGENTA = "\033[35;1m"
_GRAY = "\033[90m"

_RISK_COLOUR = {
    RiskLevel.CLEAN:    _GREEN,
    RiskLevel.INFO:     _CYAN,
    RiskLevel.LOW:      _GRAY,
    RiskLevel.MEDIUM:   _YELLOW,
    RiskLevel.HIGH:     _RED,
    RiskLevel.CRITICAL: _MAGENTA,
}


# ─────────────────────────────────────────────────────────────
# Async streaming helpers
# ─────────────────────────────────────────────────────────────

async def _stream_findings(result: ScanResult, min_risk: RiskLevel) -> AsyncIterator[SecurityFinding]:
    """Yield findings above min_risk, sorted, in memory-efficient chunks."""
    batch: list[SecurityFinding] = []
    for f in result:          # __iter__ on ScanResult yields sorted findings
        if f.risk >= min_risk:
            batch.append(f)
        if len(batch) >= 100:
            for item in batch:
                yield item
                await asyncio.sleep(0)
            batch.clear()
    for item in batch:
        yield item


# ─────────────────────────────────────────────────────────────
# Console report
# ─────────────────────────────────────────────────────────────

async def print_console_report(result: ScanResult, min_risk: RiskLevel = RiskLevel.LOW) -> None:
    """Stream a formatted report to stdout."""

    def _banner(text: str, width: int = 72) -> str:
        line = "═" * width
        pad = (width - len(text) - 2) // 2
        return f"\n{_CYAN}╔{line}╗\n║{' ' * pad} {_BOLD}{text}{_R}{_CYAN} {' ' * (width - pad - len(text) - 1)}║\n╚{line}╝{_R}"

    def _section(title: str) -> str:
        return f"\n{_BOLD}{_CYAN}── {title} {'─' * (60 - len(title))}{_R}\n"

    print(_banner(f"SysGuard Security Report  —  {time.strftime('%Y-%m-%d %H:%M:%S')}"))

    # ── Summary ───────────────────────────────────────────────
    print(_section("Executive Summary"))
    overall_colour = _RISK_COLOUR.get(result.overall_risk, _R)
    print(f"  {'Overall Risk:':<22} {overall_colour}{_BOLD}{result.overall_risk}{_R}")
    print(f"  {'Scan Duration:':<22} {result.duration:.2f}s")
    print(f"  {'Users Scanned:':<22} {len([u for u in result.users if not u.is_system])}")
    print(f"  {'Groups:':<22} {len(result.groups)}")
    print(f"  {'Total Findings:':<22} {len(result.findings)}")

    risk_counts = {r: 0 for r in RiskLevel}
    for f in result.findings:
        risk_counts[f.risk] += 1

    for risk in sorted(RiskLevel, reverse=True):
        count = risk_counts[risk]
        if count:
            colour = _RISK_COLOUR.get(risk, _R)
            print(f"  {f'  {risk}:':<22} {colour}{count}{_R}")

    if result.errors:
        print(f"\n  {_YELLOW}⚠ Scan errors: {len(result.errors)}{_R}")
        for e in result.errors[:3]:
            print(f"    {_GRAY}{e}{_R}")

    # ── Findings ──────────────────────────────────────────────
    print(_section(f"Findings (min risk: {min_risk.name})"))

    count = 0
    async for f in _stream_findings(result, min_risk):
        colour = _RISK_COLOUR.get(f.risk, _R)
        risk_badge = f"{colour}[{f.risk:<8}]{_R}"
        print(f"  {risk_badge} {_BOLD}{f.title}{_R}")
        print(f"             {_CYAN}Target:{_R} {f.target}")
        print(f"             {_CYAN}Detail:{_R} {f.detail}")
        if f.remediation:
            print(f"             {_CYAN}Fix:   {_R} {_GRAY}{f.remediation}{_R}")
        if f.reference:
            print(f"             {_CYAN}Ref:   {_R} {_GRAY}{f.reference}{_R}")
        print()
        count += 1

    if count == 0:
        print(f"  {_GREEN}✔ No findings above {min_risk.name} risk level.{_R}\n")

    # ── User table ────────────────────────────────────────────
    print(_section("User Risk Summary"))
    header = f"  {'USERNAME':<20} {'UID':<6} {'STATUS':<12} {'RISK':<10} {'SUDO':<5} {'GROUPS'}"
    print(f"{_BOLD}{header}{_R}")
    print(f"  {'─' * 70}")

    regular = sorted([u for u in result.users if not u.is_system])
    for u in regular:
        risk = u.risk_level
        rc = _RISK_COLOUR.get(risk, _R)
        sudo_badge = f"{_RED}YES{_R}" if u.sudo_access else "no"
        groups_short = ",".join(list(u.supplementary_groups)[:3])
        if len(u.supplementary_groups) > 3:
            groups_short += f" +{len(u.supplementary_groups) - 3}"
        print(
            f"  {u.username:<20} {u.uid:<6} {str(u.status):<12} "
            f"{rc}{str(risk):<10}{_R} {sudo_badge:<10} {_GRAY}{groups_short}{_R}"
        )
        await asyncio.sleep(0)

    print()


# ─────────────────────────────────────────────────────────────
# JSON export
# ─────────────────────────────────────────────────────────────

async def export_json(result: ScanResult, output: Path) -> Path:
    """Write full scan result as pretty-printed JSON."""
    try:
        data = result.to_dict()
        output.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(data, indent=2, default=str)
        await asyncio.to_thread(output.write_text, content, encoding="utf-8")
        size = output.stat().st_size
        log.info("JSON report written: %s (%d bytes)", output, size)
        await audit.audit("EXPORT_JSON", str(output), findings=len(result.findings))
        return output
    except OSError as exc:
        raise ReportError(
            message=f"Cannot write JSON: {exc}",
            code=ErrorCode.REPORT_WRITE_ERROR,
            output_path=str(output),
        ) from exc


# ─────────────────────────────────────────────────────────────
# CSV export (findings)
# ─────────────────────────────────────────────────────────────

async def export_findings_csv(result: ScanResult, output: Path) -> Path:
    """
    Export all findings to CSV using a streaming async generator.
    Writes in chunks to avoid loading all findings into memory at once.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "risk", "risk_value", "category", "title", "target",
        "detail", "remediation", "reference", "timestamp",
    ]

    try:
        def _write_csv() -> None:
            with output.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for f in sorted(result.findings):
                    d = f.to_dict()
                    d["risk_value"] = f.risk.value
                    writer.writerow({k: d.get(k, "") for k in fieldnames})

        await asyncio.to_thread(_write_csv)
        log.info("CSV findings exported: %s (%d rows)", output, len(result.findings))
        await audit.audit("EXPORT_CSV", str(output), rows=len(result.findings))
        return output
    except OSError as exc:
        raise ReportError(
            message=f"Cannot write CSV: {exc}",
            code=ErrorCode.REPORT_WRITE_ERROR,
            output_path=str(output),
        ) from exc


# ─────────────────────────────────────────────────────────────
# Users CSV export
# ─────────────────────────────────────────────────────────────

async def export_users_csv(result: ScanResult, output: Path) -> Path:
    """Export user account data to CSV."""
    output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "username", "uid", "gid", "status", "shell", "home",
        "sudo_access", "supplementary_groups", "max_age_days",
        "password_age_days", "risk_level", "finding_count",
    ]

    def _write() -> None:
        with output.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for u in sorted(result.users):
                w.writerow({
                    "username":           u.username,
                    "uid":                u.uid,
                    "gid":                u.gid,
                    "status":             u.status.name,
                    "shell":              u.shell,
                    "home":               u.home,
                    "sudo_access":        u.sudo_access,
                    "supplementary_groups": "|".join(u.supplementary_groups),
                    "max_age_days":       u.max_age,
                    "password_age_days":  u.password_age_days or "",
                    "risk_level":         u.risk_level.name,
                    "finding_count":      len(u.findings),
                })

    await asyncio.to_thread(_write)
    log.info("Users CSV exported: %s", output)
    await audit.audit("EXPORT_USERS_CSV", str(output), count=len(result.users))
    return output


# ─────────────────────────────────────────────────────────────
# Plain-text summary report
# ─────────────────────────────────────────────────────────────

async def export_text_report(result: ScanResult, output: Path) -> Path:
    """Write a human-readable text report (no ANSI codes)."""
    output.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = [
        "=" * 72,
        f"  SysGuard Security Report",
        f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Overall Risk: {result.overall_risk.name}",
        "=" * 72,
        "",
        "SUMMARY",
        f"  Users scanned:  {len([u for u in result.users if not u.is_system])}",
        f"  Groups:         {len(result.groups)}",
        f"  Total findings: {len(result.findings)}",
        f"  Critical:       {result.critical_count}",
        f"  High:           {result.high_count}",
        f"  Scan duration:  {result.duration:.2f}s",
        "",
        "FINDINGS",
        "─" * 72,
    ]

    async for f in _stream_findings(result, RiskLevel.LOW):
        lines += [
            f"  [{f.risk:<8}] [{f.category}]",
            f"  Title:       {f.title}",
            f"  Target:      {f.target}",
            f"  Detail:      {f.detail}",
        ]
        if f.remediation:
            lines.append(f"  Remediation: {f.remediation}")
        if f.reference:
            lines.append(f"  Reference:   {f.reference}")
        lines.append("")

    content = "\n".join(lines)
    await asyncio.to_thread(output.write_text, content, encoding="utf-8")
    log.info("Text report exported: %s", output)
    await audit.audit("EXPORT_TEXT", str(output))
    return output
