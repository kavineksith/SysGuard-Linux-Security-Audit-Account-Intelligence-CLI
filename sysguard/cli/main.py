"""
sysguard/cli/main.py
─────────────────────
CLI entrypoint — argparse-based args mode + interactive REPL.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

from sysguard.core.config import SysGuardConfig, get_config
from sysguard.core.exceptions import (
    RootRequiredError, ScanError, SysGuardError, Severity
)
from sysguard.core.logger import get_logger, setup_logging, shutdown_logging
from sysguard.models.accounts import RiskLevel
from sysguard.services.reporter import (
    export_findings_csv, export_json, export_text_report,
    export_users_csv, print_console_report,
)
from sysguard.services.scanner import run_scan

log = get_logger(__name__)

# ── ANSI ──────────────────────────────────────────────────────
_R     = "\033[0m"
_BOLD  = "\033[1m"
_CYAN  = "\033[36m"
_GREEN = "\033[32m"
_YELLOW= "\033[33;1m"
_RED   = "\033[31;1m"
_GRAY  = "\033[90m"
_MAG   = "\033[35;1m"


def _banner() -> None:
    print(f"""{_CYAN}{_BOLD}
  ███████╗██╗   ██╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔════╝╚██╗ ██╔╝██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ███████╗ ╚████╔╝ ███████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ╚════██║  ╚██╔╝  ╚════██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ███████║   ██║   ███████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
{_R}{_GRAY}  Linux Security Audit & Account Intelligence CLI  |  v1.0.0{_R}
""")


# ─────────────────────────────────────────────────────────────
# Progress callback for CLI
# ─────────────────────────────────────────────────────────────

class _ProgressPrinter:
    def __init__(self) -> None:
        self._last = ""
        self._start = time.monotonic()

    def __call__(self, step: str, pct: int) -> None:
        bar_w = 30
        filled = int(pct * bar_w / 100)
        bar = "█" * filled + "░" * (bar_w - filled)
        elapsed = time.monotonic() - self._start
        line = (f"\r  {_CYAN}[{bar}]{_R} {_BOLD}{pct:3d}%{_R}  "
                f"{_GRAY}{step:<40}{_R}  {elapsed:.1f}s")
        print(line, end="", flush=True)
        if pct >= 100:
            print()  # newline at completion


# ─────────────────────────────────────────────────────────────
# Async run helpers
# ─────────────────────────────────────────────────────────────

async def _run_scan_and_report(args: argparse.Namespace, cfg: SysGuardConfig) -> int:
    """Core async scan + report logic. Returns exit code."""
    progress = _ProgressPrinter()

    print(f"\n  {_CYAN}Starting scan...{_R}")
    result = await run_scan(
        cfg=cfg,
        scan_filesystem_flag=args.filesystem,
        scan_root=Path(args.scan_root),
        progress_cb=progress,
    )

    # Print console report
    min_risk = RiskLevel[args.min_risk.upper()]
    await print_console_report(result, min_risk=min_risk)

    # Exports
    ts = time.strftime("%Y%m%d_%H%M%S")
    exported: list[str] = []

    if args.json or args.all_formats:
        out = cfg.export_dir / f"sysguard_{ts}.json"
        await export_json(result, out)
        exported.append(str(out))

    if args.csv or args.all_formats:
        out = cfg.export_dir / f"findings_{ts}.csv"
        await export_findings_csv(result, out)
        exported.append(str(out))

        out2 = cfg.export_dir / f"users_{ts}.csv"
        await export_users_csv(result, out2)
        exported.append(str(out2))

    if args.text or args.all_formats:
        out = cfg.export_dir / f"report_{ts}.txt"
        await export_text_report(result, out)
        exported.append(str(out))

    if exported:
        print(f"\n  {_GREEN}{_BOLD}Exports:{_R}")
        for path in exported:
            print(f"    {_CYAN}→{_R} {path}")

    # Exit code: 1 if critical findings
    return 1 if result.critical_count > 0 else 0


# ─────────────────────────────────────────────────────────────
# Interactive REPL
# ─────────────────────────────────────────────────────────────

async def _interactive_repl(cfg: SysGuardConfig) -> None:
    _banner()
    print(f"  {_CYAN}Interactive mode. Type 'help' for commands.{_R}\n")

    scan_result = None

    def _menu() -> None:
        print(f"""
{_BOLD}  Commands:{_R}
    {_CYAN}scan{_R}           Run full account security scan
    {_CYAN}scan --fs{_R}      Scan + filesystem permission audit
    {_CYAN}report{_R}         Print last scan report (all risks)
    {_CYAN}report --min HIGH{_R}  Print report (HIGH+ only)
    {_CYAN}export json{_R}    Export last scan to JSON
    {_CYAN}export csv{_R}     Export findings + users to CSV
    {_CYAN}export text{_R}    Export plain-text report
    {_CYAN}users{_R}          List all regular users from last scan
    {_CYAN}findings{_R}       List all findings from last scan
    {_CYAN}findings --min CRITICAL{_R}  Critical findings only
    {_CYAN}logs{_R}           Show last 20 log lines
    {_CYAN}config{_R}         Show current configuration
    {_CYAN}help{_R}           Show this help
    {_CYAN}exit{_R}           Quit
""")

    _menu()

    while True:
        try:
            raw = input(f"  {_CYAN}sysguard{_R} {_GRAY}▶{_R} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {_GRAY}Bye.{_R}")
            break

        if not raw:
            continue
        parts = raw.split()
        cmd = parts[0].lower()

        if cmd in ("exit", "quit", "q"):
            print(f"  {_GRAY}Bye.{_R}")
            break

        elif cmd == "help":
            _menu()

        elif cmd == "scan":
            use_fs = "--fs" in parts
            scan_root = Path(parts[parts.index("--root") + 1]) if "--root" in parts else Path("/")
            print(f"\n  {_CYAN}Running scan...{_R}")
            try:
                scan_result = await run_scan(
                    cfg=cfg,
                    scan_filesystem_flag=use_fs,
                    scan_root=scan_root,
                    progress_cb=_ProgressPrinter(),
                )
                print(f"\n  {_GREEN}Scan complete:{_R} {scan_result}\n")
            except SysGuardError as exc:
                print(f"\n  {_RED}Scan error:{_R} {exc}\n")

        elif cmd == "report":
            if scan_result is None:
                print(f"  {_YELLOW}No scan yet — run 'scan' first.{_R}\n")
                continue
            min_risk_name = "LOW"
            if "--min" in parts and len(parts) > parts.index("--min") + 1:
                min_risk_name = parts[parts.index("--min") + 1].upper()
            try:
                min_risk = RiskLevel[min_risk_name]
                await print_console_report(scan_result, min_risk=min_risk)
            except KeyError:
                print(f"  {_RED}Unknown risk level: {min_risk_name}{_R}")

        elif cmd == "export":
            if scan_result is None:
                print(f"  {_YELLOW}No scan yet — run 'scan' first.{_R}\n")
                continue
            ts = time.strftime("%Y%m%d_%H%M%S")
            fmt = parts[1].lower() if len(parts) > 1 else "json"
            if fmt == "json":
                out = await export_json(scan_result, cfg.export_dir / f"sysguard_{ts}.json")
                print(f"  {_GREEN}Exported:{_R} {out}\n")
            elif fmt == "csv":
                out = await export_findings_csv(scan_result, cfg.export_dir / f"findings_{ts}.csv")
                print(f"  {_GREEN}Exported:{_R} {out}\n")
            elif fmt == "text":
                out = await export_text_report(scan_result, cfg.export_dir / f"report_{ts}.txt")
                print(f"  {_GREEN}Exported:{_R} {out}\n")
            else:
                print(f"  {_YELLOW}Unknown format: {fmt}. Use json | csv | text{_R}\n")

        elif cmd == "users":
            if scan_result is None:
                print(f"  {_YELLOW}No scan yet — run 'scan' first.{_R}\n")
                continue
            print(f"\n  {_BOLD}{'USERNAME':<20} {'UID':<6} {'STATUS':<12} {'RISK':<10} {'SUDO'}{_R}")
            print(f"  {'─' * 60}")
            for u in sorted(u for u in scan_result.users if not u.is_system):
                sudo = f"{_RED}YES{_R}" if u.sudo_access else "no"
                print(f"  {u.username:<20} {u.uid:<6} {str(u.status):<12} {str(u.risk_level):<10} {sudo}")
                await asyncio.sleep(0)
            print()

        elif cmd == "findings":
            if scan_result is None:
                print(f"  {_YELLOW}No scan yet — run 'scan' first.{_R}\n")
                continue
            min_risk_name = "LOW"
            if "--min" in parts and len(parts) > parts.index("--min") + 1:
                min_risk_name = parts[parts.index("--min") + 1].upper()
            try:
                min_risk = RiskLevel[min_risk_name]
            except KeyError:
                min_risk = RiskLevel.LOW

            count = 0
            for f in sorted(scan_result.findings):
                if f.risk >= min_risk:
                    print(f"  {_BOLD}[{f.risk}]{_R} {f.title} — {_CYAN}{f.target}{_R}")
                    count += 1
                await asyncio.sleep(0)
            print(f"\n  {_GRAY}Total: {count} findings (min={min_risk.name}){_R}\n")

        elif cmd == "logs":
            lf = cfg.log_dir / "sysguard.log"
            if lf.exists():
                lines = lf.read_text(errors="replace").splitlines()[-20:]
                print(f"\n  {_GRAY}{'─' * 60}{_R}")
                for line in lines:
                    print(f"  {_GRAY}{line}{_R}")
                print(f"  {_GRAY}{'─' * 60}{_R}\n")
            else:
                print(f"  {_YELLOW}No log file yet.{_R}\n")

        elif cmd == "config":
            print(f"\n  {_BOLD}Configuration:{_R}")
            print(f"    {_CYAN}Log dir:     {_R}{cfg.log_dir}")
            print(f"    {_CYAN}Export dir:  {_R}{cfg.export_dir}")
            print(f"    {_CYAN}UID range:   {_R}{cfg.min_uid} – {cfg.max_uid}")
            print(f"    {_CYAN}Max workers: {_R}{cfg.max_workers}")
            print(f"    {_CYAN}Scan timeout:{_R}{cfg.scan_timeout}s\n")

        else:
            print(f"  {_YELLOW}Unknown command: {cmd!r}. Type 'help'.{_R}\n")


# ─────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sysguard",
        description="Linux Security Audit & Account Intelligence CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo sysguard scan
  sudo sysguard scan --filesystem --scan-root /home --json --csv
  sudo sysguard scan --min-risk HIGH --all-formats
  sudo sysguard --interactive
  sudo sysguard scan --log-level DEBUG --export-dir /tmp/reports
        """,
    )

    p.add_argument("--interactive", "-i", action="store_true", help="Launch interactive REPL")
    p.add_argument("--version", action="version", version="sysguard 1.0.0")

    sub = p.add_subparsers(dest="command")

    # ── scan subcommand ────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Run security audit scan")
    scan_p.add_argument(
        "--filesystem", "-F", action="store_true",
        help="Also scan filesystem for permission issues (slower)"
    )
    scan_p.add_argument(
        "--scan-root", default="/",
        help="Root path for filesystem scan (default: /)"
    )
    scan_p.add_argument(
        "--min-risk", default="LOW",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum risk level to display in report (default: LOW)"
    )
    scan_p.add_argument("--json",        action="store_true", help="Export JSON report")
    scan_p.add_argument("--csv",         action="store_true", help="Export CSV findings + users")
    scan_p.add_argument("--text",        action="store_true", help="Export plain-text report")
    scan_p.add_argument("--all-formats", action="store_true", help="Export all formats")

    # ── global options (apply to all subcommands) ──────────────
    for pp in [p, scan_p]:
        pp.add_argument(
            "--log-level", default="INFO",
            choices=["DEBUG", "INFO", "WARNING", "ERROR"],
            help="Log verbosity (default: INFO)"
        )
        pp.add_argument(
            "--log-dir", default=None,
            help="Override log directory"
        )
        pp.add_argument(
            "--export-dir", default=None,
            help="Override export directory"
        )

    return p


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

async def _async_main(args: argparse.Namespace, cfg: SysGuardConfig) -> int:
    if args.interactive:
        await _interactive_repl(cfg)
        return 0

    if args.command == "scan":
        return await _run_scan_and_report(args, cfg)

    # Default: show help
    _build_parser().print_help()
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Override config from args
    cfg = get_config()
    if getattr(args, "log_dir", None):
        cfg.log_dir = Path(args.log_dir)
    if getattr(args, "export_dir", None):
        cfg.export_dir = Path(args.export_dir)

    # Setup logging
    log_level = getattr(logging, getattr(args, "log_level", "INFO"))
    setup_logging(
        log_dir=cfg.log_dir,
        level=log_level,
        colour=sys.stdout.isatty(),
    )

    # Root check for write operations
    if os.geteuid() != 0:
        print(f"\n  {_YELLOW}⚠  Warning: Not running as root.{_R}")
        print(f"     Shadow file and some system info may be inaccessible.")
        print(f"     For full analysis: sudo sysguard ...\n")

    try:
        exit_code = asyncio.run(_async_main(args, cfg))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print(f"\n  {_GRAY}Interrupted.{_R}")
        sys.exit(130)
    except SysGuardError as exc:
        print(f"\n  {_RED}Error:{_R} {exc}\n", file=sys.stderr)
        log.error("Fatal error: %s", exc)
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {_RED}Unexpected error:{_R} {exc}\n", file=sys.stderr)
        log.exception("Unhandled exception")
        sys.exit(1)
    finally:
        shutdown_logging()


if __name__ == "__main__":
    main()
