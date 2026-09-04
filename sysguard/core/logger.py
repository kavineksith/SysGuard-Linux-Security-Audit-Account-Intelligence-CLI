"""
sysguard/core/logger.py
───────────────────────
Non-blocking structured logger:
  • asyncio-safe via QueueHandler / QueueListener
  • Console sink: ANSI-coloured, human-readable
  • File sink: JSON-lines (machine-readable audit trail)
  • Automatic log rotation by size
  • Module-scoped factory via get_logger()
"""
from __future__ import annotations

import asyncio
import json
import logging
import logging.handlers
import os
import queue as _queue_module
import time
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────
# ANSI colour map
# ─────────────────────────────────────────────────────────────
_RESET  = "\033[0m"
_LEVEL_COLOURS: dict[int, str] = {
    logging.DEBUG:    "\033[90m",     # dark grey
    logging.INFO:     "\033[32m",     # green
    logging.WARNING:  "\033[33;1m",   # bold yellow
    logging.ERROR:    "\033[31;1m",   # bold red
    logging.CRITICAL: "\033[35;1m",   # bold magenta
}
_CYAN  = "\033[36m"
_GRAY  = "\033[90m"
_BOLD  = "\033[1m"


# ─────────────────────────────────────────────────────────────
# Console formatter (ANSI)
# ─────────────────────────────────────────────────────────────
class ANSIFormatter(logging.Formatter):
    """Coloured console formatter with optional no-colour mode."""

    _FMT = "{ts_colour}{ts}{reset}  {lv_colour}{level:<8}{reset}  {name_colour}{name}{reset}  {msg}"

    def __init__(self, colour: bool = True) -> None:
        super().__init__()
        self._colour = colour and os.isatty(1)

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        colour    = _LEVEL_COLOURS.get(record.levelno, _RESET) if self._colour else ""
        reset     = _RESET if self._colour else ""
        ts_colour = _GRAY if self._colour else ""
        nm_colour = _CYAN if self._colour else ""

        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        ms = f"{int((record.created % 1) * 1000):03d}"

        # Extra structured fields injected via logger.info("msg", extra={...})
        extra_parts = []
        for key, val in record.__dict__.items():
            if key.startswith("sg_"):  # sysguard-namespaced extras
                extra_parts.append(f"{_GRAY}{key[3:]}={val!r}{reset}" if self._colour
                                   else f"{key[3:]}={val!r}")

        msg = record.getMessage()
        if extra_parts:
            msg = f"{msg}  {' '.join(extra_parts)}"

        # Exception
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)

        return self._FMT.format(
            ts=f"{ts}.{ms}",
            ts_colour=ts_colour,
            lv_colour=colour,
            name_colour=nm_colour,
            name=f"{record.name}",
            level=record.levelname,
            msg=msg,
            reset=reset,
        )


# ─────────────────────────────────────────────────────────────
# JSON-lines formatter (audit file)
# ─────────────────────────────────────────────────────────────
class JSONLinesFormatter(logging.Formatter):
    """Writes one compact JSON object per log record."""

    _SKIP = frozenset({
        "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "name", "message",
    })

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        record.message = record.getMessage()
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "epoch":     record.created,
            "level":     record.levelname,
            "logger":    record.name,
            "func":      record.funcName,
            "line":      record.lineno,
            "file":      record.filename,
            "message":   record.message,
            "pid":       record.process,
        }
        # Extra fields
        for key, val in record.__dict__.items():
            if key.startswith("sg_"):
                payload[key[3:]] = val

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, separators=(",", ":"))


# ─────────────────────────────────────────────────────────────
# Logger factory / registry
# ─────────────────────────────────────────────────────────────
_queue_listener: logging.handlers.QueueListener | None = None
_log_queue: asyncio.Queue | None = None          # async queue for log_async()
_initialized = False

def _make_rotating_handler(path: Path, max_bytes: int, backup_count: int) -> logging.handlers.RotatingFileHandler:
    path.parent.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(
        filename=str(path),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
        delay=True,
    )
    return h


def setup_logging(
    log_dir: Path | str = Path("/tmp/sysguard/logs"),
    level: int = logging.INFO,
    log_filename: str = "sysguard.log",
    audit_filename: str = "audit.jsonl",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    colour: bool = True,
) -> None:
    """
    Initialise the global QueueHandler / QueueListener pair.
    Call once at application startup; safe to call multiple times (idempotent).
    """
    global _queue_listener, _initialized
    if _initialized:
        return

    log_dir = Path(log_dir)
    queue = _queue_module.Queue(-1)

    # ── Handlers ──────────────────────────────────────────────

    # 1. Console (stderr)
    console_h = logging.StreamHandler()
    console_h.setFormatter(ANSIFormatter(colour=colour))
    console_h.setLevel(level)

    # 2. Rotating plain-text log
    file_h = _make_rotating_handler(log_dir / log_filename, max_bytes, backup_count)
    file_h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    file_h.setLevel(logging.DEBUG)

    # 3. Rotating JSON-lines audit log
    audit_h = _make_rotating_handler(log_dir / audit_filename, max_bytes, backup_count)
    audit_h.setFormatter(JSONLinesFormatter())
    audit_h.setLevel(logging.DEBUG)

    # ── QueueListener (runs in a background thread) ────────────
    _queue_listener = logging.handlers.QueueListener(
        queue, console_h, file_h, audit_h, respect_handler_level=True
    )
    _queue_listener.start()

    # ── Root queue handler ────────────────────────────────────
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    # Remove any existing handlers to avoid duplicate output
    root.handlers.clear()
    queue_h = logging.handlers.QueueHandler(queue)
    root.addHandler(queue_h)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger, ensuring setup_logging() has been called."""
    if not _initialized:
        setup_logging()
    return logging.getLogger(name)


def shutdown_logging() -> None:
    """Flush and stop the QueueListener. Call on application exit."""
    global _queue_listener, _initialized
    if _queue_listener is not None:
        _queue_listener.stop()
        _queue_listener = None
    _initialized = False


# ─────────────────────────────────────────────────────────────
# Async audit helper
# ─────────────────────────────────────────────────────────────
class AsyncAuditLogger:
    """
    Thin async wrapper that enqueues audit records from async coroutines
    without blocking the event loop.
    """

    def __init__(self, name: str) -> None:
        self._logger = get_logger(name)

    async def audit(
        self,
        action: str,
        target: str,
        result: str = "OK",
        **extra: Any,
    ) -> None:
        """Fire-and-forget audit record; yields control back to the event loop."""
        await asyncio.sleep(0)  # yield
        self._logger.info(
            "AUDIT action=%s target=%s result=%s",
            action, target, result,
            extra={f"sg_{k}": v for k, v in extra.items()} | {
                "sg_action": action,
                "sg_target": target,
                "sg_result": result,
            },
        )

    async def warn(self, message: str, **extra: Any) -> None:
        await asyncio.sleep(0)
        self._logger.warning(message, extra={f"sg_{k}": v for k, v in extra.items()})

    async def error(self, message: str, **extra: Any) -> None:
        await asyncio.sleep(0)
        self._logger.error(message, extra={f"sg_{k}": v for k, v in extra.items()})
