"""
sysguard/core/exceptions.py
───────────────────────────
OOP-based custom exception hierarchy with:
  • Structured error codes
  • Rich context payloads
  • Full dunder method suite (__str__, __repr__, __eq__, __hash__, __bool__,
    __len__, __iter__, __contains__, __format__, __reduce__)
  • Severity levels for log routing
  • Chain-of-cause preservation
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, Iterator


# ─────────────────────────────────────────────────────────────
# Error codes
# ─────────────────────────────────────────────────────────────
class ErrorCode(IntEnum):
    UNKNOWN                 = 0

    # I/O and system
    FILE_NOT_FOUND          = 1001
    PERMISSION_DENIED       = 1002
    PARSE_ERROR             = 1003
    ENCODING_ERROR          = 1004

    # Privilege
    INSUFFICIENT_PRIVILEGE  = 2001
    ROOT_REQUIRED           = 2002

    # User / group analysis
    USER_NOT_FOUND          = 3001
    USER_DUPLICATE          = 3002
    GROUP_NOT_FOUND         = 3003
    INVALID_UID_RANGE       = 3004
    WEAK_PASSWORD_POLICY    = 3005
    SHADOW_INACCESSIBLE     = 3006

    # Permission / ACL
    UNSAFE_PERMISSION       = 4001
    UNOWNED_FILE            = 4002
    SUID_FOUND              = 4003
    WORLD_WRITABLE          = 4004
    ACL_PARSE_ERROR         = 4005

    # Sudoers
    SUDOERS_PARSE_ERROR     = 5001
    SUDOERS_UNSAFE_RULE     = 5002

    # Analysis / report
    SCAN_TIMEOUT            = 6001
    SCAN_PARTIAL            = 6002
    REPORT_WRITE_ERROR      = 6003
    EXPORT_FORMAT_ERROR     = 6004

    # Config
    CONFIG_MISSING          = 7001
    CONFIG_INVALID          = 7002


class Severity(IntEnum):
    DEBUG    = auto()
    INFO     = auto()
    WARNING  = auto()
    ERROR    = auto()
    CRITICAL = auto()


def _reconstruct_sysguard_error(cls: type) -> "SysGuardError":
    """Pickle helper: create an empty instance bypassing __init__, state applied via __setstate__."""
    obj = cls.__new__(cls)
    return obj


# ─────────────────────────────────────────────────────────────
# Base exception
# ─────────────────────────────────────────────────────────────
@dataclass
class SysGuardError(Exception):
    """
    Base exception for all SysGuard errors.

    Dunder methods:
        __str__      human-readable message
        __repr__     full developer representation
        __eq__       compare by code + message
        __hash__     hashable (code + message)
        __bool__     always True (an exception instance is always truthy)
        __len__      number of context keys
        __iter__     iterate over context items
        __contains__ key-in-context lookup
        __format__   format spec: 'json' | 'short' | '' (default)
        __reduce__   pickle support
    """
    message: str
    code: ErrorCode = ErrorCode.UNKNOWN
    severity: Severity = Severity.ERROR
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    # ── core dunders ──────────────────────────────────────────

    def __str__(self) -> str:
        base = f"[{self.code.name}] {self.message}"
        if self.context:
            ctx = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{base} ({ctx})"
        return base

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"code={self.code.name}, "
            f"severity={self.severity.name}, "
            f"message={self.message!r}, "
            f"context={self.context!r}, "
            f"timestamp={self.timestamp:.3f})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SysGuardError):
            return NotImplemented
        return self.code == other.code and self.message == other.message

    def __hash__(self) -> int:
        return hash((type(self).__name__, self.code, self.message))

    def __bool__(self) -> bool:
        return True  # an exception instance is always truthy

    def __len__(self) -> int:
        return len(self.context)

    def __iter__(self) -> Iterator[tuple[str, Any]]:
        return iter(self.context.items())

    def __contains__(self, key: object) -> bool:
        return key in self.context

    def __format__(self, spec: str) -> str:
        if spec == "json":
            return json.dumps({
                "type": type(self).__name__,
                "code": self.code.name,
                "code_value": int(self.code),
                "severity": self.severity.name,
                "message": self.message,
                "context": self.context,
                "timestamp": self.timestamp,
            }, default=str)
        if spec == "short":
            return f"{self.code.name}: {self.message}"
        return str(self)

    def __reduce__(self) -> tuple:
        return (
            _reconstruct_sysguard_error,
            (type(self),),
            {
                "message": self.message,
                "code": self.code,
                "severity": self.severity,
                "context": self.context,
                "timestamp": self.timestamp,
            },
        )

    def __setstate__(self, state: dict) -> None:
        for k, v in state.items():
            object.__setattr__(self, k, v)
        Exception.__init__(self, self.message)

    # ── helpers ───────────────────────────────────────────────

    def with_context(self, **kwargs: Any) -> "SysGuardError":
        """Return a copy with additional context keys."""
        new_ctx = {**self.context, **kwargs}
        return type(self)(
            message=self.message,
            code=self.code,
            severity=self.severity,
            context=new_ctx,
            timestamp=self.timestamp,
        )

    def is_critical(self) -> bool:
        return self.severity >= Severity.CRITICAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": type(self).__name__,
            "code": self.code.name,
            "severity": self.severity.name,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp,
        }


# ─────────────────────────────────────────────────────────────
# Domain-specific subclasses
# ─────────────────────────────────────────────────────────────

@dataclass
class SystemAccessError(SysGuardError):
    """Raised when the process lacks privilege to read system files."""
    code: ErrorCode = ErrorCode.INSUFFICIENT_PRIVILEGE
    severity: Severity = Severity.CRITICAL

    def __str__(self) -> str:
        return f"[PRIVILEGE] {self.message} — try running with sudo"


@dataclass
class RootRequiredError(SystemAccessError):
    """Raised when an operation strictly requires UID 0."""
    code: ErrorCode = ErrorCode.ROOT_REQUIRED

    def __str__(self) -> str:
        return f"[ROOT REQUIRED] {self.message}"


@dataclass
class ParseError(SysGuardError):
    """Raised when a system file cannot be parsed."""
    code: ErrorCode = ErrorCode.PARSE_ERROR
    severity: Severity = Severity.ERROR
    line_number: int = 0
    raw_line: str = ""

    def __str__(self) -> str:
        loc = f" (line {self.line_number})" if self.line_number else ""
        return f"[PARSE] {self.message}{loc}"


@dataclass
class UserAnalysisError(SysGuardError):
    """Raised during user account analysis."""
    code: ErrorCode = ErrorCode.USER_NOT_FOUND
    severity: Severity = Severity.WARNING
    username: str = ""

    def __str__(self) -> str:
        u = f" [{self.username}]" if self.username else ""
        return f"[USER]{u} {self.message}"


@dataclass
class PermissionFindingError(SysGuardError):
    """Raised when a dangerous permission configuration is found."""
    code: ErrorCode = ErrorCode.UNSAFE_PERMISSION
    severity: Severity = Severity.WARNING
    path: str = ""
    octal: str = ""

    def __str__(self) -> str:
        p = f" path={self.path!r}" if self.path else ""
        o = f" mode={self.octal}" if self.octal else ""
        return f"[PERM FINDING]{p}{o} — {self.message}"


@dataclass
class SudoersError(SysGuardError):
    """Raised when a sudoers rule is dangerous or unparseable."""
    code: ErrorCode = ErrorCode.SUDOERS_PARSE_ERROR
    severity: Severity = Severity.WARNING
    rule: str = ""

    def __str__(self) -> str:
        r = f" rule={self.rule!r}" if self.rule else ""
        return f"[SUDOERS]{r} {self.message}"


@dataclass
class ScanError(SysGuardError):
    """Raised when a scan operation times out or partially fails."""
    code: ErrorCode = ErrorCode.SCAN_TIMEOUT
    severity: Severity = Severity.ERROR
    scan_target: str = ""
    scanned: int = 0
    total: int = 0

    def __str__(self) -> str:
        progress = f" ({self.scanned}/{self.total})" if self.total else ""
        return f"[SCAN]{progress} {self.message}"


@dataclass
class ReportError(SysGuardError):
    """Raised during report generation or export."""
    code: ErrorCode = ErrorCode.REPORT_WRITE_ERROR
    severity: Severity = Severity.ERROR
    output_path: str = ""

    def __str__(self) -> str:
        p = f" → {self.output_path}" if self.output_path else ""
        return f"[REPORT]{p} {self.message}"


@dataclass
class ConfigError(SysGuardError):
    """Raised when configuration is missing or invalid."""
    code: ErrorCode = ErrorCode.CONFIG_MISSING
    severity: Severity = Severity.CRITICAL
    config_key: str = ""

    def __str__(self) -> str:
        k = f" key={self.config_key!r}" if self.config_key else ""
        return f"[CONFIG]{k} {self.message}"


# ─────────────────────────────────────────────────────────────
# Exception group (Python 3.11+ ExceptionGroup compatible)
# ─────────────────────────────────────────────────────────────

class SysGuardErrorGroup(SysGuardError):
    """
    Aggregates multiple SysGuardError instances from parallel scans.
    Supports iteration over sub-errors and severity-based filtering.
    """
    def __init__(self, message: str, errors: list[SysGuardError]) -> None:
        super().__init__(
            message=message,
            code=ErrorCode.SCAN_PARTIAL,
            severity=max((e.severity for e in errors), default=Severity.ERROR),
            context={"error_count": len(errors)},
        )
        self.errors: list[SysGuardError] = errors

    def __len__(self) -> int:
        return len(self.errors)

    def __iter__(self) -> Iterator[SysGuardError]:  # type: ignore[override]
        return iter(self.errors)

    def __contains__(self, item: object) -> bool:
        return item in self.errors

    def __str__(self) -> str:
        lines = [f"[ERROR GROUP] {self.message} ({len(self.errors)} errors):"]
        for i, e in enumerate(self.errors, 1):
            lines.append(f"  {i}. {e}")
        return "\n".join(lines)

    def filter_by_severity(self, min_severity: Severity) -> list[SysGuardError]:
        return [e for e in self.errors if e.severity >= min_severity]

    def critical_only(self) -> list[SysGuardError]:
        return self.filter_by_severity(Severity.CRITICAL)
