"""
sysguard/models/accounts.py
────────────────────────────
Rich data models for Linux account objects.

Every class implements a full dunder method suite:
    __str__, __repr__, __eq__, __hash__, __lt__ (for sorting),
    __bool__, __len__, __iter__, __contains__, __getitem__,
    __format__, __slots__ (where applicable)
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Iterator


# ─────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────

class AccountStatus(Enum):
    ACTIVE   = auto()
    LOCKED   = auto()
    EXPIRED  = auto()
    NO_LOGIN = auto()
    SYSTEM   = auto()

    def __str__(self) -> str:
        return self.name.replace("_", " ").title()

    def __bool__(self) -> bool:
        return self is AccountStatus.ACTIVE


class RiskLevel(Enum):
    CLEAN    = 0
    INFO     = 1
    LOW      = 2
    MEDIUM   = 3
    HIGH     = 4
    CRITICAL = 5

    def __str__(self) -> str:
        return self.name

    def __lt__(self, other: "RiskLevel") -> bool:
        return self.value < other.value

    def __le__(self, other: "RiskLevel") -> bool:
        return self.value <= other.value

    def __gt__(self, other: "RiskLevel") -> bool:
        return self.value > other.value

    def __ge__(self, other: "RiskLevel") -> bool:
        return self.value >= other.value

    def __bool__(self) -> bool:
        return self.value > 0


class FindingCategory(Enum):
    PASSWORD_POLICY  = "password_policy"
    ACCOUNT_STATUS   = "account_status"
    PERMISSION       = "permission"
    SUID_SGID        = "suid_sgid"
    WORLD_WRITABLE   = "world_writable"
    UNOWNED_FILE     = "unowned_file"
    SUDOERS          = "sudoers"
    GROUP_MEMBERSHIP = "group_membership"
    HOME_DIRECTORY   = "home_directory"
    SHELL_POLICY     = "shell_policy"

    def __str__(self) -> str:
        return self.value.replace("_", " ").title()


# ─────────────────────────────────────────────────────────────
# UserAccount
# ─────────────────────────────────────────────────────────────

@dataclass
class UserAccount:
    """
    Represents a Linux user account parsed from /etc/passwd + /etc/shadow.

    Dunder methods showcase:
        __str__      short display string
        __repr__     full developer repr
        __eq__       UID-based equality
        __hash__     UID-based hash (immutable key)
        __lt__       sort by username
        __bool__     True if account is active
        __len__      number of supplementary groups
        __iter__     iterate over supplementary groups
        __contains__ group membership check
        __getitem__  attribute access by string key
        __format__   'short' | 'csv' | 'json' | '' (default)
    """
    username:       str
    uid:            int
    gid:            int
    comment:        str
    home:           str
    shell:          str
    status:         AccountStatus = AccountStatus.ACTIVE
    password_hash:  str = "x"
    last_changed:   int = 0          # shadow: days since epoch
    min_age:        int = 0
    max_age:        int = 99999
    warn_days:      int = 7
    inactive_days:  int = -1
    expire_date:    int = -1
    supplementary_groups: list[str] = field(default_factory=list)
    sudo_access:    bool = False
    findings:       list["SecurityFinding"] = field(default_factory=list)

    # ── core dunders ──────────────────────────────────────────

    def __str__(self) -> str:
        status_tag = f" [{self.status}]" if self.status != AccountStatus.ACTIVE else ""
        return f"{self.username} (uid={self.uid}, gid={self.gid}){status_tag}"

    def __repr__(self) -> str:
        return (
            f"UserAccount(username={self.username!r}, uid={self.uid}, "
            f"gid={self.gid}, status={self.status.name}, "
            f"shell={self.shell!r}, sudo={self.sudo_access})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UserAccount):
            return NotImplemented
        return self.uid == other.uid

    def __hash__(self) -> int:
        return hash(self.uid)

    def __lt__(self, other: "UserAccount") -> bool:
        return self.username < other.username

    def __bool__(self) -> bool:
        return self.status == AccountStatus.ACTIVE

    def __len__(self) -> int:
        return len(self.supplementary_groups)

    def __iter__(self) -> Iterator[str]:
        return iter(self.supplementary_groups)

    def __contains__(self, group: object) -> bool:
        return group in self.supplementary_groups

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(f"UserAccount has no field {key!r}")

    def __format__(self, spec: str) -> str:
        import json as _json
        if spec == "short":
            return f"{self.username}:{self.uid}:{self.status}"
        if spec == "csv":
            groups = "|".join(self.supplementary_groups)
            return (f"{self.username},{self.uid},{self.gid},{self.home},"
                    f"{self.shell},{self.status.name},{groups},{self.sudo_access}")
        if spec == "json":
            return _json.dumps(self.to_dict(), default=str)
        return str(self)

    # ── computed properties ───────────────────────────────────

    @property
    def is_system(self) -> bool:
        return self.uid < 1000

    @property
    def password_age_days(self) -> int | None:
        if not self.last_changed:
            return None
        today_days = int(time.time() / 86400)
        return today_days - self.last_changed

    @property
    def password_expires_in(self) -> int | None:
        if self.max_age <= 0 or self.max_age == 99999:
            return None
        age = self.password_age_days
        if age is None:
            return None
        return max(0, self.max_age - age)

    @property
    def risk_level(self) -> RiskLevel:
        if not self.findings:
            return RiskLevel.CLEAN
        return max(f.risk for f in self.findings)

    def all_groups(self) -> list[str]:
        """Primary group name + supplementary groups."""
        return self.supplementary_groups[:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "username":           self.username,
            "uid":                self.uid,
            "gid":                self.gid,
            "comment":            self.comment,
            "home":               self.home,
            "shell":              self.shell,
            "status":             self.status.name,
            "sudo_access":        self.sudo_access,
            "supplementary_groups": self.supplementary_groups,
            "max_age_days":       self.max_age,
            "password_age_days":  self.password_age_days,
            "risk_level":         self.risk_level.name,
            "findings":           [f.to_dict() for f in self.findings],
        }


# ─────────────────────────────────────────────────────────────
# GroupInfo
# ─────────────────────────────────────────────────────────────

@dataclass
class GroupInfo:
    """
    Represents a Linux group from /etc/group.

    Dunder methods:
        __str__, __repr__, __eq__, __hash__, __lt__,
        __len__ (member count), __iter__ (members), __contains__
    """
    name:    str
    gid:     int
    members: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.name} (gid={self.gid}, members={len(self.members)})"

    def __repr__(self) -> str:
        return f"GroupInfo(name={self.name!r}, gid={self.gid}, members={self.members!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GroupInfo):
            return NotImplemented
        return self.gid == other.gid

    def __hash__(self) -> int:
        return hash(self.gid)

    def __lt__(self, other: "GroupInfo") -> bool:
        return self.name < other.name

    def __len__(self) -> int:
        return len(self.members)

    def __iter__(self) -> Iterator[str]:
        return iter(self.members)

    def __contains__(self, username: object) -> bool:
        return username in self.members

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "gid": self.gid, "members": self.members}


# ─────────────────────────────────────────────────────────────
# SecurityFinding
# ─────────────────────────────────────────────────────────────

@dataclass
class SecurityFinding:
    """
    A single security issue discovered during analysis.

    Dunder methods:
        __str__, __repr__, __eq__, __hash__, __lt__, __bool__,
        __format__ ('detail' | 'oneline' | ''), __len__ (detail length)
    """
    category:    FindingCategory
    risk:        RiskLevel
    title:       str
    detail:      str
    target:      str          # path, username, rule, etc.
    remediation: str = ""
    reference:   str = ""
    timestamp:   float = field(default_factory=time.time)
    extra:       dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.risk}] {self.title}: {self.target}"

    def __repr__(self) -> str:
        return (
            f"SecurityFinding(risk={self.risk.name}, "
            f"category={self.category.name}, "
            f"title={self.title!r}, target={self.target!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecurityFinding):
            return NotImplemented
        return (self.category, self.risk, self.title, self.target) == \
               (other.category, other.risk, other.title, other.target)

    def __hash__(self) -> int:
        return hash((self.category, self.title, self.target))

    def __lt__(self, other: "SecurityFinding") -> bool:
        # Sort: higher risk first, then by category, then title
        if self.risk != other.risk:
            return self.risk > other.risk
        return self.title < other.title

    def __bool__(self) -> bool:
        return self.risk > RiskLevel.CLEAN

    def __len__(self) -> int:
        return len(self.detail)

    def __format__(self, spec: str) -> str:
        if spec == "oneline":
            return f"[{self.risk:<8}] [{self.category}] {self.title} — {self.target}"
        if spec == "detail":
            lines = [
                f"{'─' * 60}",
                f"Risk:        {self.risk}",
                f"Category:    {self.category}",
                f"Title:       {self.title}",
                f"Target:      {self.target}",
                f"Detail:      {self.detail}",
            ]
            if self.remediation:
                lines.append(f"Remediation: {self.remediation}")
            if self.reference:
                lines.append(f"Reference:   {self.reference}")
            return "\n".join(lines)
        return str(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category":    self.category.value,
            "risk":        self.risk.name,
            "risk_value":  self.risk.value,
            "title":       self.title,
            "detail":      self.detail,
            "target":      self.target,
            "remediation": self.remediation,
            "reference":   self.reference,
            "timestamp":   self.timestamp,
            **self.extra,
        }


# ─────────────────────────────────────────────────────────────
# SudoersRule
# ─────────────────────────────────────────────────────────────

@dataclass
class SudoersRule:
    """
    A parsed sudoers rule entry.

    Dunder methods:
        __str__, __repr__, __eq__, __hash__, __bool__, __lt__
    """
    source_file: str
    raw:         str
    subject:     str     # user or %group
    hosts:       str
    runas:       str
    tags:        list[str]
    commands:    list[str]
    is_group:    bool = False
    nopasswd:    bool = False
    is_dangerous: bool = False
    risk:        RiskLevel = RiskLevel.CLEAN

    def __str__(self) -> str:
        cmd_str = ", ".join(self.commands[:2])
        if len(self.commands) > 2:
            cmd_str += f" (+{len(self.commands) - 2} more)"
        return f"{self.subject} → {cmd_str} [{self.risk}]"

    def __repr__(self) -> str:
        return (
            f"SudoersRule(subject={self.subject!r}, "
            f"commands={self.commands!r}, "
            f"nopasswd={self.nopasswd}, risk={self.risk.name})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SudoersRule):
            return NotImplemented
        return self.raw == other.raw

    def __hash__(self) -> int:
        return hash(self.raw)

    def __bool__(self) -> bool:
        return not self.is_dangerous

    def __lt__(self, other: "SudoersRule") -> bool:
        return self.risk > other.risk  # higher risk sorts first

    def __len__(self) -> int:
        return len(self.commands)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source":      self.source_file,
            "subject":     self.subject,
            "hosts":       self.hosts,
            "runas":       self.runas,
            "nopasswd":    self.nopasswd,
            "commands":    self.commands,
            "tags":        self.tags,
            "is_dangerous": self.is_dangerous,
            "risk":        self.risk.name,
            "raw":         self.raw,
        }


# ─────────────────────────────────────────────────────────────
# ScanResult — top-level aggregation
# ─────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    Top-level aggregation of a full system scan.

    Dunder methods:
        __str__, __repr__, __bool__, __len__, __iter__, __contains__,
        __add__ (merge two ScanResults), __getitem__
    """
    users:      list[UserAccount]   = field(default_factory=list)
    groups:     list[GroupInfo]     = field(default_factory=list)
    findings:   list[SecurityFinding] = field(default_factory=list)
    sudoers:    list[SudoersRule]   = field(default_factory=list)
    scan_time:  float               = field(default_factory=time.time)
    duration:   float               = 0.0
    errors:     list[str]           = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"ScanResult: {len(self.users)} users, {len(self.groups)} groups, "
            f"{len(self.findings)} findings ({self.critical_count} critical), "
            f"in {self.duration:.2f}s"
        )

    def __repr__(self) -> str:
        return (
            f"ScanResult(users={len(self.users)}, groups={len(self.groups)}, "
            f"findings={len(self.findings)}, duration={self.duration:.2f})"
        )

    def __bool__(self) -> bool:
        return len(self.findings) > 0

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Iterator[SecurityFinding]:
        return iter(sorted(self.findings))

    def __contains__(self, item: object) -> bool:
        return item in self.findings

    def __add__(self, other: "ScanResult") -> "ScanResult":
        return ScanResult(
            users=self.users + other.users,
            groups=self.groups + other.groups,
            findings=self.findings + other.findings,
            sudoers=self.sudoers + other.sudoers,
            scan_time=min(self.scan_time, other.scan_time),
            duration=self.duration + other.duration,
            errors=self.errors + other.errors,
        )

    def __getitem__(self, risk: RiskLevel) -> list[SecurityFinding]:
        return [f for f in self.findings if f.risk == risk]

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.HIGH)

    @property
    def overall_risk(self) -> RiskLevel:
        if not self.findings:
            return RiskLevel.CLEAN
        return max(f.risk for f in self.findings)

    def findings_by_category(self) -> dict[FindingCategory, list[SecurityFinding]]:
        result: dict[FindingCategory, list[SecurityFinding]] = {}
        for f in self.findings:
            result.setdefault(f.category, []).append(f)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_time":   self.scan_time,
            "duration":    self.duration,
            "summary": {
                "users":    len(self.users),
                "groups":   len(self.groups),
                "findings": len(self.findings),
                "critical": self.critical_count,
                "high":     self.high_count,
                "risk":     self.overall_risk.name,
                "errors":   len(self.errors),
            },
            "users":    [u.to_dict() for u in self.users],
            "groups":   [g.to_dict() for g in self.groups],
            "findings": [f.to_dict() for f in sorted(self.findings)],
            "sudoers":  [s.to_dict() for s in self.sudoers],
            "errors":   self.errors,
        }
