"""
tests/test_sysguard.py
───────────────────────
Comprehensive test suite covering:
  • Exception hierarchy dunders
  • Model dunders and business logic
  • Async parser generators
  • Security analyzers
  • Reporter utilities
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from sysguard.core.exceptions import (
    ConfigError, ErrorCode, ParseError, PermissionFindingError,
    RootRequiredError, Severity, SudoersError, SysGuardError,
    SysGuardErrorGroup, SystemAccessError, UserAnalysisError,
)
from sysguard.models.accounts import (
    AccountStatus, FindingCategory, GroupInfo, RiskLevel,
    ScanResult, SecurityFinding, SudoersRule, UserAccount,
)


# ═════════════════════════════════════════════════════════════
# Fixtures
# ═════════════════════════════════════════════════════════════

@pytest.fixture
def sample_user() -> UserAccount:
    return UserAccount(
        username="alice",
        uid=1001,
        gid=1001,
        comment="Alice Smith",
        home="/home/alice",
        shell="/bin/bash",
        status=AccountStatus.ACTIVE,
        password_hash="$6$hashed",
        last_changed=18000,
        max_age=90,
        warn_days=7,
        supplementary_groups=["developers", "docker"],
        sudo_access=True,
    )


@pytest.fixture
def sample_finding() -> SecurityFinding:
    return SecurityFinding(
        category=FindingCategory.PASSWORD_POLICY,
        risk=RiskLevel.HIGH,
        title="Password expired",
        detail="Password is 120 days old",
        target="alice",
        remediation="sudo chage -d 0 alice",
        reference="CIS 5.4.1",
    )


@pytest.fixture
def sample_group() -> GroupInfo:
    return GroupInfo(name="developers", gid=2000, members=["alice", "bob"])


@pytest.fixture
def sample_sudoers_rule() -> SudoersRule:
    return SudoersRule(
        source_file="/etc/sudoers",
        raw="alice ALL=(ALL:ALL) NOPASSWD: ALL",
        subject="alice",
        hosts="ALL",
        runas="ALL:ALL",
        tags=["NOPASSWD"],
        commands=["ALL"],
        nopasswd=True,
        is_dangerous=True,
        risk=RiskLevel.CRITICAL,
    )


@pytest.fixture
def sample_scan_result(sample_user, sample_finding, sample_group, sample_sudoers_rule) -> ScanResult:
    return ScanResult(
        users=[sample_user],
        groups=[sample_group],
        findings=[sample_finding],
        sudoers=[sample_sudoers_rule],
        scan_time=time.time(),
        duration=1.23,
    )


# ═════════════════════════════════════════════════════════════
# Exception tests
# ═════════════════════════════════════════════════════════════

class TestSysGuardError:
    def test_str(self):
        e = SysGuardError(message="Test error", code=ErrorCode.FILE_NOT_FOUND)
        assert "FILE_NOT_FOUND" in str(e)
        assert "Test error" in str(e)

    def test_repr(self):
        e = SysGuardError(message="Test", code=ErrorCode.PARSE_ERROR)
        r = repr(e)
        assert "SysGuardError" in r
        assert "PARSE_ERROR" in r

    def test_eq(self):
        e1 = SysGuardError(message="same", code=ErrorCode.FILE_NOT_FOUND)
        e2 = SysGuardError(message="same", code=ErrorCode.FILE_NOT_FOUND)
        e3 = SysGuardError(message="different", code=ErrorCode.FILE_NOT_FOUND)
        assert e1 == e2
        assert e1 != e3

    def test_hash(self):
        e1 = SysGuardError(message="same", code=ErrorCode.FILE_NOT_FOUND)
        e2 = SysGuardError(message="same", code=ErrorCode.FILE_NOT_FOUND)
        assert hash(e1) == hash(e2)
        s = {e1, e2}
        assert len(s) == 1

    def test_bool(self):
        e = SysGuardError(message="any", code=ErrorCode.UNKNOWN)
        assert bool(e) is True

    def test_len(self):
        e = SysGuardError(message="ctx", context={"a": 1, "b": 2})
        assert len(e) == 2

    def test_iter(self):
        e = SysGuardError(message="ctx", context={"x": 10, "y": 20})
        items = list(e)
        assert ("x", 10) in items
        assert ("y", 20) in items

    def test_contains(self):
        e = SysGuardError(message="ctx", context={"key": "val"})
        assert "key" in e
        assert "missing" not in e

    def test_format_json(self):
        import json
        e = SysGuardError(message="json test", code=ErrorCode.SCAN_TIMEOUT)
        d = json.loads(f"{e:json}")
        assert d["code"] == "SCAN_TIMEOUT"
        assert d["message"] == "json test"

    def test_format_short(self):
        e = SysGuardError(message="short test", code=ErrorCode.CONFIG_MISSING)
        s = f"{e:short}"
        assert "CONFIG_MISSING" in s
        assert "short test" in s

    def test_with_context(self):
        e = SysGuardError(message="base", context={"a": 1})
        e2 = e.with_context(b=2)
        assert "a" in e2
        assert "b" in e2
        assert "b" not in e  # original unchanged

    def test_is_critical(self):
        e_crit = SysGuardError(message="crit", severity=Severity.CRITICAL)
        e_warn = SysGuardError(message="warn", severity=Severity.WARNING)
        assert e_crit.is_critical()
        assert not e_warn.is_critical()

    def test_to_dict(self):
        e = SysGuardError(message="dict", code=ErrorCode.FILE_NOT_FOUND)
        d = e.to_dict()
        assert d["message"] == "dict"
        assert d["code"] == "FILE_NOT_FOUND"

    def test_subclass_system_access(self):
        e = SystemAccessError(message="no perms", context={"path": "/etc/shadow"})
        assert "PRIVILEGE" in str(e)
        assert isinstance(e, SysGuardError)

    def test_subclass_parse_error(self):
        e = ParseError(message="bad line", line_number=42, raw_line="garbage")
        assert "42" in str(e)

    def test_subclass_user_analysis(self):
        e = UserAnalysisError(message="not found", username="alice")
        assert "alice" in str(e)

    def test_subclass_perm_finding(self):
        e = PermissionFindingError(message="bad perm", path="/srv", octal="0777")
        assert "/srv" in str(e)
        assert "0777" in str(e)

    def test_subclass_sudoers(self):
        e = SudoersError(message="dangerous", rule="alice ALL=(ALL) NOPASSWD: ALL")
        assert "NOPASSWD" in str(e)

    def test_pickle_roundtrip(self):
        import pickle
        e = SysGuardError(message="pickleable", code=ErrorCode.SCAN_TIMEOUT,
                          context={"key": "val"})
        data = pickle.dumps(e)
        e2 = pickle.loads(data)
        assert e2.message == "pickleable"
        assert e2.code == ErrorCode.SCAN_TIMEOUT


class TestSysGuardErrorGroup:
    def test_len(self):
        errors = [
            SysGuardError(message="e1"),
            SysGuardError(message="e2"),
        ]
        g = SysGuardErrorGroup("multi", errors)
        assert len(g) == 2

    def test_iter(self):
        errors = [SysGuardError(message=f"e{i}") for i in range(3)]
        g = SysGuardErrorGroup("group", errors)
        assert list(g) == errors

    def test_contains(self):
        e = SysGuardError(message="unique")
        g = SysGuardErrorGroup("g", [e])
        assert e in g

    def test_str(self):
        errors = [SysGuardError(message="e1"), SysGuardError(message="e2")]
        g = SysGuardErrorGroup("errors occurred", errors)
        s = str(g)
        assert "2 errors" in s

    def test_filter_by_severity(self):
        errors = [
            SysGuardError(message="warn", severity=Severity.WARNING),
            SysGuardError(message="crit", severity=Severity.CRITICAL),
        ]
        g = SysGuardErrorGroup("mixed", errors)
        criticals = g.filter_by_severity(Severity.CRITICAL)
        assert len(criticals) == 1
        assert criticals[0].message == "crit"


# ═════════════════════════════════════════════════════════════
# Model tests
# ═════════════════════════════════════════════════════════════

class TestUserAccount:
    def test_str(self, sample_user):
        s = str(sample_user)
        assert "alice" in s
        assert "1001" in s

    def test_repr(self, sample_user):
        r = repr(sample_user)
        assert "UserAccount" in r
        assert "alice" in r

    def test_eq_by_uid(self):
        u1 = UserAccount("alice", 1001, 1001, "", "/home/alice", "/bin/bash")
        u2 = UserAccount("alice_copy", 1001, 1001, "", "/home/alice", "/bin/bash")
        u3 = UserAccount("bob", 1002, 1002, "", "/home/bob", "/bin/bash")
        assert u1 == u2   # same UID
        assert u1 != u3

    def test_hash_by_uid(self):
        u1 = UserAccount("alice", 1001, 1001, "", "/home/alice", "/bin/bash")
        u2 = UserAccount("alias", 1001, 1001, "", "/home/alias", "/bin/sh")
        assert hash(u1) == hash(u2)

    def test_lt_by_username(self):
        u1 = UserAccount("alice", 1001, 1001, "", "/home/alice", "/bin/bash")
        u2 = UserAccount("bob", 1002, 1002, "", "/home/bob", "/bin/bash")
        assert u1 < u2

    def test_bool_active(self, sample_user):
        assert bool(sample_user) is True

    def test_bool_locked(self, sample_user):
        sample_user.status = AccountStatus.LOCKED
        assert bool(sample_user) is False

    def test_len_groups(self, sample_user):
        assert len(sample_user) == 2  # developers, docker

    def test_iter_groups(self, sample_user):
        groups = list(sample_user)
        assert "developers" in groups
        assert "docker" in groups

    def test_contains_group(self, sample_user):
        assert "developers" in sample_user
        assert "missing_group" not in sample_user

    def test_getitem(self, sample_user):
        assert sample_user["username"] == "alice"
        assert sample_user["uid"] == 1001

    def test_getitem_missing(self, sample_user):
        with pytest.raises(KeyError):
            _ = sample_user["nonexistent"]

    def test_format_csv(self, sample_user):
        s = f"{sample_user:csv}"
        parts = s.split(",")
        assert parts[0] == "alice"
        assert parts[1] == "1001"

    def test_format_short(self, sample_user):
        s = f"{sample_user:short}"
        assert "alice" in s
        assert "1001" in s

    def test_format_json(self, sample_user):
        import json
        s = f"{sample_user:json}"
        d = json.loads(s)
        assert d["username"] == "alice"

    def test_is_system(self):
        sys_user = UserAccount("daemon", 1, 1, "", "/", "/usr/sbin/nologin")
        regular = UserAccount("alice", 1001, 1001, "", "/home/alice", "/bin/bash")
        assert sys_user.is_system
        assert not regular.is_system

    def test_risk_level_clean(self, sample_user):
        assert sample_user.risk_level == RiskLevel.CLEAN

    def test_risk_level_with_findings(self, sample_user, sample_finding):
        sample_user.findings.append(sample_finding)
        assert sample_user.risk_level == RiskLevel.HIGH

    def test_to_dict(self, sample_user):
        d = sample_user.to_dict()
        assert d["username"] == "alice"
        assert d["uid"] == 1001
        assert isinstance(d["supplementary_groups"], list)


class TestGroupInfo:
    def test_str(self, sample_group):
        s = str(sample_group)
        assert "developers" in s
        assert "2" in s  # 2 members

    def test_eq(self):
        g1 = GroupInfo("dev", 2000, ["a", "b"])
        g2 = GroupInfo("dev_alias", 2000, [])
        assert g1 == g2

    def test_hash(self):
        g = GroupInfo("g", 2000, [])
        assert isinstance(hash(g), int)

    def test_lt(self):
        g1 = GroupInfo("alpha", 2000)
        g2 = GroupInfo("beta", 2001)
        assert g1 < g2

    def test_len(self, sample_group):
        assert len(sample_group) == 2

    def test_iter(self, sample_group):
        members = list(sample_group)
        assert "alice" in members

    def test_contains(self, sample_group):
        assert "alice" in sample_group
        assert "charlie" not in sample_group


class TestSecurityFinding:
    def test_str(self, sample_finding):
        s = str(sample_finding)
        assert "HIGH" in s
        assert "alice" in s

    def test_bool_risky(self, sample_finding):
        assert bool(sample_finding) is True

    def test_bool_clean(self):
        f = SecurityFinding(
            category=FindingCategory.ACCOUNT_STATUS,
            risk=RiskLevel.CLEAN,
            title="Clean",
            detail="",
            target="x",
        )
        assert bool(f) is False

    def test_lt_higher_risk_first(self):
        f_critical = SecurityFinding(FindingCategory.PASSWORD_POLICY, RiskLevel.CRITICAL, "c", "", "t")
        f_low = SecurityFinding(FindingCategory.PASSWORD_POLICY, RiskLevel.LOW, "l", "", "t")
        assert f_critical < f_low   # critical sorts before low

    def test_len(self, sample_finding):
        assert len(sample_finding) == len(sample_finding.detail)

    def test_eq(self, sample_finding):
        f2 = SecurityFinding(
            category=sample_finding.category,
            risk=sample_finding.risk,
            title=sample_finding.title,
            detail="different detail",
            target=sample_finding.target,
        )
        assert sample_finding == f2   # eq by category+title+target

    def test_hash(self, sample_finding):
        assert isinstance(hash(sample_finding), int)

    def test_format_oneline(self, sample_finding):
        s = f"{sample_finding:oneline}"
        assert "HIGH" in s
        assert "alice" in s

    def test_format_detail(self, sample_finding):
        s = f"{sample_finding:detail}"
        assert "Remediation" in s
        assert "Reference" in s

    def test_to_dict(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["risk"] == "HIGH"
        assert d["target"] == "alice"


class TestSudoersRule:
    def test_str(self, sample_sudoers_rule):
        s = str(sample_sudoers_rule)
        assert "alice" in s
        assert "CRITICAL" in s

    def test_bool_dangerous(self, sample_sudoers_rule):
        assert bool(sample_sudoers_rule) is False  # is_dangerous=True → bool False

    def test_len(self, sample_sudoers_rule):
        assert len(sample_sudoers_rule) == 1  # one command: ALL

    def test_eq(self, sample_sudoers_rule):
        r2 = SudoersRule(
            source_file="/other",
            raw=sample_sudoers_rule.raw,   # same raw → equal
            subject="bob", hosts="ALL", runas="ALL", tags=[], commands=[]
        )
        assert sample_sudoers_rule == r2


class TestScanResult:
    def test_str(self, sample_scan_result):
        s = str(sample_scan_result)
        assert "finding" in s.lower()

    def test_bool_has_findings(self, sample_scan_result):
        assert bool(sample_scan_result) is True

    def test_bool_no_findings(self):
        r = ScanResult()
        assert bool(r) is False

    def test_len(self, sample_scan_result):
        assert len(sample_scan_result) == 1

    def test_iter_sorted(self, sample_scan_result):
        findings = list(sample_scan_result)
        assert len(findings) == 1

    def test_contains(self, sample_scan_result, sample_finding):
        assert sample_finding in sample_scan_result

    def test_add(self, sample_scan_result):
        r2 = ScanResult(
            findings=[SecurityFinding(FindingCategory.SUDOERS, RiskLevel.CRITICAL, "c", "", "t")]
        )
        combined = sample_scan_result + r2
        assert len(combined.findings) == 2

    def test_getitem_by_risk(self, sample_scan_result):
        high_findings = sample_scan_result[RiskLevel.HIGH]
        assert len(high_findings) == 1

    def test_getitem_missing_risk(self, sample_scan_result):
        crit = sample_scan_result[RiskLevel.CRITICAL]
        assert crit == []

    def test_overall_risk(self, sample_scan_result):
        assert sample_scan_result.overall_risk == RiskLevel.HIGH

    def test_critical_count(self, sample_scan_result):
        assert sample_scan_result.critical_count == 0

    def test_to_dict(self, sample_scan_result):
        d = sample_scan_result.to_dict()
        assert "summary" in d
        assert d["summary"]["findings"] == 1


# ═════════════════════════════════════════════════════════════
# RiskLevel enum tests
# ═════════════════════════════════════════════════════════════

class TestRiskLevel:
    def test_ordering(self):
        assert RiskLevel.CLEAN < RiskLevel.INFO
        assert RiskLevel.LOW < RiskLevel.MEDIUM
        assert RiskLevel.HIGH < RiskLevel.CRITICAL

    def test_bool(self):
        assert not bool(RiskLevel.CLEAN)
        assert bool(RiskLevel.LOW)
        assert bool(RiskLevel.CRITICAL)

    def test_str(self):
        assert str(RiskLevel.HIGH) == "HIGH"


# ═════════════════════════════════════════════════════════════
# Async analyzer tests
# ═════════════════════════════════════════════════════════════

class TestSecurityAnalyzers:
    """Test async security analyzers using real UserAccount objects."""

    @pytest.mark.asyncio
    async def test_analyze_user_policy_no_password(self):
        from sysguard.analyzers.security import analyze_user_policy
        from sysguard.core.config import SysGuardConfig
        cfg = SysGuardConfig()
        user = UserAccount(
            "testuser", 1005, 1005, "", "/home/testuser", "/bin/bash",
            password_hash="",  # empty hash = no password
        )
        findings = []
        async for f in analyze_user_policy(user, cfg, frozenset(["/bin/bash"])):
            findings.append(f)
        titles = [f.title for f in findings]
        assert any("no password" in t.lower() for t in titles)

    @pytest.mark.asyncio
    async def test_analyze_user_policy_no_max_age(self):
        from sysguard.analyzers.security import analyze_user_policy
        from sysguard.core.config import SysGuardConfig
        cfg = SysGuardConfig()
        user = UserAccount(
            "testuser", 1005, 1005, "", "/home/testuser", "/bin/bash",
            max_age=99999,
            status=AccountStatus.ACTIVE,
        )
        findings = []
        async for f in analyze_user_policy(user, cfg, frozenset(["/bin/bash"])):
            findings.append(f)
        titles = [f.title for f in findings]
        assert any("max age" in t.lower() for t in titles)

    @pytest.mark.asyncio
    async def test_analyze_user_policy_sudo_no_password(self):
        from sysguard.analyzers.security import analyze_user_policy
        from sysguard.core.config import SysGuardConfig
        cfg = SysGuardConfig()
        user = UserAccount(
            "dangeruser", 1006, 1006, "", "/home/dangeruser", "/bin/bash",
            password_hash="!!",
            sudo_access=True,
        )
        findings = []
        async for f in analyze_user_policy(user, cfg, frozenset(["/bin/bash"])):
            findings.append(f)
        risks = [f.risk for f in findings]
        assert RiskLevel.CRITICAL in risks

    @pytest.mark.asyncio
    async def test_analyze_sudoers_nopasswd_all(self, sample_sudoers_rule):
        from sysguard.analyzers.security import analyze_sudoers
        findings = []
        async for f in analyze_sudoers([sample_sudoers_rule]):
            findings.append(f)
        assert len(findings) == 1
        assert findings[0].risk == RiskLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_analyze_group_memberships_sudo_group(self):
        from sysguard.analyzers.security import analyze_group_memberships
        user = UserAccount(
            "alice", 1001, 1001, "", "/home/alice", "/bin/bash",
            supplementary_groups=["sudo", "developers"],
        )
        findings = []
        async for f in analyze_group_memberships([user]):
            findings.append(f)
        assert any("sudo" in f.detail for f in findings)
        assert any(f.risk >= RiskLevel.HIGH for f in findings)

    @pytest.mark.asyncio
    async def test_analyze_all_users_parallel(self):
        from sysguard.analyzers.security import analyze_all_users
        from sysguard.core.config import SysGuardConfig
        cfg = SysGuardConfig()
        cfg.max_workers = 2
        users = [
            UserAccount(f"user{i}", 1000 + i, 1000 + i, "", f"/home/user{i}", "/bin/bash",
                        max_age=99999)
            for i in range(5)
        ]
        findings = []
        async for f in analyze_all_users(users, cfg, frozenset(["/bin/bash"])):
            findings.append(f)
        # Each user should trigger at least "no max age" finding
        assert len(findings) >= 5


# ═════════════════════════════════════════════════════════════
# Reporter tests
# ═════════════════════════════════════════════════════════════

class TestReporter:
    @pytest.mark.asyncio
    async def test_export_json(self, sample_scan_result, tmp_path):
        from sysguard.services.reporter import export_json
        import json
        out = tmp_path / "report.json"
        result_path = await export_json(sample_scan_result, out)
        assert result_path.exists()
        data = json.loads(result_path.read_text())
        assert "summary" in data
        assert data["summary"]["findings"] == 1

    @pytest.mark.asyncio
    async def test_export_findings_csv(self, sample_scan_result, tmp_path):
        from sysguard.services.reporter import export_findings_csv
        out = tmp_path / "findings.csv"
        await export_findings_csv(sample_scan_result, out)
        assert out.exists()
        content = out.read_text()
        assert "risk" in content
        assert "HIGH" in content

    @pytest.mark.asyncio
    async def test_export_users_csv(self, sample_scan_result, tmp_path):
        from sysguard.services.reporter import export_users_csv
        out = tmp_path / "users.csv"
        await export_users_csv(sample_scan_result, out)
        assert out.exists()
        content = out.read_text()
        assert "alice" in content

    @pytest.mark.asyncio
    async def test_export_text_report(self, sample_scan_result, tmp_path):
        from sysguard.services.reporter import export_text_report
        out = tmp_path / "report.txt"
        await export_text_report(sample_scan_result, out)
        assert out.exists()
        content = out.read_text()
        assert "SysGuard" in content
        assert "HIGH" in content

    @pytest.mark.asyncio
    async def test_export_json_write_error(self, sample_scan_result):
        from sysguard.services.reporter import export_json
        from sysguard.core.exceptions import ReportError
        # Path traversing through a file (not a directory) is always invalid
        bad_path = Path("/etc/hostname/cannot_create_subdir/report.json")
        with pytest.raises(ReportError):
            await export_json(sample_scan_result, bad_path)


# ═════════════════════════════════════════════════════════════
# Config tests
# ═════════════════════════════════════════════════════════════

class TestConfig:
    def test_defaults(self):
        from sysguard.core.config import SysGuardConfig
        cfg = SysGuardConfig()
        assert cfg.min_uid == 1000
        assert cfg.max_uid == 60000
        assert cfg.max_workers == 8

    def test_repr(self):
        from sysguard.core.config import SysGuardConfig
        cfg = SysGuardConfig()
        r = repr(cfg)
        assert "SysGuardConfig" in r
        assert "min_uid" in r
