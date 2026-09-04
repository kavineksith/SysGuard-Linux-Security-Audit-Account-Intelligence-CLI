"""
sysguard/core/config.py
───────────────────────
Central configuration with environment variable overrides.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SysGuardConfig:
    # Paths
    log_dir:        Path = Path(os.getenv("SYSGUARD_LOG_DIR", "/tmp/sysguard/logs"))
    export_dir:     Path = Path(os.getenv("SYSGUARD_EXPORT_DIR", "/tmp/sysguard/exports"))

    # UID range for "regular" users
    min_uid:        int  = int(os.getenv("SYSGUARD_MIN_UID", "1000"))
    max_uid:        int  = int(os.getenv("SYSGUARD_MAX_UID", "60000"))

    # Password policy thresholds
    pass_max_age:   int  = int(os.getenv("SYSGUARD_PASS_MAX_AGE", "90"))
    pass_min_len:   int  = int(os.getenv("SYSGUARD_PASS_MIN_LEN", "12"))

    # Scan settings
    max_workers:    int  = int(os.getenv("SYSGUARD_MAX_WORKERS", "8"))
    scan_timeout:   float = float(os.getenv("SYSGUARD_SCAN_TIMEOUT", "60.0"))
    max_depth:      int  = int(os.getenv("SYSGUARD_MAX_DEPTH", "6"))
    max_files:      int  = int(os.getenv("SYSGUARD_MAX_FILES", "50000"))

    # Log settings
    log_level:      str  = os.getenv("SYSGUARD_LOG_LEVEL", "INFO")
    log_max_bytes:  int  = int(os.getenv("SYSGUARD_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
    log_backup:     int  = int(os.getenv("SYSGUARD_LOG_BACKUP", "5"))

    # System files
    passwd_file:    Path = Path("/etc/passwd")
    shadow_file:    Path = Path("/etc/shadow")
    group_file:     Path = Path("/etc/group")
    sudoers_file:   Path = Path("/etc/sudoers")
    sudoers_dir:    Path = Path("/etc/sudoers.d")
    shells_file:    Path = Path("/etc/shells")

    # SUID/SGID scan paths to skip
    skip_paths:     list[str] = field(default_factory=lambda: [
        "/proc", "/sys", "/dev", "/run", "/snap",
    ])

    def __post_init__(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def __repr__(self) -> str:
        return (
            f"SysGuardConfig("
            f"min_uid={self.min_uid}, max_uid={self.max_uid}, "
            f"max_workers={self.max_workers}, log_dir={self.log_dir})"
        )


# Singleton
_config: SysGuardConfig | None = None


def get_config() -> SysGuardConfig:
    global _config
    if _config is None:
        _config = SysGuardConfig()
    return _config
