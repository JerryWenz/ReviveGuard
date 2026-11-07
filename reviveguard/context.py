"""Execution context handed to every check.

Everything a check needs from the host goes through this object, so tests can
substitute a fake filesystem root, command runner and stat function.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from reviveguard.system import CommandResult, OsInfo, detect_os, is_root, run_command


@dataclass
class AuditContext:
    root: Path = Path("/")
    runner: Callable[[list[str]], CommandResult] = run_command
    stat: Callable[[Path], os.stat_result] = os.stat
    os_info: OsInfo = field(default_factory=detect_os)
    running_as_root: bool = field(default_factory=is_root)
    env: dict[str, str] = field(default_factory=lambda: dict(os.environ))

    def path(self, absolute: str) -> Path:
        """Map an absolute host path under ``root`` (``/`` on a real system)."""
        return self.root / absolute.lstrip("/")

    def read_text(self, absolute: str) -> str | None:
        try:
            return self.path(absolute).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
