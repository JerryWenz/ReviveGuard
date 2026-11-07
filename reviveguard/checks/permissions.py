"""Permissions of selected security-sensitive files (read-only, no recursion).

A file is flagged when it is not owned by root or grants more than the allowed maximum
mode. Fixes only ever *remove* permission bits (see ``fixes/permissions.py``).
"""

from __future__ import annotations

import glob
import stat as stat_mod
from dataclasses import dataclass
from pathlib import Path

from reviveguard.checks.common import result
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity


@dataclass(frozen=True)
class Violation:
    path: str  # absolute host path (not the fake-root path)
    mode: int
    uid: int
    max_mode: int


# check id -> (name, severity, [(path pattern, max mode)])
GROUPS: dict[str, tuple[str, Severity, list[tuple[str, int]]]] = {
    "PERM-001": ("accounts", Severity.HIGH, [("/etc/passwd", 0o644), ("/etc/group", 0o644)]),
    "PERM-002": ("shadow", Severity.CRITICAL, [("/etc/shadow", 0o640), ("/etc/gshadow", 0o640)]),
    "PERM-003": (
        "sudoers",
        Severity.HIGH,
        [("/etc/sudoers", 0o640), ("/etc/sudoers.d/*", 0o640)],
    ),
    "PERM-004": ("host_keys", Severity.HIGH, [("/etc/ssh/ssh_host_*_key", 0o600)]),
}
IGNORED_SUFFIXES = (".pub", "~", ".dpkg-old", ".dpkg-new", ".bak")


def find_violations(ctx: AuditContext, check_id: str) -> list[Violation]:
    found = []
    for pattern, max_mode in GROUPS[check_id][2]:
        for real in sorted(glob.glob(str(ctx.path(pattern)))):
            host_path = "/" + str(Path(real).relative_to(ctx.root))
            if host_path.endswith(IGNORED_SUFFIXES) or Path(host_path).name == "README":
                continue
            try:
                st = ctx.stat(Path(real))
            except OSError:
                continue
            if not stat_mod.S_ISREG(st.st_mode):
                continue
            mode = stat_mod.S_IMODE(st.st_mode)
            if st.st_uid != 0 or mode & ~max_mode:
                found.append(Violation(host_path, mode, st.st_uid, max_mode))
    return found


def run(ctx: AuditContext) -> list[CheckResult]:
    results = []
    for check_id, (name, severity, _) in GROUPS.items():
        bad = find_violations(ctx, check_id)
        evidence = [
            f"{v.path}: mode {v.mode:04o} (max {v.max_mode:04o}), owner uid {v.uid}" for v in bad
        ] or ["permissions are as expected"]
        results.append(result("permissions", check_id, name, severity, bool(bad), evidence))
    return results
