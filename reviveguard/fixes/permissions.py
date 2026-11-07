"""Permission fixes: tighten specific files, never recurse, never add permissions."""

from __future__ import annotations

import os
from pathlib import Path

from reviveguard.checks.permissions import GROUPS, Violation, find_violations
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual


def tightened_mode(v: Violation) -> int:
    new = v.mode & v.max_mode  # only removes bits
    return new or 0o400  # never leave a file completely unreadable for its owner


def plan_permissions(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    violations = find_violations(ctx, result.check_id)
    if not violations:
        return Manual("fix.reason.nothing_to_fix")
    targets = [(ctx.path(v.path), v) for v in violations]

    def apply() -> None:
        for path, v in targets:
            if v.uid != 0:
                os.chown(path, 0, -1)
            os.chmod(path, tightened_mode(v))

    shown = "; ".join(f"{v.path} -> {tightened_mode(v):04o}, owner root" for _, v in targets)
    return FixSpec(
        fix_id=f"permissions.{GROUPS[result.check_id][0]}.tighten",
        check_id=result.check_id,
        description=f"Tighten permissions: {shown}",
        files=[Path(p) for p, _ in targets],
        apply=apply,
        validate=lambda: None,
        activate=None,
        change_key="fix.permissions.tighten",
        change_args={"changes": shown},
    )
