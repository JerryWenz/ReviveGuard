"""Firewall findings are intentionally manual.

Enabling or changing a firewall can cut the access the administrator depends on, and the
set of ports that must stay open cannot be derived reliably from the host. ReviveGuard
therefore explains the finding and the exact manual steps, and never touches rules.
"""

from __future__ import annotations

from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual


def plan_manual(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    return Manual("fix.reason.firewall_manual")
