"""Firewall findings are intentionally manual.

Enabling or changing a firewall can cut the access the administrator depends on, and the
set of ports that must stay open cannot be derived reliably from the host. ReviveGuard
therefore explains the finding and the exact manual steps, and never touches rules.
"""

from __future__ import annotations

from reviveguard import packages
from reviveguard.checks.firewall import collect
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual


def plan_manual(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    return Manual("fix.reason.firewall_manual")


plan_manual.manual_only = True  # type: ignore[attr-defined]


def plan_install_ufw(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    """FW-001: with no firewall tool at all, offer to install ufw. It is left *disabled*."""
    state = collect(ctx)
    if state.tools_present or state.firewalld_active:
        return Manual("fix.reason.firewall_manual")
    if not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")

    def apply() -> None:
        error = packages.install(ctx, ["ufw"])
        if error:
            raise RuntimeError(error)

    return FixSpec(
        fix_id="firewall.ufw.install",
        check_id=result.check_id,
        description="Install the ufw package (left disabled; no rules are changed)",
        files=[],
        apply=apply,
        validate=lambda: None,
        activate=None,
        change_key="fix.firewall.install_ufw",
        reversible=False,
        verify=lambda: None if packages.is_installed(ctx, "ufw") else "ufw is not installed",
    )
