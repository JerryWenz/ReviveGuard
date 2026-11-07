"""Update fixes: refresh the package index, apply security updates, enable auto-updates.

Package operations cannot be rolled back; they are recorded as non-reversible and always
need explicit confirmation. Packages are never removed and services are never restarted
by ReviveGuard (needrestart runs in list-only mode).
"""

from __future__ import annotations

from reviveguard import packages
from reviveguard.checks.updates import security_packages
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual, write_file_atomic

AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
AUTO_UPGRADES_TEXT = (
    "// Managed by ReviveGuard (UPD-004). Remove this file to undo.\n"
    'APT::Periodic::Update-Package-Lists "1";\n'
    'APT::Periodic::Unattended-Upgrade "1";\n'
)


def _raise_on(error: str | None) -> None:
    if error:
        raise RuntimeError(error)


def plan_index(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    if not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")
    return FixSpec(
        fix_id="updates.index.refresh",
        check_id=result.check_id,
        description="Refresh the apt package index (apt-get update)",
        files=[],
        apply=lambda: _raise_on(packages.update_index(ctx)),
        validate=lambda: None,
        activate=None,
        change_key="fix.updates.index",
        reversible=False,
        verify=lambda: None,  # apt-get update succeeded (non-zero exit is an apply failure)
    )


def plan_security_updates(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    if not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")
    pkgs = security_packages(ctx)
    if not pkgs:
        return Manual("fix.reason.nothing_to_upgrade")
    preview = ", ".join(pkgs[:8]) + (" ..." if len(pkgs) > 8 else "")
    return FixSpec(
        fix_id="updates.security.apply",
        check_id=result.check_id,
        description=f"Upgrade {len(pkgs)} package(s) from the security pocket: {', '.join(pkgs)}",
        files=[],
        apply=lambda: _raise_on(packages.upgrade_only(ctx, pkgs)),
        validate=lambda: None,
        activate=None,
        change_key="fix.updates.security",
        change_args={"count": str(len(pkgs)), "packages": preview},
        service_key="fix.service.packages_may_restart",
        disruptive=True,
        reversible=False,
    )


def plan_auto_updates(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    if not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")
    path = ctx.path(AUTO_UPGRADES)

    def apply() -> None:
        if not packages.is_installed(ctx, "unattended-upgrades"):
            _raise_on(packages.install(ctx, ["unattended-upgrades"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        write_file_atomic(path, AUTO_UPGRADES_TEXT, 0o644)

    return FixSpec(
        fix_id="updates.auto.enable",
        check_id=result.check_id,
        description=f"Install unattended-upgrades and enable it via {AUTO_UPGRADES}",
        files=[path],
        apply=apply,
        validate=lambda: None,
        activate=None,
        change_key="fix.updates.auto",
        change_args={"path": AUTO_UPGRADES},
        reversible=True,  # rollback removes/restores the file; the package stays installed
    )
