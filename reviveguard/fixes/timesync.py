"""Enable time synchronization (systemd-timesyncd). The time zone is never changed."""

from __future__ import annotations

from reviveguard import packages
from reviveguard.checks.timesync import read_time_info
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual


def plan_enable_ntp(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    info = read_time_info(ctx)
    if info is None:
        return Manual("fix.reason.no_timedatectl")
    if info.get("NTP") == "yes":
        return Manual("fix.reason.ntp_waiting")  # enabled, just not synchronized yet
    needs_package = info.get("CanNTP") != "yes"
    if needs_package and not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")

    def apply() -> None:
        if needs_package:
            error = packages.install(ctx, ["systemd-timesyncd"])
            if error:
                raise RuntimeError(error)
        proc = ctx.runner(["timedatectl", "set-ntp", "true"], timeout=60)
        if not proc.ok:
            detail = ((proc.stderr or proc.stdout).strip().splitlines() or ["failed"])[0]
            raise RuntimeError(f"timedatectl set-ntp true: {detail}"[:200])

    def verify() -> str | None:
        after = read_time_info(ctx)
        return (
            None if after and after.get("NTP") == "yes" else "time synchronization is not enabled"
        )

    return FixSpec(
        fix_id="time.ntp.enable",
        check_id=result.check_id,
        description="Enable time synchronization (timedatectl set-ntp true)"
        + (" after installing systemd-timesyncd" if needs_package else ""),
        files=[],
        apply=apply,
        validate=lambda: None,
        activate=None,
        change_key="fix.time.enable_ntp",
        reversible=False,
        packages=["systemd-timesyncd"] if needs_package else [],
        verify=verify,
        next_key="fix.next.ntp",
    )
