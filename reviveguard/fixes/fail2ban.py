"""Fail2ban fixes. Only the SSH jail is enabled automatically, through a drop-in file.

Fail2ban is reloaded (``fail2ban-client reload``), never restarted. Installing packages is
never done automatically.
"""

from __future__ import annotations

from reviveguard.checks.fail2ban import JAIL, ssh_port
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual, write_file_atomic

JAIL_DIR = "/etc/fail2ban/jail.d"
DROPIN = "reviveguard-sshd.local"


def _config_error(ctx: AuditContext) -> str | None:
    proc = ctx.runner(["fail2ban-client", "-t"])
    if proc.ok:
        return None
    return ((proc.stderr or proc.stdout).strip().splitlines() or ["fail2ban -t failed"])[0][:200]


def plan_ssh_jail(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    if ctx.runner(["fail2ban-client", "--version"]).missing:
        return Manual("fix.reason.fail2ban_missing")
    if _config_error(ctx) is not None:
        return Manual("fix.reason.fail2ban_config_invalid")
    if not ctx.path(JAIL_DIR).is_dir():
        return Manual("fix.reason.no_fail2ban_dir")
    port = ssh_port(ctx)
    path = ctx.path(f"{JAIL_DIR}/{DROPIN}")
    text = (
        f"# Managed by ReviveGuard ({result.check_id}). Remove this file to undo.\n"
        f"[{JAIL}]\nenabled = true\nport = {port}\n"
    )
    return FixSpec(
        fix_id="fail2ban.sshd_jail.enable",
        check_id=result.check_id,
        description=f"Enable the {JAIL} jail (port {port}) via drop-in {JAIL_DIR}/{DROPIN}",
        files=[path],
        apply=lambda: write_file_atomic(path, text, 0o644),
        validate=lambda: _config_error(ctx),
        activate=lambda: ctx.runner(["fail2ban-client", "reload"]).ok,
        change_key="fix.fail2ban.enable_jail",
        change_args={"path": f"{JAIL_DIR}/{DROPIN}", "port": port},
        service_key="fix.service.reload_fail2ban",
    )
