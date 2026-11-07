"""Fail2ban fixes. Only the SSH jail is enabled automatically, through a drop-in file.

Fail2ban is reloaded (``fail2ban-client reload``), never restarted. Installing packages is
never done automatically.
"""

from __future__ import annotations

import ipaddress
import re

from reviveguard import packages
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


IGNOREIP_DROPIN = "reviveguard-ignoreip.local"


def client_ip(ctx: AuditContext) -> str | None:
    """Address of the administrator's current SSH client (to keep it from being banned)."""
    raw = (ctx.env.get("SSH_CONNECTION") or ctx.env.get("SSH_CLIENT") or "").split(" ")[0]
    if not raw:
        who = ctx.runner(["who", "-m"])
        found = re.search(r"\(([0-9a-fA-F:.]+)\)", who.stdout) if who.ok else None
        raw = found.group(1) if found else ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def plan_install(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    """F2B-001: install fail2ban when absent, protecting the current client address."""
    if not ctx.runner(["fail2ban-client", "--version"]).missing:
        return Manual("fix.reason.fail2ban_inactive")
    if not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")
    ip = client_ip(ctx)
    path = ctx.path(f"{JAIL_DIR}/{IGNOREIP_DROPIN}")
    text = (
        f"# Managed by ReviveGuard ({result.check_id}). Remove this file to undo.\n"
        f"[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 {ip}\n"
    )

    def apply() -> None:
        error = packages.install(ctx, ["fail2ban"])
        if error:
            raise RuntimeError(error)
        if ip:
            path.parent.mkdir(parents=True, exist_ok=True)
            write_file_atomic(path, text, 0o644)

    return FixSpec(
        fix_id="fail2ban.install",
        check_id=result.check_id,
        description="Install fail2ban" + (f" and whitelist the current client {ip}" if ip else ""),
        files=[path] if ip else [],
        apply=apply,
        validate=lambda: _config_error(ctx),
        activate=(lambda: ctx.runner(["fail2ban-client", "reload"]).ok) if ip else None,
        change_key="fix.fail2ban.install",
        change_args={"ip": ip or "-"},
        service_key="fix.service.reload_fail2ban" if ip else None,
        reversible=bool(ip),  # the package itself is never uninstalled
    )
