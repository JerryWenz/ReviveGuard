"""Fail2ban fixes: install/start fail2ban and enable the SSH jail through a drop-in file.

A running fail2ban is reloaded, never restarted; a stopped one is started. Packages are only
installed with the user's confirmation (allow-listed) and are never removed.
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
    text = jail_text(ctx, result.check_id, port, None)
    return FixSpec(
        fix_id="fail2ban.sshd_jail.enable",
        check_id=result.check_id,
        description=f"Enable the {JAIL} jail (port {port}) via drop-in {JAIL_DIR}/{DROPIN}",
        files=[path],
        apply=lambda: write_file_atomic(path, text, 0o644),
        validate=lambda: _config_error(ctx),
        activate=lambda: activate_fail2ban(ctx),
        change_key="fix.fail2ban.enable_jail",
        change_args={"path": f"{JAIL_DIR}/{DROPIN}", "port": port},
        service_key="fix.service.reload_fail2ban",
    )


def tool_present(ctx: AuditContext, name: str) -> bool:
    return not ctx.runner([name, "--version"]).missing


def needs_journal_backend(ctx: AuditContext) -> bool:
    """Minimal images have no auth.log (no rsyslog); sshd then logs only to journald."""
    return not ctx.path("/var/log/auth.log").is_file() and ctx.path("/run/systemd/journal").exists()


def choose_banaction(ctx: AuditContext) -> str | None:
    """Pick the ban mechanism that really exists on this host (nft first, then iptables)."""
    for tool, action in (("nft", "nftables"), ("iptables", "iptables")):
        if (
            tool_present(ctx, tool)
            and ctx.path(f"/etc/fail2ban/action.d/{action}-multiport.conf").is_file()
        ):
            return action
    return None


def jail_text(ctx: AuditContext, check_id: str, port: str, ip: str | None) -> str:
    lines = [f"# Managed by ReviveGuard ({check_id}). Remove this file to undo.", "[DEFAULT]"]
    if ip:
        lines.append(f"ignoreip = 127.0.0.1/8 ::1 {ip}")
    action = choose_banaction(ctx)
    if action:
        lines += [f"banaction = {action}-multiport", f"banaction_allports = {action}-allports"]
    lines += ["", f"[{JAIL}]", "enabled = true", f"port = {port}"]
    if needs_journal_backend(ctx):
        lines.append("backend = systemd")
    return "\n".join(lines) + "\n"


def activate_fail2ban(ctx: AuditContext) -> bool:
    """Reload a running fail2ban; start (and enable) a stopped one. Never a blind restart."""
    if ctx.runner(["systemctl", "is-active", "--quiet", "fail2ban"]).ok:
        return ctx.runner(["fail2ban-client", "reload"]).ok
    return ctx.runner(["systemctl", "enable", "--now", "fail2ban"], timeout=120).ok


IGNOREIP_DROPIN = "reviveguard-base.local"


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
    """F2B-001: install/start fail2ban with everything it needs to actually work.

    Handles a bare image: journald backend (python3-systemd) when there is no auth.log, a
    ban mechanism (iptables) when no firewall tool exists, and a stopped, installed fail2ban.
    The current SSH client address is whitelisted so the administrator is not banned.
    """
    if not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")
    ip = client_ip(ctx)
    port = ssh_port(ctx)
    path = ctx.path(f"{JAIL_DIR}/{IGNOREIP_DROPIN}")
    installed = not ctx.runner(["fail2ban-client", "--version"]).missing
    wanted = [] if installed else ["fail2ban"]
    if needs_journal_backend(ctx) and not packages.is_installed(ctx, "python3-systemd"):
        wanted.append("python3-systemd")
    if not (tool_present(ctx, "nft") or tool_present(ctx, "iptables")):
        wanted.append("iptables")

    def apply() -> None:
        if wanted:
            error = packages.install(ctx, wanted)
            if error:
                raise RuntimeError(error)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_file_atomic(path, jail_text(ctx, result.check_id, port, ip), 0o644)

    what = ", ".join(wanted) if wanted else "nothing new"
    return FixSpec(
        fix_id="fail2ban.install",
        check_id=result.check_id,
        description=f"Set up fail2ban (packages: {what}; sshd jail, whitelist {ip or 'none'})",
        files=[path],
        apply=apply,
        validate=lambda: _config_error(ctx),
        activate=lambda: activate_fail2ban(ctx),
        change_key="fix.fail2ban.install",
        change_args={"ip": ip or "-", "packages": what},
        service_key="fix.service.start_fail2ban",
        packages=wanted,
    )
