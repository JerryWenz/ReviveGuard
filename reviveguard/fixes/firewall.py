"""Firewall findings are intentionally manual.

Enabling or changing a firewall can cut the access the administrator depends on, and the
set of ports that must stay open cannot be derived reliably from the host. ReviveGuard
therefore explains the finding and the exact manual steps, and never touches rules.
"""

from __future__ import annotations

from reviveguard import packages
from reviveguard.checks.firewall import collect, is_active
from reviveguard.checks.services import RISKY, parse_ss
from reviveguard.checks.ssh import effective_config, ports_of
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual


def plan_manual(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    return Manual("fix.reason.firewall_manual")


plan_manual.manual_only = True  # type: ignore[attr-defined]


def plan_install_ufw(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    """FW-001: with no firewall tool at all, offer to install ufw. It is left *disabled*."""
    state = collect(ctx)
    if "ufw" in state.tools_readable and not is_active(state) and not state.firewalld_active:
        return plan_enable_ufw(ctx, result)
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


NOT_SERVED = {68, 123, 5353, 631, 111, 161}  # client/mDNS/RPC ports that are not "services"


def plan_enable_ufw(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    """Enable ufw with default-deny while keeping every service that is reachable today.

    Allowed: all SSH ports (always), plus ports that are publicly listening now. Database and
    admin ports from the risky list stay blocked and are shown to the user. If the new firewall
    cuts the user off, the missing confirmation disables it again.
    """
    ssh_ports = {
        int(p) for p in ports_of(effective_config(ctx)[0] if effective_config(ctx) else {})
    }
    ss = ctx.runner(["ss", "-H", "-tulnp"])
    if not ss.ok:
        return Manual("fix.reason.ufw_no_ss")
    allow: dict[tuple[int, str], str] = {(p, "tcp"): "ssh" for p in sorted(ssh_ports)}
    blocked: list[str] = []
    for item in parse_ss(ss.stdout):
        if not item.public or item.port in ssh_ports or item.port in NOT_SERVED:
            continue
        if item.port in RISKY:
            blocked.append(f"{item.port}/{item.proto} ({RISKY[item.port][0]})")
        else:
            allow.setdefault((item.port, item.proto), item.process or "service")
    connected = (ctx.env.get("SSH_CONNECTION") or "").split()
    if len(connected) >= 4 and connected[3].isdigit():
        allow.setdefault((int(connected[3]), "tcp"), "current ssh session")
    rules = [f"{port}/{proto}" for (port, proto) in sorted(allow)]
    files = [
        ctx.path(p)
        for p in (
            "/etc/ufw/ufw.conf",
            "/etc/ufw/user.rules",
            "/etc/ufw/user6.rules",
            "/etc/default/ufw",
        )
        if ctx.path(p).is_file()
    ]

    def run_ufw(*args: str) -> None:
        proc = ctx.runner(["ufw", *args], timeout=60)
        if not proc.ok:
            detail = ((proc.stderr or proc.stdout).strip().splitlines() or ["ufw failed"])[0]
            raise RuntimeError(f"ufw {' '.join(args)}: {detail}"[:200])

    def apply() -> None:
        run_ufw("default", "deny", "incoming")
        run_ufw("default", "allow", "outgoing")
        for rule in rules:
            run_ufw("allow", rule)
        run_ufw("--force", "enable")

    def verify() -> str | None:
        status = ctx.runner(["ufw", "status"])
        if not (status.ok and "Status: active" in status.stdout):
            return "ufw is not active after enabling"
        missing = [r for r in rules if r not in status.stdout]
        return f"ufw is missing rules: {', '.join(missing)}" if missing else None

    return FixSpec(
        fix_id="firewall.ufw.enable",
        check_id=result.check_id,
        description=f"Enable ufw (default deny incoming); allow {', '.join(rules)}",
        files=files,
        apply=apply,
        validate=lambda: None,
        activate=None,
        change_key="fix.firewall.enable_ufw",
        change_args={"allow": ", ".join(rules), "blocked": ", ".join(blocked) or "-"},
        service_key="fix.service.ufw_enable",
        disruptive=True,
        verify=verify,
        undo=lambda: run_ufw("--force", "disable"),
        confirm_key="fix.confirm.firewall",
        confirm_args={"ports": ", ".join(rules)},
        next_key="fix.next.ufw_enabled",
    )
