"""Fix registry: check ID -> planner ``(ctx, result) -> FixSpec | Manual``."""

from __future__ import annotations

from collections.abc import Callable

from reviveguard.context import AuditContext
from reviveguard.fixes import fail2ban, firewall, permissions, ssh, sysctl, updates
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual

Planner = Callable[[AuditContext, CheckResult], FixSpec | Manual]


def manual_only(reason_key: str) -> Planner:
    """Planner for findings that are never fixed automatically (explains why)."""

    def planner(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
        return Manual(reason_key)

    planner.manual_only = True  # type: ignore[attr-defined]
    return planner


REGISTRY: dict[str, Planner] = {
    "SSH-001": ssh.plan_root_login,
    "SSH-002": ssh.plan_password_auth,
    "SSH-003": ssh.plan_empty_passwords,
    "SSH-004": ssh.plan_pubkey_auth,
    "SSH-005": ssh.plan_config_perms,
    "SSH-006": ssh.plan_x11,
    "SSH-007": ssh.plan_max_auth_tries,
    "SSH-008": ssh.plan_grace_time,
    "SSH-009": ssh.plan_weak_algorithms,
    "SSH-010": ssh.plan_port_add,
    "SSH-011": ssh.plan_port_finish,
    "F2B-001": fail2ban.plan_install,
    "F2B-002": fail2ban.plan_ssh_jail,
    "FW-001": firewall.plan_install_ufw,
    "FW-002": firewall.plan_manual,
    "FW-003": firewall.plan_manual,
    "FW-004": firewall.plan_manual,
    "UPD-001": updates.plan_index,
    "UPD-002": updates.plan_security_updates,
    "UPD-004": updates.plan_auto_updates,
    "UPD-003": manual_only("fix.reason.reboot_manual"),
    "UPD-005": manual_only("fix.reason.os_manual"),
    "SVC-002": manual_only("fix.reason.service_manual"),
    "PERM-001": permissions.plan_permissions,
    "PERM-002": permissions.plan_permissions,
    "PERM-003": permissions.plan_permissions,
    "PERM-004": permissions.plan_permissions,
    "SYS-001": manual_only("fix.reason.sysctl_manual"),
    "SYS-002": sysctl.plan_sysctl,
    "SYS-003": sysctl.plan_sysctl,
    "SYS-004": sysctl.plan_sysctl,
    "SYS-005": sysctl.plan_sysctl,
    "SYS-006": sysctl.plan_sysctl,
    "SYS-007": sysctl.plan_sysctl,
    "SYS-008": manual_only("fix.reason.sysctl_manual"),
}

# Checks that have a real automatic fix (the rest only explain the manual steps).
AUTOMATIC = frozenset(
    k for k, planner in REGISTRY.items() if not getattr(planner, "manual_only", False)
)
