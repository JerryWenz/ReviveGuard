"""Fix registry: check ID -> planner ``(ctx, result) -> FixSpec | Manual``."""

from __future__ import annotations

from collections.abc import Callable

from reviveguard.context import AuditContext
from reviveguard.fixes import ssh
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual

Planner = Callable[[AuditContext, CheckResult], FixSpec | Manual]

REGISTRY: dict[str, Planner] = {
    "SSH-001": ssh.plan_root_login,
    "SSH-002": ssh.plan_password_auth,
    "SSH-003": ssh.plan_empty_passwords,
    "SSH-004": ssh.plan_pubkey_auth,
    "SSH-005": ssh.plan_config_perms,
}
