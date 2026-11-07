"""Check registry: maps an audit category to its ``run(ctx)`` function."""

from __future__ import annotations

from collections.abc import Callable

from reviveguard.checks import fail2ban, firewall, ssh, updates
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult

CheckFunc = Callable[[AuditContext], list[CheckResult]]

REGISTRY: dict[str, CheckFunc] = {
    "ssh": ssh.run,
    "firewall": firewall.run,
    "fail2ban": fail2ban.run,
    "updates": updates.run,
}

# Check ID prefix -> category (used to find the module that owns a check ID).
PREFIXES = {"SSH": "ssh", "FW": "firewall", "F2B": "fail2ban", "UPD": "updates"}
