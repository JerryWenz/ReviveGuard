"""Check registry: maps an audit category to its ``run(ctx)`` function."""

from __future__ import annotations

from collections.abc import Callable

from reviveguard.checks import (
    accounts,
    docker,
    fail2ban,
    firewall,
    permissions,
    services,
    ssh,
    sysctl,
    timesync,
    tuning,
    updates,
)
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult

CheckFunc = Callable[[AuditContext], list[CheckResult]]

REGISTRY: dict[str, CheckFunc] = {
    "ssh": ssh.run,
    "firewall": firewall.run,
    "fail2ban": fail2ban.run,
    "updates": updates.run,
    "permissions": permissions.run,
    "services": services.run,
    "sysctl": sysctl.run,
    "accounts": accounts.run,
    "docker": docker.run,
    "time": timesync.run,
    "tuning": tuning.run,
}

# Check ID prefix -> category (used to find the module that owns a check ID).
PREFIXES = {
    "SSH": "ssh",
    "FW": "firewall",
    "F2B": "fail2ban",
    "UPD": "updates",
    "PERM": "permissions",
    "SVC": "services",
    "SYS": "sysctl",
    "USR": "accounts",
    "DOC": "docker",
    "TIME": "time",
    "TUN": "tuning",
}
