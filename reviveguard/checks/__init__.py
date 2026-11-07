"""Check registry: maps an audit category to its ``run(ctx)`` function."""

from __future__ import annotations

from collections.abc import Callable

from reviveguard.checks import ssh
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult

CheckFunc = Callable[[AuditContext], list[CheckResult]]

REGISTRY: dict[str, CheckFunc] = {
    "ssh": ssh.run,
}
