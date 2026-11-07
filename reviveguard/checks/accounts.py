"""Account checks (read-only): an administrator other than root, empty passwords, extra UID 0."""

from __future__ import annotations

from pathlib import Path

from reviveguard.checks.common import result, skipped
from reviveguard.checks.ssh import effective_config
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity
from reviveguard.ssh_access import NO_LOGIN_SHELLS, PasswdEntry, admin_access, read_passwd


def _can_login(entry: PasswdEntry | None) -> bool:
    return entry is not None and Path(entry.shell).name not in NO_LOGIN_SHELLS


def run(ctx: AuditContext) -> list[CheckResult]:
    results: list[CheckResult] = []
    passwd = read_passwd(ctx)
    found = effective_config(ctx)
    if found is not None:
        admins = admin_access(ctx, found[0])
        usable = [a.name for a in admins if a.uid != 0 and a.permitted and a.has_key]
        evidence = (
            [f"administrators with SSH key access: {', '.join(usable)}"]
            if usable
            else ["only root can administer this server over SSH"]
        )
        results.append(
            result("accounts", "USR-001", "admin_user", Severity.MEDIUM, not usable, evidence)
        )
    extra_root = [e.name for e in passwd if e.uid == 0 and e.name != "root"]
    evidence = [f"accounts with UID 0: root, {', '.join(extra_root)}"]
    results.append(
        result(
            "accounts",
            "USR-003",
            "extra_root",
            Severity.HIGH,
            bool(extra_root),
            evidence if extra_root else ["only root has UID 0"],
        )
    )
    if not ctx.running_as_root:
        return [*results, skipped("accounts", "USR-000", "accounts.needs_root")]
    shadow = ctx.read_text("/etc/shadow")
    if shadow is not None:
        by_name = {e.name: e for e in passwd}
        empty = []
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) > 1 and fields[1] == "" and _can_login(by_name.get(fields[0])):
                empty.append(fields[0])
        results.append(
            result(
                "accounts",
                "USR-002",
                "empty_password",
                Severity.CRITICAL,
                bool(empty),
                [f"accounts with an empty password: {', '.join(empty)}"] if empty else ["none"],
            )
        )
    return results
