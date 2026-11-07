"""Time checks (read-only): clock synchronization and the server time zone.

Accurate time matters for security: TLS certificates, TOTP codes, Kerberos and, above all, log
correlation across hosts. The time zone is only *reported* as a recommendation (UTC); changing it
affects cron schedules and application output, so it is never changed automatically.
"""

from __future__ import annotations

from reviveguard.checks.common import result, skipped
from reviveguard.checks.sysctl import is_container
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity

UTC_NAMES = {"UTC", "Etc/UTC", "Etc/UCT", "UCT", "Universal", "Etc/Universal", "Zulu", "Etc/Zulu"}


def parse_show(text: str) -> dict[str, str]:
    info = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            info[key.strip()] = value.strip()
    return info


def read_time_info(ctx: AuditContext) -> dict[str, str] | None:
    proc = ctx.runner(["timedatectl", "show"])
    return parse_show(proc.stdout) if proc.ok and proc.stdout.strip() else None


def run(ctx: AuditContext) -> list[CheckResult]:
    if is_container(ctx):
        return [skipped("time", "TIME-000", "time.container")]
    info = read_time_info(ctx)
    if info is None:
        return [skipped("time", "TIME-000", "time.unavailable")]
    synced = info.get("NTPSynchronized") == "yes"
    evidence = [
        f"time synchronization enabled: {info.get('NTP', '?')}",
        f"clock synchronized: {info.get('NTPSynchronized', '?')}",
    ]
    zone = info.get("Timezone", "")
    return [
        result("time", "TIME-001", "ntp_sync", Severity.MEDIUM, not synced, evidence),
        result(
            "time",
            "TIME-002",
            "timezone",
            Severity.LOW,
            zone not in UTC_NAMES,
            [f"time zone: {zone or 'unknown'}"],
        ),
    ]
