"""Package operations (apt). Package changes cannot be rolled back: callers must mark
the operation non-reversible and ask for explicit confirmation.

Packages are never removed. Installs are limited to an allow-list, and package names
parsed from command output are validated before being passed back to apt.
"""

from __future__ import annotations

import re

from reviveguard.context import AuditContext

INSTALLABLE = frozenset(
    {
        "ufw",
        "fail2ban",
        "unattended-upgrades",
        "python3-systemd",
        "iptables",
        "libpam-pwquality",
        "systemd-timesyncd",
    }
)
PKG_NAME = re.compile(r"^[a-z0-9][a-z0-9+.\-]*$")
PACKAGE_TIMEOUT = 1800  # seconds; upgrades can take a while
# Non-interactive, keep existing config files, never auto-restart services (needrestart).
APT_ENV = [
    "env",
    "DEBIAN_FRONTEND=noninteractive",
    "NEEDRESTART_MODE=l",
    "APT_LISTCHANGES_FRONTEND=none",
]
APT_OPTS = ["-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef"]


def apt_available(ctx: AuditContext) -> bool:
    return not ctx.runner(["apt-get", "--version"]).missing


def is_installed(ctx: AuditContext, package: str) -> bool:
    proc = ctx.runner(["dpkg-query", "-W", "-f=${Status}", package])
    return proc.ok and proc.stdout.strip() == "install ok installed"


def _error(proc) -> str:
    lines = (proc.stderr or proc.stdout).strip().splitlines()
    if proc.timed_out:
        return "command timed out"
    return (lines[-1] if lines else "apt-get failed")[:200]


def update_index(ctx: AuditContext) -> str | None:
    proc = ctx.runner([*APT_ENV, "apt-get", "update"], timeout=PACKAGE_TIMEOUT)
    return None if proc.ok else _error(proc)


def install(ctx: AuditContext, packages: list[str]) -> str | None:
    bad = [p for p in packages if p not in INSTALLABLE]
    if bad:
        return f"package not allowed: {bad[0]}"
    proc = ctx.runner(
        [*APT_ENV, "apt-get", "install", *APT_OPTS, "--no-install-recommends", *packages],
        timeout=PACKAGE_TIMEOUT,
    )
    return None if proc.ok else _error(proc)


def upgrade_only(ctx: AuditContext, packages: list[str]) -> str | None:
    if not packages or any(not PKG_NAME.match(p) for p in packages):
        return "invalid package list"
    proc = ctx.runner(
        [*APT_ENV, "apt-get", "install", *APT_OPTS, "--only-upgrade", *packages],
        timeout=PACKAGE_TIMEOUT,
    )
    return None if proc.ok else _error(proc)
