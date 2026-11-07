"""System update checks (read-only): index freshness, security updates, reboot, auto-updates.

Security updates are told apart from ordinary updates by the ``-security`` archive pocket
(Debian ``bookworm-security``, Ubuntu ``jammy-security``/``jammy-infra-security``).
"""

from __future__ import annotations

import re
import time

from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.packages import PKG_NAME, is_installed

STALE_DAYS = 7
_UPGRADABLE = re.compile(r"^(?P<name>[^/\s]+)/(?P<pocket>\S+)\s")


def parse_upgradable(text: str) -> tuple[list[str], list[str]]:
    """Return (security package names, other package names) from ``apt list --upgradable``."""
    security, other = [], []
    for line in text.splitlines():
        m = _UPGRADABLE.match(line)
        if not m or not PKG_NAME.match(m["name"]):
            continue
        (security if "-security" in m["pocket"] else other).append(m["name"])
    return security, other


def index_age_days(ctx: AuditContext) -> float | None:
    """Age of the newest apt index file, or None if the index was never downloaded."""
    candidates = [ctx.path("/var/lib/apt/periodic/update-success-stamp")]
    lists = ctx.path("/var/lib/apt/lists")
    if lists.is_dir():
        candidates += [p for p in lists.iterdir() if p.is_file() and p.name != "lock"]
    mtimes = []
    for path in candidates:
        try:
            mtimes.append(path.stat().st_mtime)
        except OSError:
            continue
    return (time.time() - max(mtimes)) / 86400 if mtimes else None


def security_packages(ctx: AuditContext) -> list[str]:
    proc = ctx.runner(["apt", "list", "--upgradable"])
    return parse_upgradable(proc.stdout)[0] if proc.ok else []


def _result(
    check_id: str,
    name: str,
    severity: Severity,
    failed: bool,
    evidence: list[str],
    reboot: bool = False,
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category="updates",
        severity=severity if failed else Severity.INFO,
        status=Status.FAIL if failed else Status.OK,
        title_key=f"updates.{name}.title",
        description_key=f"updates.{name}.desc",
        remediation_key=f"updates.{name}.fix",
        evidence=tuple(evidence),
        reboot_required=reboot and failed,
    )


def _skipped(check_id: str, reason_key: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category="updates",
        severity=Severity.INFO,
        status=Status.SKIPPED,
        title_key="updates.module.title",
        description_key=reason_key,
        remediation_key="remediation.none",
    )


def run(ctx: AuditContext) -> list[CheckResult]:
    results = [
        _result(
            "UPD-005",
            "os_supported",
            Severity.MEDIUM,
            not ctx.os_info.is_supported,
            [f"{ctx.os_info.id} {ctx.os_info.version_id}".strip()],
        )
    ]
    if ctx.runner(["apt-get", "--version"]).missing:
        return results + [_skipped("UPD-000", "updates.no_apt")]

    age = index_age_days(ctx)
    stale = age is None or age > STALE_DAYS
    results.insert(
        0,
        _result(
            "UPD-001",
            "index_fresh",
            Severity.MEDIUM,
            stale,
            ["package index was never downloaded"]
            if age is None
            else [f"package index is {age:.0f} day(s) old"],
        ),
    )
    if stale:
        results.append(_skipped("UPD-002", "updates.index_stale"))
    else:
        proc = ctx.runner(["apt", "list", "--upgradable"])
        if proc.ok:
            security, other = parse_upgradable(proc.stdout)
            shown = ", ".join(security[:10]) + (" ..." if len(security) > 10 else "")
            results.append(
                _result(
                    "UPD-002",
                    "security_updates",
                    Severity.HIGH,
                    bool(security),
                    [
                        f"security updates: {len(security)}" + (f" ({shown})" if security else ""),
                        f"other updates: {len(other)}",
                    ],
                )
            )
        else:
            results.append(_skipped("UPD-002", "updates.unreadable"))

    reboot = (
        ctx.path("/var/run/reboot-required").exists() or ctx.path("/run/reboot-required").exists()
    )
    pkgs = (ctx.read_text("/var/run/reboot-required.pkgs") or "").split()[:5]
    results.append(
        _result(
            "UPD-003",
            "reboot",
            Severity.MEDIUM,
            reboot,
            ["reboot required" + (f" by: {', '.join(pkgs)}" if pkgs else "")]
            if reboot
            else ["no reboot pending"],
            reboot=True,
        )
    )
    cfg = ctx.runner(["apt-config", "dump", "APT::Periodic"]).stdout
    enabled = bool(re.search(r'Unattended-Upgrade\s+"1"', cfg))
    installed = is_installed(ctx, "unattended-upgrades")
    results.append(
        _result(
            "UPD-004",
            "auto_updates",
            Severity.MEDIUM,
            not (enabled and installed),
            [f"unattended-upgrades installed: {installed}, enabled: {enabled}"],
        )
    )
    return results
