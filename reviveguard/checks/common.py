"""Helpers shared by check modules."""

from __future__ import annotations

from reviveguard.models import CheckResult, Severity, Status


def result(
    category: str,
    check_id: str,
    name: str,
    severity: Severity,
    failed: bool,
    evidence: list[str],
    restart: bool = False,
    reboot: bool = False,
) -> CheckResult:
    """Build a pass/fail result whose texts live under ``<category>.<name>.title|desc|fix``."""
    return CheckResult(
        check_id=check_id,
        category=category,
        severity=severity if failed else Severity.INFO,
        status=Status.FAIL if failed else Status.OK,
        title_key=f"{category}.{name}.title",
        description_key=f"{category}.{name}.desc",
        remediation_key=f"{category}.{name}.fix",
        evidence=tuple(evidence),
        restart_required=restart and failed,
        reboot_required=reboot and failed,
    )


def skipped(category: str, check_id: str, reason_key: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category=category,
        severity=Severity.INFO,
        status=Status.SKIPPED,
        title_key=f"{category}.module.title",
        description_key=reason_key,
        remediation_key="remediation.none",
    )
