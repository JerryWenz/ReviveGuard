"""Audit engine: runs enabled checks and isolates their failures."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from reviveguard.checks import REGISTRY
from reviveguard.config import Config
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity, Status


@dataclass
class AuditReport:
    results: list[CheckResult]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    modules: list[str] = field(default_factory=list)

    def count_by_severity(self) -> dict[Severity, int]:
        counts = {sev: 0 for sev in sorted(Severity, reverse=True)}
        for r in self.results:
            if r.status is Status.FAIL:
                counts[r.severity] += 1
        return counts

    def count_status(self, status: Status) -> int:
        return sum(1 for r in self.results if r.status is status)


def run_audit(ctx: AuditContext, config: Config) -> AuditReport:
    """Run every enabled, implemented check module. Read-only by contract."""
    results: list[CheckResult] = []
    modules: list[str] = []
    for name in config.audit.enabled_modules():
        check = REGISTRY.get(name)
        if check is None:
            continue  # configured but not implemented yet
        modules.append(name)
        try:
            results.extend(check(ctx))
        except Exception as exc:  # a broken check must not abort the audit
            results.append(
                CheckResult(
                    check_id=f"{name.upper()}-ERR",
                    category=name,
                    severity=Severity.INFO,
                    status=Status.ERROR,
                    title_key=f"{name}.module.title",
                    description_key="scanner.check_error",
                    remediation_key="remediation.none",
                    evidence=(type(exc).__name__,),
                )
            )
    return AuditReport(results=results, modules=modules)
