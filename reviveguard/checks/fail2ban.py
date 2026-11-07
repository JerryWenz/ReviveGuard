"""Fail2ban checks (read-only). Reading jail state needs root (client socket)."""

from __future__ import annotations

import re

from reviveguard.checks.ssh import effective_config
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity, Status

MIN_BANTIME = 600  # seconds; shorter bans barely slow brute force
MAX_RETRY = 10
JAIL = "sshd"


def parse_jail_list(text: str) -> list[str]:
    match = re.search(r"Jail list:\s*(.*)", text)
    return [j.strip() for j in match.group(1).split(",") if j.strip()] if match else []


def parse_logpaths(text: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(r"^[|`]-\s*(/\S+)", text, re.M)]


def ssh_server_present(ctx: AuditContext) -> bool:
    return ctx.read_text("/etc/ssh/sshd_config") is not None


def ssh_port(ctx: AuditContext) -> str:
    found = effective_config(ctx)
    port = (found[0].get("port", "22") if found else "22").split()[0]
    return port if port.isdigit() else "22"


def _result(
    check_id: str, name: str, severity: Severity, failed: bool, evidence: list[str]
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category="fail2ban",
        severity=severity if failed else Severity.INFO,
        status=Status.FAIL if failed else Status.OK,
        title_key=f"fail2ban.{name}.title",
        description_key=f"fail2ban.{name}.desc",
        remediation_key=f"fail2ban.{name}.fix",
        evidence=tuple(evidence),
        auto_fix_supported=False,
    )


def _skipped(reason_key: str) -> list[CheckResult]:
    return [
        CheckResult(
            check_id="F2B-000",
            category="fail2ban",
            severity=Severity.INFO,
            status=Status.SKIPPED,
            title_key="fail2ban.module.title",
            description_key=reason_key,
            remediation_key="remediation.none",
        )
    ]


def _get(ctx: AuditContext, key: str) -> str | None:
    proc = ctx.runner(["fail2ban-client", "get", JAIL, key])
    return proc.stdout.strip() if proc.ok else None


def run(ctx: AuditContext) -> list[CheckResult]:
    if not ctx.running_as_root:
        return _skipped("fail2ban.needs_root")
    installed = not ctx.runner(["fail2ban-client", "--version"]).missing
    active = installed and ctx.runner(["systemctl", "is-active", "fail2ban"]).ok
    if not installed:
        return [_result("F2B-001", "running", Severity.MEDIUM, True, ["fail2ban is not installed"])]
    if not active:
        return [_result("F2B-001", "running", Severity.MEDIUM, True, ["service is not active"])]
    results = [_result("F2B-001", "running", Severity.MEDIUM, False, ["service is active"])]

    valid = ctx.runner(["fail2ban-client", "-t"])
    detail = (valid.stderr or valid.stdout).strip().splitlines()
    results.append(
        _result(
            "F2B-003",
            "config_valid",
            Severity.MEDIUM,
            not valid.ok,
            ["configuration test passed"]
            if valid.ok
            else detail[:1] or ["configuration test failed"],
        )
    )
    if not ssh_server_present(ctx):
        return results  # nothing to protect with an SSH jail

    status = ctx.runner(["fail2ban-client", "status"])
    if not status.ok:
        return results + _skipped("fail2ban.unreadable")
    jails = parse_jail_list(status.stdout)
    has_jail = JAIL in jails
    results.append(
        _result(
            "F2B-002",
            "ssh_jail",
            Severity.MEDIUM,
            not has_jail,
            [f"active jails: {', '.join(jails) or 'none'}"],
        )
    )
    if not has_jail:
        return results

    backend = _get(ctx, "backend")
    if backend is not None:
        if backend == "systemd":
            has_log = not ctx.runner(["journalctl", "--version"]).missing
            evidence = ["backend: systemd" + ("" if has_log else " (journalctl missing)")]
        else:
            paths = parse_logpaths(_get(ctx, "logpath") or "")
            has_log = any(ctx.path(p).is_file() for p in paths)
            evidence = [f"backend: {backend}", f"log files: {', '.join(paths) or 'none'}"]
        results.append(_result("F2B-004", "log_backend", Severity.MEDIUM, not has_log, evidence))

    values = {k: _get(ctx, k) for k in ("bantime", "findtime", "maxretry")}
    try:
        bantime, maxretry = int(values["bantime"] or ""), int(values["maxretry"] or "")
    except ValueError:
        return results  # cannot read ban settings: do not guess
    weak = maxretry > MAX_RETRY or 0 <= bantime < MIN_BANTIME  # negative bantime = permanent
    results.append(
        _result(
            "F2B-005",
            "ban_settings",
            Severity.LOW,
            weak,
            [f"bantime={bantime}s, findtime={values['findtime']}, maxretry={maxretry}"],
        )
    )
    return results
