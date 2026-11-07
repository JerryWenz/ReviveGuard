"""Kernel (sysctl) hardening checks, read from /proc/sys.

Routing-related settings are judged in context: forwarding is expected on Docker/VPN hosts,
and reverse-path filtering is only recommended (it can break asymmetric routing and VPNs).
"""

from __future__ import annotations

from dataclasses import dataclass

from reviveguard.checks.common import result, skipped
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity


@dataclass(frozen=True)
class Param:
    check_id: str
    name: str
    severity: Severity
    keys: tuple[str, ...]  # all must satisfy the predicate
    ok: tuple[int, ...]  # acceptable values
    set_to: int | None  # value a fix writes (None: recommendation only)


PARAMS = [
    Param("SYS-001", "ip_forward", Severity.LOW, ("net.ipv4.ip_forward",), (0,), None),
    Param(
        "SYS-002",
        "accept_redirects",
        Severity.MEDIUM,
        ("net.ipv4.conf.all.accept_redirects", "net.ipv6.conf.all.accept_redirects"),
        (0,),
        0,
    ),
    Param(
        "SYS-003",
        "source_route",
        Severity.MEDIUM,
        ("net.ipv4.conf.all.accept_source_route", "net.ipv6.conf.all.accept_source_route"),
        (0,),
        0,
    ),
    Param("SYS-004", "syncookies", Severity.MEDIUM, ("net.ipv4.tcp_syncookies",), (1,), 1),
    Param("SYS-005", "kptr_restrict", Severity.LOW, ("kernel.kptr_restrict",), (1, 2), 1),
    Param("SYS-006", "dmesg_restrict", Severity.LOW, ("kernel.dmesg_restrict",), (1,), 1),
    Param("SYS-007", "aslr", Severity.HIGH, ("kernel.randomize_va_space",), (2,), 2),
    Param("SYS-008", "rp_filter", Severity.LOW, ("net.ipv4.conf.all.rp_filter",), (1, 2), None),
]
ROUTING_MARKERS = ("/var/run/docker.sock", "/run/docker.sock", "/etc/wireguard", "/etc/openvpn")


def read_value(ctx: AuditContext, key: str) -> int | None:
    text = ctx.read_text("/proc/sys/" + key.replace(".", "/"))
    try:
        return int((text or "").strip())
    except ValueError:
        return None


def is_container(ctx: AuditContext) -> bool:
    proc = ctx.runner(["systemd-detect-virt", "--container"])
    return proc.ok and proc.stdout.strip() not in ("", "none")


def run(ctx: AuditContext) -> list[CheckResult]:
    if is_container(ctx):
        return [skipped("sysctl", "SYS-000", "sysctl.container")]
    routing_host = any(ctx.path(m).exists() for m in ROUTING_MARKERS)
    results = []
    for p in PARAMS:
        values = {k: read_value(ctx, k) for k in p.keys}
        known = {k: v for k, v in values.items() if v is not None}
        if not known:
            continue  # parameter not present on this kernel
        bad = {k: v for k, v in known.items() if v not in p.ok}
        evidence = [f"{k} = {v}" for k, v in known.items()]
        if p.check_id == "SYS-001" and bad and routing_host:
            bad, evidence = {}, [*evidence, "forwarding expected: Docker/VPN detected"]
        results.append(result("sysctl", p.check_id, p.name, p.severity, bool(bad), evidence))
    return results
