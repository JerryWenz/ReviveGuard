"""Server tuning checks (read-only): BBR congestion control, IPv6, swap.

These are optional improvements rather than vulnerabilities, so findings are LOW. Container
guests are skipped: the kernel (and its swap and network stack) belong to the host.
"""

from __future__ import annotations

import re

from reviveguard.checks.common import result, skipped
from reviveguard.checks.sysctl import is_container
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity

LOW_MEMORY_KB = 2_300_000  # "2 GB" VPS plans report ~1.9-2.0 GiB of usable memory
CC_PATH = "/proc/sys/net/ipv4/tcp_congestion_control"
CC_AVAILABLE = "/proc/sys/net/ipv4/tcp_available_congestion_control"
IPV6_PATH = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
IF_INET6 = "/proc/net/if_inet6"


def meminfo(ctx: AuditContext) -> dict[str, int]:
    info = {}
    for line in (ctx.read_text("/proc/meminfo") or "").splitlines():
        m = re.match(r"(\w+):\s+(\d+)\s*kB", line)
        if m:
            info[m.group(1)] = int(m.group(2))
    return info


def bbr_available(ctx: AuditContext) -> bool:
    if "bbr" in (ctx.read_text(CC_AVAILABLE) or "").split():
        return True
    release = ctx.read_text("/proc/sys/kernel/osrelease") or ""
    modules = ctx.path(f"/lib/modules/{release.strip()}/kernel/net/ipv4")
    return bool(release.strip()) and modules.is_dir() and any(modules.glob("tcp_bbr.ko*"))


def global_ipv6_addresses(ctx: AuditContext) -> int:
    """Number of global-scope IPv6 addresses (``/proc/net/if_inet6``: scope field ``00``)."""
    count = 0
    for line in (ctx.read_text(IF_INET6) or "").splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3] == "00":
            count += 1
    return count


def run(ctx: AuditContext) -> list[CheckResult]:
    if is_container(ctx):
        return [skipped("tuning", "TUN-000", "tuning.container")]
    results: list[CheckResult] = []

    current = (ctx.read_text(CC_PATH) or "").strip()
    if current:
        if current == "bbr":
            results.append(
                result("tuning", "TUN-001", "bbr", Severity.LOW, False, ["congestion control: bbr"])
            )
        elif bbr_available(ctx):
            evidence = [f"congestion control: {current}; BBR is available in this kernel"]
            results.append(result("tuning", "TUN-001", "bbr", Severity.LOW, True, evidence))
        else:
            results.append(skipped("tuning", "TUN-001", "tuning.bbr_unavailable"))

    disabled = (ctx.read_text(IPV6_PATH) or "").strip()
    if disabled in ("0", "1"):
        n = global_ipv6_addresses(ctx)
        evidence = [
            "IPv6 is disabled" if disabled == "1" else f"IPv6 is enabled ({n} global address(es))"
        ]
        results.append(result("tuning", "TUN-002", "ipv6", Severity.LOW, disabled == "0", evidence))

    info = meminfo(ctx)
    if "MemTotal" in info:
        mem_mib, swap_mib = info["MemTotal"] // 1024, info.get("SwapTotal", 0) // 1024
        low = info["MemTotal"] < LOW_MEMORY_KB
        evidence = [f"memory: {mem_mib} MiB, swap: {swap_mib} MiB"]
        results.append(
            result("tuning", "TUN-003", "swap", Severity.LOW, swap_mib == 0 and low, evidence)
        )
    return results
