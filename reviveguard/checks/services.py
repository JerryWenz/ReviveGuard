"""Listening services and ports (read-only, via ``ss``). Nothing is ever stopped."""

from __future__ import annotations

import re
from dataclasses import dataclass

from reviveguard.checks.common import result, skipped
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity

PUBLIC_ADDRS = {"0.0.0.0", "::", "*", "[::]"}
# port -> (description, severity if reachable from everywhere)
RISKY = {
    21: ("FTP (plaintext)", Severity.MEDIUM),
    23: ("Telnet (plaintext)", Severity.HIGH),
    111: ("rpcbind (usually unnecessary)", Severity.MEDIUM),
    139: ("SMB/NetBIOS", Severity.MEDIUM),
    445: ("SMB", Severity.MEDIUM),
    161: ("SNMP", Severity.MEDIUM),
    631: ("CUPS printing (usually unnecessary)", Severity.LOW),
    2375: ("Docker API (unencrypted)", Severity.HIGH),
    2376: ("Docker API", Severity.MEDIUM),
    3306: ("MySQL/MariaDB", Severity.MEDIUM),
    3389: ("RDP", Severity.MEDIUM),
    5353: ("mDNS/Avahi (usually unnecessary)", Severity.LOW),
    5432: ("PostgreSQL", Severity.MEDIUM),
    5900: ("VNC", Severity.MEDIUM),
    6379: ("Redis (no auth by default)", Severity.HIGH),
    8006: ("Proxmox web UI", Severity.MEDIUM),
    8888: ("Jupyter", Severity.MEDIUM),
    9090: ("Cockpit/admin UI", Severity.MEDIUM),
    9200: ("Elasticsearch (no auth by default)", Severity.HIGH),
    10000: ("Webmin", Severity.MEDIUM),
    11211: ("Memcached", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
}


@dataclass(frozen=True)
class Listener:
    proto: str
    address: str
    port: int
    process: str

    @property
    def public(self) -> bool:
        return self.address in PUBLIC_ADDRS


def parse_ss(text: str) -> list[Listener]:
    listeners = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] not in ("tcp", "udp"):
            continue
        local = re.sub(r"%[^:\]]*", "", cols[4])  # drop the interface scope (127.0.0.53%lo)
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        listeners.append(
            Listener(
                cols[0],
                addr.strip("[]") if addr != "[::]" else "::",
                int(port),
                proc.group(1) if proc else "",
            )
        )
    return listeners


def _label(item: Listener) -> str:
    who = f" ({item.process})" if item.process else ""
    return f"{item.proto} {item.address}:{item.port}{who}"


def run(ctx: AuditContext) -> list[CheckResult]:
    proc = ctx.runner(["ss", "-H", "-tulnp"])
    if proc.missing:
        return [skipped("services", "SVC-000", "services.no_ss")]
    if not proc.ok:
        return [skipped("services", "SVC-000", "services.unreadable")]
    listeners = parse_ss(proc.stdout)
    unique = {(x.proto, x.port, x.address, x.process): x for x in listeners if x.public}
    public = sorted(unique.values(), key=lambda x: (x.port, x.proto))
    overview = [_label(x) for x in public] or ["no service listens on all interfaces"]
    results = [result("services", "SVC-001", "public", Severity.INFO, False, overview)]
    risky = [(x, RISKY[x.port]) for x in public if x.port in RISKY]
    severity = max((s for _, (_, s) in risky), default=Severity.LOW)
    evidence = [f"{_label(x)}: {why}" for x, (why, _) in risky] or ["none found"]
    results.append(result("services", "SVC-002", "risky", severity, bool(risky), evidence))
    return results
