"""Docker checks (read-only). Findings only: containers are never modified or restarted."""

from __future__ import annotations

import json
import stat as stat_mod
from pathlib import Path

from reviveguard.checks.common import result, skipped
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity
from reviveguard.ssh_access import read_groups

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH", "NET_ADMIN"}
SENSITIVE_MOUNTS = (
    "/",
    "/etc",
    "/root",
    "/boot",
    "/proc",
    "/sys",
    "/var/lib/docker",
    "/var/run/docker.sock",
    "/run/docker.sock",
)
SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")


def _names(items: list[dict], pick) -> list[str]:
    return sorted(i.get("Name", "?").lstrip("/") for i in items if pick(i))


def _mount_sources(item: dict) -> list[str]:
    host = item.get("HostConfig") or {}
    sources = [b.split(":")[0] for b in host.get("Binds") or []]
    sources += [m.get("Source", "") for m in item.get("Mounts") or [] if m.get("Type") == "bind"]
    return sources


def inspect_containers(ctx: AuditContext) -> list[dict] | None:
    ids = ctx.runner(["docker", "ps", "-q"])
    if not ids.ok:
        return None
    wanted = ids.stdout.split()
    if not wanted:
        return []
    proc = ctx.runner(["docker", "inspect", *wanted])
    try:
        data = json.loads(proc.stdout) if proc.ok else None
    except ValueError:
        return None
    return data if isinstance(data, list) else None


def run(ctx: AuditContext) -> list[CheckResult]:
    if ctx.runner(["docker", "--version"]).missing:
        return [skipped("docker", "DOC-000", "docker.not_installed")]
    results: list[CheckResult] = []
    for sock in SOCKETS:
        path = ctx.path(sock)
        if path.exists():
            try:
                mode = stat_mod.S_IMODE(ctx.stat(Path(path)).st_mode)
            except OSError:
                break
            bad = bool(mode & 0o006)
            results.append(
                result(
                    "docker",
                    "DOC-001",
                    "socket",
                    Severity.HIGH,
                    bad,
                    [f"{sock}: mode {mode:04o}" + (" (accessible by everyone)" if bad else "")],
                )
            )
            break
    members = sorted(read_groups(ctx).get("docker", (0, set()))[1])
    results.append(
        result(
            "docker",
            "DOC-002",
            "group",
            Severity.LOW,
            bool(members),
            [f"members of the 'docker' group (root-equivalent): {', '.join(members)}"]
            if members
            else ["the docker group has no members"],
        )
    )
    exposed = []
    daemon = ctx.read_text("/etc/docker/daemon.json")
    try:
        hosts = (json.loads(daemon).get("hosts") or []) if daemon else []
    except (ValueError, AttributeError):
        hosts = []
    for host in hosts:
        if host.startswith("tcp://") and not host.startswith(("tcp://127.", "tcp://localhost")):
            exposed.append(f"daemon.json hosts: {host}")
    results.append(
        result(
            "docker",
            "DOC-003",
            "api",
            Severity.HIGH,
            bool(exposed),
            exposed or ["the API is not exposed on a network address"],
        )
    )
    if not ctx.running_as_root:
        return [*results, skipped("docker", "DOC-000", "docker.needs_root")]
    containers = inspect_containers(ctx)
    if containers is None:
        return [*results, skipped("docker", "DOC-000", "docker.unreadable")]

    def host_cfg(item: dict) -> dict:
        return item.get("HostConfig") or {}

    checks = [
        ("DOC-004", "privileged", Severity.HIGH, lambda i: bool(host_cfg(i).get("Privileged"))),
        (
            "DOC-005",
            "host_network",
            Severity.MEDIUM,
            lambda i: host_cfg(i).get("NetworkMode") == "host",
        ),
        (
            "DOC-006",
            "capabilities",
            Severity.MEDIUM,
            lambda i: bool(DANGEROUS_CAPS & {c.upper() for c in host_cfg(i).get("CapAdd") or []}),
        ),
        (
            "DOC-007",
            "mounts",
            Severity.HIGH,
            lambda i: any(s.rstrip("/") in SENSITIVE_MOUNTS or s == "/" for s in _mount_sources(i)),
        ),
        (
            "DOC-008",
            "root_user",
            Severity.LOW,
            lambda i: (i.get("Config") or {}).get("User", "") in ("", "root", "0"),
        ),
    ]
    for check_id, name, severity, pick in checks:
        bad = _names(containers, pick)
        evidence = [f"containers: {', '.join(bad)}"] if bad else ["none"]
        results.append(result("docker", check_id, name, severity, bool(bad), evidence))
    return results
