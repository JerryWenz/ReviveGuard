"""Tuning fixes: enable BBR, disable IPv6, create a swap file (all guarded and confirmed).

Runtime effects that restoring files cannot undo (a loaded congestion control, a disabled IPv6
stack, an active swap file) are reversed by each spec's ``undo`` hook when a fix fails after it
was applied.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from reviveguard.checks.tuning import CC_PATH, IPV6_PATH, bbr_available, meminfo
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual, write_file_atomic
from reviveguard.ssh_access import current_connection, is_remote_session

SYSCTL_DIR = "/etc/sysctl.d"
BBR_SYSCTL = f"{SYSCTL_DIR}/99-reviveguard-bbr.conf"
BBR_MODULES = "/etc/modules-load.d/reviveguard-bbr.conf"
IPV6_SYSCTL = f"{SYSCTL_DIR}/99-reviveguard-ipv6.conf"
SWAP_SYSCTL = f"{SYSCTL_DIR}/99-reviveguard-swap.conf"
SWAPFILE = "/swapfile"
SWAP_MIB = 2048
HEADROOM_MIB = 1024
SWAP_BAD_FS = {"btrfs", "zfs", "tmpfs", "overlay", "overlayfs", "nfs", "fuseblk", "unknown"}
HEADER = "# Managed by ReviveGuard ({id}). Remove this file to undo (takes effect after reboot).\n"


def _run(ctx: AuditContext, args: list[str], timeout: int = 60) -> None:
    proc = ctx.runner(args, timeout=timeout)
    if not proc.ok:
        lines = (proc.stderr or proc.stdout).strip().splitlines() or ["failed"]
        raise RuntimeError(f"{' '.join(args[:3])}: {lines[0]}"[:200])


def _write(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_file_atomic(path, text, mode)


def _sysctl_text(check_id: str, settings: dict[str, str]) -> str:
    return HEADER.format(id=check_id) + "".join(f"{k} = {v}\n" for k, v in settings.items())


def _proc(ctx: AuditContext, key_path: str) -> str:
    return (ctx.read_text(key_path) or "").strip()


# ---------------- BBR ----------------


def plan_bbr(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    if not bbr_available(ctx):
        return Manual("fix.reason.bbr_unavailable")
    sysctl_path, modules_path = ctx.path(BBR_SYSCTL), ctx.path(BBR_MODULES)
    previous_cc = _proc(ctx, CC_PATH)
    previous_qdisc = _proc(ctx, "/proc/sys/net/core/default_qdisc")
    text = _sysctl_text(
        result.check_id,
        {"net.core.default_qdisc": "fq", "net.ipv4.tcp_congestion_control": "bbr"},
    )

    def apply() -> None:
        _write(sysctl_path, text)
        _write(modules_path, "# Managed by ReviveGuard (TUN-001)\ntcp_bbr\n")

    def activate() -> bool:
        return ctx.runner(["modprobe", "tcp_bbr"]).ok and (
            ctx.runner(["sysctl", "-p", str(sysctl_path)]).ok
        )

    def undo() -> None:
        for key, value in (
            ("net.ipv4.tcp_congestion_control", previous_cc),
            ("net.core.default_qdisc", previous_qdisc),
        ):
            if value:
                ctx.runner(["sysctl", "-w", f"{key}={value}"])

    return FixSpec(
        fix_id="tuning.bbr.enable",
        check_id=result.check_id,
        description="Enable BBR congestion control (fq + bbr) via sysctl and modules-load drop-ins",
        files=[sysctl_path, modules_path],
        apply=apply,
        validate=lambda: None,
        activate=activate,
        change_key="fix.tuning.bbr",
        verify=lambda: None if _proc(ctx, CC_PATH) == "bbr" else "BBR is not active",
        undo=undo,
        next_key="fix.next.bbr",
    )


# ---------------- IPv6 ----------------


def plan_ipv6(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    conn = current_connection(ctx)
    connected = (ctx.env.get("SSH_CONNECTION") or "").split()
    server_ip = connected[2] if len(connected) >= 3 else ""
    if (conn and ":" in conn[0]) or ":" in server_ip:
        return Manual("fix.reason.ipv6_session")  # you would cut the branch you sit on
    if is_remote_session(ctx) and conn is None:
        return Manual("fix.reason.ipv6_unknown")
    v4 = ctx.runner(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    if v4.missing:
        return Manual("fix.reason.ipv6_unknown")
    if not v4.stdout.strip():
        return Manual("fix.reason.ipv6_only")
    path = ctx.path(IPV6_SYSCTL)
    text = _sysctl_text(
        result.check_id,
        {"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"},
    )

    def undo() -> None:
        for key in ("all", "default"):
            ctx.runner(["sysctl", "-w", f"net.ipv6.conf.{key}.disable_ipv6=0"])

    return FixSpec(
        fix_id="tuning.ipv6.disable",
        check_id=result.check_id,
        description="Disable IPv6 (net.ipv6.conf.all/default.disable_ipv6 = 1) via sysctl drop-in",
        files=[path],
        apply=lambda: _write(path, text),
        validate=lambda: None,
        activate=lambda: ctx.runner(["sysctl", "-p", str(path)]).ok,
        change_key="fix.tuning.ipv6",
        service_key="fix.service.ipv6",
        disruptive=True,
        verify=lambda: None if _proc(ctx, IPV6_PATH) == "1" else "IPv6 is still enabled",
        undo=undo,
        confirm_key="fix.confirm.ipv6",
        next_key="fix.next.ipv6",
    )


# ---------------- swap file ----------------


def plan_swap(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    if meminfo(ctx).get("SwapTotal", 0) > 0:
        return Manual("fix.reason.nothing_to_fix")
    swap_path = ctx.path(SWAPFILE)
    if os.path.lexists(swap_path):
        return Manual("fix.reason.swap_exists")
    stat = ctx.runner(["stat", "-f", "-c", "%T", str(ctx.path("/"))])
    fs = stat.stdout.strip() if stat.ok and stat.stdout.strip() else "unknown"
    if fs in SWAP_BAD_FS:
        return Manual("fix.reason.swap_fs", {"fs": fs})
    free_mib = shutil.disk_usage(ctx.path("/")).free // (1024 * 1024)
    if free_mib < SWAP_MIB + HEADROOM_MIB:
        return Manual(
            "fix.reason.swap_space", {"need": str(SWAP_MIB + HEADROOM_MIB), "free": str(free_mib)}
        )
    fstab, sysctl_path = ctx.path("/etc/fstab"), ctx.path(SWAP_SYSCTL)
    fstab_line = f"{SWAPFILE} none swap sw 0 0"
    files = [fstab, sysctl_path]  # fstab may not exist yet: then rollback removes what we made

    def apply() -> None:
        proc = ctx.runner(["fallocate", "-l", f"{SWAP_MIB}M", str(swap_path)], timeout=300)
        if not proc.ok:  # e.g. a file system without fallocate: write the zeros instead
            _run(
                ctx,
                [
                    "dd",
                    "if=/dev/zero",
                    f"of={swap_path}",
                    "bs=1M",
                    f"count={SWAP_MIB}",
                    "status=none",
                ],
                timeout=900,
            )
        os.chmod(swap_path, 0o600)  # swap holds memory contents: root only
        _run(ctx, ["mkswap", str(swap_path)])
        _run(ctx, ["swapon", str(swap_path)])
        existing = fstab.read_text(encoding="utf-8") if fstab.is_file() else ""
        if not any(line.split()[:1] == [SWAPFILE] for line in existing.splitlines()):
            glue = "" if not existing or existing.endswith("\n") else "\n"
            mode = (fstab.stat().st_mode & 0o777) if fstab.is_file() else 0o644
            _write(fstab, f"{existing}{glue}{fstab_line}\n", mode)
        _write(sysctl_path, _sysctl_text(result.check_id, {"vm.swappiness": "10"}))

    def undo() -> None:
        ctx.runner(["swapoff", str(swap_path)])
        try:
            os.unlink(swap_path)
        except OSError:
            pass

    return FixSpec(
        fix_id="tuning.swap.create",
        check_id=result.check_id,
        description=f"Create a {SWAP_MIB} MiB swap file {SWAPFILE} (mode 0600), enable it, "
        "add it to /etc/fstab and set vm.swappiness = 10",
        files=files,
        apply=apply,
        validate=lambda: None,
        activate=lambda: ctx.runner(["sysctl", "-p", str(sysctl_path)]).ok,
        change_key="fix.tuning.swap",
        change_args={"size": str(SWAP_MIB), "path": SWAPFILE},
        verify=lambda: (
            None
            if str(swap_path) in (ctx.read_text("/proc/swaps") or "")
            else "the swap file is not active"
        ),
        undo=undo,
        next_key="fix.next.swap",
    )
