from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from reviveguard.backup import Store
from reviveguard.checks import tuning
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.fixes import tuning as fixes
from reviveguard.models import Severity, Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import FakeRunner


def put(root: Path, path: str, text: str) -> Path:
    p = root / path.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def meminfo(total_kb: int, swap_kb: int = 0) -> str:
    return (
        f"MemTotal:  {total_kb} kB\nMemFree: 100 kB\n"
        f"SwapTotal: {swap_kb} kB\nSwapFree: {swap_kb} kB\n"
    )


class TuneHost:
    """Fake kernel interface: /proc/sys files, sysctl, modprobe, swap tools, ip, stat."""

    def __init__(self, root, fs="ext2/ext3", ipv4="2: eth0 inet 203.0.113.5/24\n", fail=()):
        self.root, self.fs, self.ipv4, self.fail = root, fs, ipv4, set(fail)
        self.calls: list[list[str]] = []

    def proc(self, key):
        return (self.root / "proc/sys" / key.replace(".", "/")).read_text().strip()

    def set_proc(self, key, value):
        put(self.root, "/proc/sys/" + key.replace(".", "/"), f"{value}\n")

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        name = args[0]
        if name in self.fail:
            return CommandResult(tuple(args), 1, "", f"{name}: boom")
        ok = CommandResult(tuple(args), 0)
        if args == ["systemd-detect-virt", "--container"]:
            return CommandResult(tuple(args), 1, "none")
        if name == "modprobe":
            put(
                self.root, "/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr\n"
            )
            return ok
        if args[:2] == ["sysctl", "-p"]:
            for line in Path(args[2]).read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    self.set_proc(key.strip(), value.strip())
            return ok
        if args[:2] == ["sysctl", "-w"]:
            key, _, value = args[2].partition("=")
            self.set_proc(key, value)
            return ok
        if args[:3] == ["ip", "-4", "-o"]:
            return CommandResult(tuple(args), 0, self.ipv4)
        if name == "stat":
            return CommandResult(tuple(args), 0, self.fs + "\n")
        if name == "fallocate":
            Path(args[3]).write_bytes(b"\0" * 16)
            return ok
        if name == "dd":
            Path(args[2][3:]).write_bytes(b"\0" * 16)
            return ok
        if name == "swapon":
            put(self.root, "/proc/swaps", f"Filename Type\n{args[1]} file\n")
            put(self.root, "/proc/meminfo", meminfo(1_000_000, 2_097_152))
            return ok
        if name == "swapoff":
            put(self.root, "/proc/swaps", "Filename Type\n")
            put(self.root, "/proc/meminfo", meminfo(1_000_000, 0))
            return ok
        if name == "mkswap":
            return ok
        return CommandResult(tuple(args), None, missing=True)


def by_id(results):
    return {r.check_id: r for r in results}


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


@pytest.fixture
def kernel(fake_root):
    """A small server: reno, IPv6 on, 1 GB RAM, no swap."""
    host = TuneHost(fake_root)
    put(fake_root, "/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n")
    put(fake_root, "/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic\n")
    put(fake_root, "/proc/sys/net/core/default_qdisc", "pfifo_fast\n")
    put(fake_root, "/proc/sys/net/ipv6/conf/all/disable_ipv6", "0\n")
    put(fake_root, "/proc/net/if_inet6", "2001db8000000000000000000000001 02 40 00 80 eth0\n")
    put(fake_root, "/proc/meminfo", meminfo(1_000_000))
    put(fake_root, "/proc/sys/kernel/osrelease", "6.1.0\n")
    put(fake_root, "/proc/swaps", "Filename Type\n")
    put(fake_root, "/etc/fstab", "UUID=abc / ext4 defaults 0 1\n")
    return host


# ---------------- checks ----------------


def test_small_server_gets_three_low_findings(make_ctx, kernel):
    # BBR is not available here yet (only reno/cubic, no module): that one is skipped
    res = by_id(tuning.run(make_ctx(runner=kernel)))
    assert res["TUN-001"].status is Status.SKIPPED
    assert res["TUN-002"].status is Status.FAIL and res["TUN-002"].severity is Severity.LOW
    assert "1 global" in res["TUN-002"].evidence[0]
    assert res["TUN-003"].status is Status.FAIL and "1000000" not in res["TUN-003"].evidence[0]
    assert "memory: 976 MiB, swap: 0 MiB" in res["TUN-003"].evidence[0]


def test_bbr_states(make_ctx, kernel, fake_root):
    put(fake_root, "/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr\n")
    assert by_id(tuning.run(make_ctx(runner=kernel)))["TUN-001"].status is Status.FAIL
    put(fake_root, "/proc/sys/net/ipv4/tcp_congestion_control", "bbr\n")
    assert by_id(tuning.run(make_ctx(runner=kernel)))["TUN-001"].status is Status.OK
    put(fake_root, "/proc/sys/net/ipv4/tcp_congestion_control", "cubic\n")
    put(fake_root, "/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic\n")
    mod = fake_root / "lib/modules/6.1.0/kernel/net/ipv4"
    mod.mkdir(parents=True)
    (mod / "tcp_bbr.ko.xz").write_text("")
    assert by_id(tuning.run(make_ctx(runner=kernel)))["TUN-001"].status is Status.FAIL


def test_ipv6_disabled_is_ok_and_absent_is_ignored(make_ctx, kernel, fake_root):
    put(fake_root, "/proc/sys/net/ipv6/conf/all/disable_ipv6", "1\n")
    assert by_id(tuning.run(make_ctx(runner=kernel)))["TUN-002"].status is Status.OK
    (fake_root / "proc/sys/net/ipv6/conf/all/disable_ipv6").unlink()
    assert "TUN-002" not in by_id(tuning.run(make_ctx(runner=kernel)))


def test_swap_findings_depend_on_memory_and_swap(make_ctx, kernel, fake_root):
    put(fake_root, "/proc/meminfo", meminfo(1_000_000, 2_097_152))
    assert by_id(tuning.run(make_ctx(runner=kernel)))["TUN-003"].status is Status.OK
    put(fake_root, "/proc/meminfo", meminfo(8_000_000))  # plenty of RAM, no swap: fine
    res = by_id(tuning.run(make_ctx(runner=kernel)))["TUN-003"]
    assert res.status is Status.OK and "swap: 0 MiB" in res.evidence[0]
    (fake_root / "proc/meminfo").unlink()
    assert "TUN-003" not in by_id(tuning.run(make_ctx(runner=kernel)))


def test_containers_are_skipped(make_ctx, kernel):
    runner = FakeRunner({("systemd-detect-virt", "--container"): CommandResult(("x",), 0, "lxc\n")})
    res = tuning.run(make_ctx(runner=runner))
    assert [r.check_id for r in res] == ["TUN-000"] and res[0].status is Status.SKIPPED


def test_audit_is_read_only(make_ctx, kernel):
    tuning.run(make_ctx(runner=kernel))
    assert all(c[0] == "systemd-detect-virt" for c in kernel.calls)


# ---------------- BBR fix ----------------


def failing(ctx, check_id):
    return next(r for r in tuning.run(ctx) if r.check_id == check_id)


def test_bbr_fix_enables_and_persists(make_ctx, kernel, fake_root, store):
    put(fake_root, "/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr\n")
    ctx = make_ctx(runner=kernel)
    spec = REGISTRY["TUN-001"](ctx, failing(ctx, "TUN-001"))
    assert isinstance(spec, FixSpec) and not spec.disruptive and "TUN-001" in AUTOMATIC
    assert run_fix(store, ctx, spec).status == "applied"
    assert kernel.proc("net.ipv4.tcp_congestion_control") == "bbr"
    assert kernel.proc("net.core.default_qdisc") == "fq"
    assert (
        "net.ipv4.tcp_congestion_control = bbr"
        in (fake_root / "etc/sysctl.d/99-reviveguard-bbr.conf").read_text()
    )
    assert "tcp_bbr" in (fake_root / "etc/modules-load.d/reviveguard-bbr.conf").read_text()
    assert ["modprobe", "tcp_bbr"] in kernel.calls


def test_bbr_failure_reverts_files_and_restores_the_running_values(
    make_ctx, kernel, fake_root, store
):
    put(fake_root, "/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr\n")
    ctx = make_ctx(runner=kernel)
    spec = REGISTRY["TUN-001"](ctx, failing(ctx, "TUN-001"))
    spec.verify = lambda: "BBR is not active"  # e.g. the kernel refused the value
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "verify_failed" and outcome.revert_ok
    assert kernel.proc("net.ipv4.tcp_congestion_control") == "cubic"  # undo restored it
    assert kernel.proc("net.core.default_qdisc") == "pfifo_fast"
    assert not (fake_root / "etc/sysctl.d/99-reviveguard-bbr.conf").exists()


def test_bbr_refused_when_the_kernel_has_none(make_ctx, kernel):
    ctx = make_ctx(runner=kernel)
    from reviveguard.models import CheckResult

    r = CheckResult("TUN-001", "tuning", Severity.LOW, Status.FAIL, "t", "d", "r")
    plan = REGISTRY["TUN-001"](ctx, r)
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.bbr_unavailable"


# ---------------- IPv6 fix ----------------


def ipv6_spec(make_ctx, kernel, env=None):
    ctx = make_ctx(runner=kernel, env=env or {"SSH_CONNECTION": "203.0.113.9 5555 203.0.113.5 22"})
    return ctx, REGISTRY["TUN-002"](ctx, failing(ctx, "TUN-002"))


def test_ipv6_fix_needs_live_confirmation_and_applies(make_ctx, kernel, store):
    ctx, spec = ipv6_spec(make_ctx, kernel)
    assert isinstance(spec, FixSpec) and spec.disruptive and spec.confirm_key == "fix.confirm.ipv6"
    assert run_fix(store, ctx, spec, confirm=lambda s: True).status == "applied"
    assert kernel.proc("net.ipv6.conf.all.disable_ipv6") == "1"
    assert kernel.proc("net.ipv6.conf.default.disable_ipv6") == "1"


def test_declined_ipv6_confirmation_switches_ipv6_back_on(make_ctx, kernel, fake_root, store):
    ctx, spec = ipv6_spec(make_ctx, kernel)
    outcome = run_fix(store, ctx, spec, confirm=lambda s: False)
    assert outcome.status == "confirmation_failed" and outcome.revert_ok
    assert kernel.proc("net.ipv6.conf.all.disable_ipv6") == "0"  # the undo hook ran
    assert not (fake_root / "etc/sysctl.d/99-reviveguard-ipv6.conf").exists()


@pytest.mark.parametrize(
    ("env", "reason"),
    [
        ({"SSH_CONNECTION": "2001:db8::9 5555 2001:db8::5 22"}, "fix.reason.ipv6_session"),
        ({"SSH_CONNECTION": "203.0.113.9 5555 2001:db8::5 22"}, "fix.reason.ipv6_session"),
        ({"SSH_CLIENT": "2001:db8::9 5555 22"}, "fix.reason.ipv6_session"),
    ],
)
def test_ipv6_refused_when_the_session_uses_ipv6(make_ctx, kernel, env, reason):
    _, plan = ipv6_spec(make_ctx, kernel, env)
    assert isinstance(plan, Manual) and plan.reason_key == reason


def test_ipv6_refused_for_an_ipv6_only_host_or_unknown_state(make_ctx, kernel):
    kernel.ipv4 = ""
    _, plan = ipv6_spec(make_ctx, kernel)
    assert plan.reason_key == "fix.reason.ipv6_only"
    ctx = make_ctx(runner=FakeRunner(), env={})
    from reviveguard.models import CheckResult

    r = CheckResult("TUN-002", "tuning", Severity.LOW, Status.FAIL, "t", "d", "r")
    assert REGISTRY["TUN-002"](ctx, r).reason_key == "fix.reason.ipv6_unknown"


def test_ipv6_is_not_part_of_the_automatic_set_without_confirmation(make_ctx, kernel):
    from reviveguard.config import Config
    from reviveguard.fixflow import Item, auto_block_reason

    ctx, spec = ipv6_spec(make_ctx, kernel)
    item = Item(failing(ctx, "TUN-002"), spec)
    assert auto_block_reason(Config(), item) == "fix.auto.skip_disruptive"


# ---------------- swap fix ----------------


def swap_spec(make_ctx, kernel):
    ctx = make_ctx(runner=kernel)
    return ctx, REGISTRY["TUN-003"](ctx, failing(ctx, "TUN-003"))


def test_swap_fix_creates_a_private_persistent_swap_file(make_ctx, kernel, fake_root, store):
    ctx, spec = swap_spec(make_ctx, kernel)
    assert isinstance(spec, FixSpec) and not spec.disruptive and "TUN-003" in AUTOMATIC
    assert run_fix(store, ctx, spec).status == "applied"
    swapfile = fake_root / "swapfile"
    assert swapfile.exists() and stat.S_IMODE(swapfile.stat().st_mode) == 0o600
    assert (fake_root / "etc/fstab").read_text().splitlines() == [
        "UUID=abc / ext4 defaults 0 1",
        "/swapfile none swap sw 0 0",
    ]
    assert "vm.swappiness = 10" in (fake_root / "etc/sysctl.d/99-reviveguard-swap.conf").read_text()
    assert kernel.proc("vm.swappiness") == "10"
    assert by_id(tuning.run(ctx))["TUN-003"].status is Status.OK
    assert ["swapon", str(swapfile)] in kernel.calls


def test_swap_fstab_entry_is_not_duplicated_and_fstab_may_be_missing(
    make_ctx, kernel, fake_root, store
):
    (fake_root / "etc/fstab").write_text(
        "UUID=abc / ext4 defaults 0 1\n/swapfile none swap sw 0 0\n"
    )
    ctx, spec = swap_spec(make_ctx, kernel)
    assert run_fix(store, ctx, spec).status == "applied"
    assert (fake_root / "etc/fstab").read_text().count("/swapfile") == 1


def test_swap_works_without_an_fstab(make_ctx, kernel, fake_root, store):
    (fake_root / "etc/fstab").unlink()
    ctx, spec = swap_spec(make_ctx, kernel)
    assert run_fix(store, ctx, spec).status == "applied"
    assert (fake_root / "etc/fstab").read_text() == "/swapfile none swap sw 0 0\n"


def test_swap_falls_back_to_dd_when_fallocate_fails(make_ctx, kernel, fake_root, store):
    kernel.fail = {"fallocate"}
    ctx, spec = swap_spec(make_ctx, kernel)
    assert run_fix(store, ctx, spec).status == "applied"
    assert any(c[0] == "dd" for c in kernel.calls)


def test_a_failure_midway_removes_everything_it_created(make_ctx, kernel, fake_root, store):
    kernel.fail = {"swapon"}
    ctx, spec = swap_spec(make_ctx, kernel)
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "apply_failed" and outcome.revert_ok
    assert not (fake_root / "swapfile").exists()  # the undo hook deleted it
    assert (fake_root / "etc/fstab").read_text() == "UUID=abc / ext4 defaults 0 1\n"
    assert not (fake_root / "etc/sysctl.d/99-reviveguard-swap.conf").exists()
    assert ["swapoff", str(fake_root / "swapfile")] in kernel.calls


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ("exists", "fix.reason.swap_exists"),
        ("btrfs", "fix.reason.swap_fs"),
        ("space", "fix.reason.swap_space"),
    ],
)
def test_swap_refusals(make_ctx, kernel, fake_root, monkeypatch, setup, reason):
    ctx = make_ctx(runner=kernel)
    result = failing(ctx, "TUN-003")
    if setup == "exists":
        (fake_root / "swapfile").write_text("precious")
    elif setup == "btrfs":
        kernel.fs = "btrfs"
    else:
        monkeypatch.setattr(
            "reviveguard.fixes.tuning.shutil.disk_usage",
            lambda p: type("U", (), {"free": 500 * 1024 * 1024})(),
        )
    plan = REGISTRY["TUN-003"](ctx, result)
    assert isinstance(plan, Manual) and plan.reason_key == reason
    if setup == "exists":
        assert (fake_root / "swapfile").read_text() == "precious"  # never overwritten


def test_existing_swap_means_nothing_to_do(make_ctx, kernel, fake_root):
    ctx = make_ctx(runner=kernel)
    result = failing(ctx, "TUN-003")
    put(fake_root, "/proc/meminfo", meminfo(1_000_000, 524288))
    assert REGISTRY["TUN-003"](ctx, result).reason_key == "fix.reason.nothing_to_fix"


def test_config_flag_disables_the_module(make_ctx):
    from reviveguard.config import AuditConfig

    assert "tuning" in AuditConfig().enabled_modules()
    assert "tuning" not in AuditConfig(tuning=False).enabled_modules()
    assert os.path.basename(fixes.SWAPFILE) == "swapfile"
