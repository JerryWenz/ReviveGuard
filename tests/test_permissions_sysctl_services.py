from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from reviveguard import rollback
from reviveguard.backup import Store
from reviveguard.checks import permissions, services, sysctl
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.models import Severity, Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import FakeRunner


def by_id(results):
    return {r.check_id: r for r in results}


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


# ---------------- permissions ----------------


def put(root: Path, rel: str, mode: int, text="x"):
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)
    return p


def real_stat_as_root(path):
    st = os.stat(path)
    return SimpleNamespace(st_mode=st.st_mode, st_uid=0)


def test_permissions_all_ok(make_ctx, fake_root):
    put(fake_root, "/etc/passwd", 0o644)
    put(fake_root, "/etc/shadow", 0o640)
    put(fake_root, "/etc/sudoers", 0o440)
    ctx = make_ctx(stat=real_stat_as_root)
    assert all(r.status is Status.OK for r in permissions.run(ctx))


def test_world_readable_shadow_is_critical(make_ctx, fake_root):
    put(fake_root, "/etc/shadow", 0o644)
    res = by_id(permissions.run(make_ctx(stat=real_stat_as_root)))
    assert res["PERM-002"].status is Status.FAIL and res["PERM-002"].severity is Severity.CRITICAL
    assert "/etc/shadow: mode 0644 (max 0640)" in res["PERM-002"].evidence[0]


def test_wrong_owner_and_sudoers_d_glob(make_ctx, fake_root):
    put(fake_root, "/etc/passwd", 0o644)
    put(fake_root, "/etc/sudoers.d/90-custom", 0o666)
    put(fake_root, "/etc/sudoers.d/README", 0o666)  # ignored
    put(fake_root, "/etc/ssh/ssh_host_ed25519_key", 0o600)
    put(fake_root, "/etc/ssh/ssh_host_ed25519_key.pub", 0o644)  # public keys ignored
    ctx = make_ctx(stat=lambda p: SimpleNamespace(st_mode=os.stat(p).st_mode, st_uid=1000))
    res = by_id(permissions.run(ctx))
    assert res["PERM-001"].status is Status.FAIL and "uid 1000" in res["PERM-001"].evidence[0]
    assert len(res["PERM-003"].evidence) == 1 and "90-custom" in res["PERM-003"].evidence[0]
    assert ".pub" not in res["PERM-004"].evidence[0]


def test_missing_files_are_not_findings(make_ctx):
    assert all(r.status is Status.OK for r in permissions.run(make_ctx()))


def test_permission_fix_only_removes_bits_and_rolls_back(make_ctx, fake_root, store, monkeypatch):
    shadow = put(fake_root, "/etc/shadow", 0o666, "hashes")
    monkeypatch.setattr(os, "chown", lambda *a: None)
    ctx = make_ctx(stat=real_stat_as_root)
    failing = by_id(permissions.run(ctx))["PERM-002"]
    spec = REGISTRY["PERM-002"](ctx, failing)
    assert isinstance(spec, FixSpec) and not spec.disruptive
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied" and (shadow.stat().st_mode & 0o777) == 0o640
    assert rollback.execute_rollback(store, rollback.plan_rollback(store, outcome.op_id)) == []
    assert (shadow.stat().st_mode & 0o777) == 0o666 and shadow.read_text() == "hashes"


def test_tightened_mode_never_adds_permissions():
    from reviveguard.fixes.permissions import tightened_mode

    v = permissions.Violation("/etc/x", 0o600, 0, 0o440)
    assert tightened_mode(v) == 0o400  # 0600 & 0440 = 0400
    assert tightened_mode(permissions.Violation("/etc/x", 0o060, 0, 0o600)) == 0o400
    assert tightened_mode(permissions.Violation("/etc/x", 0o777, 0, 0o640)) == 0o640


def test_permission_fix_nothing_to_do(make_ctx):
    from reviveguard.models import CheckResult

    r = CheckResult("PERM-001", "permissions", Severity.HIGH, Status.FAIL, "t", "d", "r")
    plan = REGISTRY["PERM-001"](make_ctx(), r)
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.nothing_to_fix"


# ---------------- sysctl ----------------


def proc_sys(root: Path, **values):
    for key, value in values.items():
        put(root, "/proc/sys/" + key.replace(".", "/"), 0o644, f"{value}\n")


SECURE = {
    "net.ipv4.ip_forward": 0,
    "net.ipv4.conf.all.accept_redirects": 0,
    "net.ipv6.conf.all.accept_redirects": 0,
    "net.ipv4.conf.all.accept_source_route": 0,
    "net.ipv6.conf.all.accept_source_route": 0,
    "net.ipv4.tcp_syncookies": 1,
    "kernel.kptr_restrict": 1,
    "kernel.dmesg_restrict": 1,
    "kernel.randomize_va_space": 2,
    "net.ipv4.conf.all.rp_filter": 1,
}


def test_sysctl_secure_host(make_ctx, fake_root):
    proc_sys(fake_root, **SECURE)
    res = sysctl.run(make_ctx())
    assert len(res) == 8 and all(r.status is Status.OK for r in res)


def test_sysctl_weak_values_flagged(make_ctx, fake_root):
    weak = {**SECURE, "kernel.randomize_va_space": 0, "net.ipv4.conf.all.accept_redirects": 1}
    proc_sys(fake_root, **weak)
    res = by_id(sysctl.run(make_ctx()))
    assert res["SYS-007"].status is Status.FAIL and res["SYS-007"].severity is Severity.HIGH
    assert res["SYS-002"].status is Status.FAIL and "= 1" in res["SYS-002"].evidence[0]
    assert res["SYS-004"].status is Status.OK


def test_forwarding_is_expected_on_docker_hosts(make_ctx, fake_root):
    proc_sys(fake_root, **{**SECURE, "net.ipv4.ip_forward": 1})
    assert by_id(sysctl.run(make_ctx()))["SYS-001"].status is Status.FAIL
    put(fake_root, "/var/run/docker.sock", 0o600)
    r = by_id(sysctl.run(make_ctx()))["SYS-001"]
    assert r.status is Status.OK and "Docker/VPN" in r.evidence[-1]


def test_sysctl_skipped_in_container_and_for_missing_params(make_ctx, fake_root):
    runner = FakeRunner({("systemd-detect-virt", "--container"): CommandResult(("x",), 0, "lxc\n")})
    res = sysctl.run(make_ctx(runner=runner))
    assert [r.check_id for r in res] == ["SYS-000"]
    assert sysctl.run(make_ctx()) == []  # no /proc/sys values at all: nothing guessed


def test_sysctl_fix_writes_dropin_merges_and_applies(make_ctx, fake_root, store):
    proc_sys(fake_root, **{**SECURE, "kernel.randomize_va_space": 0, "kernel.dmesg_restrict": 0})
    runner = FakeRunner()
    ctx_holder = {}

    def sysctl_runner(args, timeout=None):
        runner.calls.append(list(args))
        if args[:2] == ["sysctl", "-p"]:  # emulate the kernel taking the value
            text = Path(args[2]).read_text()
            for line in text.splitlines():
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    proc_sys(fake_root, **{k.strip(): v.strip()})
            return CommandResult(tuple(args), 0)
        return CommandResult(tuple(args), None, missing=True)

    ctx = make_ctx(runner=sysctl_runner)
    ctx_holder["ctx"] = ctx
    for check_id in ("SYS-007", "SYS-006"):
        failing = by_id(sysctl.run(ctx))[check_id]
        outcome = run_fix(store, ctx, REGISTRY[check_id](ctx, failing))
        assert outcome.status == "applied", outcome
    text = (fake_root / "etc/sysctl.d/99-reviveguard.conf").read_text()
    assert "kernel.randomize_va_space = 2" in text and "kernel.dmesg_restrict = 1" in text
    assert ["sysctl", "-p", str(fake_root / "etc/sysctl.d/99-reviveguard.conf")] in runner.calls


def test_sysctl_fix_reverts_when_kernel_rejects(make_ctx, fake_root, store):
    proc_sys(fake_root, **{**SECURE, "kernel.randomize_va_space": 0})
    ctx = make_ctx(
        runner=lambda args, timeout=None: (
            CommandResult(tuple(args), 1, "", "read-only /proc/sys")
            if args[0] == "sysctl"
            else CommandResult(tuple(args), None, missing=True)
        )
    )
    failing = by_id(sysctl.run(ctx))["SYS-007"]
    outcome = run_fix(store, ctx, REGISTRY["SYS-007"](ctx, failing))
    assert outcome.status == "activation_failed" and outcome.revert_ok
    assert not (fake_root / "etc/sysctl.d/99-reviveguard.conf").exists()


def test_routing_sysctls_are_manual_only():
    for check_id in ("SYS-001", "SYS-008"):
        assert check_id not in AUTOMATIC
    assert {"SYS-002", "SYS-003", "SYS-004", "SYS-005", "SYS-006", "SYS-007"} <= AUTOMATIC


# ---------------- services ----------------

SS = """tcp   LISTEN 0 128 0.0.0.0:22     0.0.0.0:*  users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0 128    [::]:22        [::]:*  users:(("sshd",pid=1,fd=4))
tcp   LISTEN 0 511 127.0.0.1:6379    0.0.0.0:*  users:(("redis-server",pid=2,fd=6))
tcp   LISTEN 0 511 0.0.0.0:3306      0.0.0.0:*  users:(("mysqld",pid=3,fd=21))
udp   UNCONN 0 0   127.0.0.53%lo:53  0.0.0.0:*
udp   UNCONN 0 0   0.0.0.0:5353     0.0.0.0:*
"""


def ss_runner(text=SS, rc=0):
    return FakeRunner({("ss", "-H", "-tulnp"): CommandResult(("ss",), rc, text)})


def test_parse_ss_handles_ipv6_loopback_and_scope_suffix():
    items = services.parse_ss(SS)
    assert {(i.address, i.port) for i in items} >= {
        ("::", 22),
        ("127.0.0.1", 6379),
        ("127.0.0.53", 53),
    }
    assert next(i for i in items if i.port == 22).process == "sshd"


def test_public_overview_and_risky_exposure(make_ctx):
    res = by_id(services.run(make_ctx(runner=ss_runner())))
    assert res["SVC-001"].status is Status.OK and any("sshd" in e for e in res["SVC-001"].evidence)
    assert not any("6379" in e for e in res["SVC-001"].evidence)  # loopback is not public
    risky = res["SVC-002"]
    assert risky.status is Status.FAIL and risky.severity is Severity.MEDIUM
    assert any("MySQL" in e for e in risky.evidence)
    assert not any("6379" in e for e in risky.evidence)


def test_high_risk_service_raises_severity(make_ctx):
    out = 'tcp LISTEN 0 1 *:6379 *:* users:(("redis-server",pid=2,fd=6))\n'
    assert by_id(services.run(make_ctx(runner=ss_runner(out))))["SVC-002"].severity is Severity.HIGH


def test_clean_host_and_missing_ss(make_ctx):
    out = "tcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*\n"
    assert by_id(services.run(make_ctx(runner=ss_runner(out))))["SVC-002"].status is Status.OK
    assert services.run(make_ctx(runner=FakeRunner()))[0].check_id == "SVC-000"
    assert services.run(make_ctx(runner=ss_runner("", 1)))[0].status is Status.SKIPPED


def test_service_findings_are_manual(make_ctx):
    plan = REGISTRY["SVC-002"](make_ctx(), None)
    assert isinstance(plan, Manual) and "SVC-002" not in AUTOMATIC
