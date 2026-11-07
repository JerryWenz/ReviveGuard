"""Hardening without any key: a password administrator, root off, password policy."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from reviveguard import cli
from reviveguard.backup import Store
from reviveguard.checks import accounts
from reviveguard.checks import ssh as ssh_checks
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.models import Status
from reviveguard.remediation import FixSpec, Manual, run_fix

from .conftest import SSHD_MAIN, FakeRunner, build_host, ssh_runner
from .test_admin_user import KEY, UserHost
from .test_updates import AptHost

CONN = {"SSH_CONNECTION": "10.0.0.1 5555 10.0.0.2 22", "SUDO_USER": "root"}
PASSWORD_LOG = "Accepted password for root from 10.0.0.1 port 5555 ssh2\n"


def failing(ctx, check_id):
    results = ssh_checks.run(ctx)
    return next(r for r in results if r.check_id == check_id and r.status is Status.FAIL)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


def host_with_password_admin(make_ctx, fake_root, admin_password=True):
    users = {
        "root": {"uid": 0, "key": True, "password": True},
        "ops": {"uid": 1000, "sudo": True, "password": admin_password},
    }
    build_host(fake_root, users, SSHD_MAIN + "PermitRootLogin yes\n")
    (fake_root / "proc/self").mkdir(parents=True, exist_ok=True)
    (fake_root / "proc/self/loginuid").write_text("0")
    return make_ctx(runner=ssh_runner(accepted=PASSWORD_LOG), env=dict(CONN))


def test_root_login_can_be_switched_off_for_a_root_password_session(make_ctx, fake_root, store):
    """No key needed: a password administrator exists, the live confirmation covers the rest."""
    ctx = host_with_password_admin(make_ctx, fake_root)
    spec = REGISTRY["SSH-001"](ctx, failing(ctx, "SSH-001"))
    assert isinstance(spec, FixSpec) and spec.change_args["directive"] == "PermitRootLogin no"
    assert spec.confirm_key == "fix.confirm.ssh_root" and spec.confirm_args["admins"] == "ops"
    assert run_fix(store, ctx, spec, confirm=lambda s: True).status == "applied"


def test_declined_confirmation_restores_root_login(make_ctx, fake_root, store):
    ctx = host_with_password_admin(make_ctx, fake_root)
    spec = REGISTRY["SSH-001"](ctx, failing(ctx, "SSH-001"))
    outcome = run_fix(store, ctx, spec, confirm=lambda s: False)
    dropin = fake_root / "etc/ssh/sshd_config.d/00-reviveguard-permitrootlogin.conf"
    assert outcome.status == "confirmation_failed" and outcome.revert_ok and not dropin.exists()


def test_without_a_working_administrator_root_stays_and_passwords_stay(make_ctx, fake_root):
    ctx = host_with_password_admin(make_ctx, fake_root, admin_password=False)
    root_plan = REGISTRY["SSH-001"](ctx, failing(ctx, "SSH-001"))
    assert isinstance(root_plan, Manual)  # password login as root is the only way in
    pw_plan = REGISTRY["SSH-002"](ctx, failing(ctx, "SSH-002"))
    assert (
        isinstance(pw_plan, Manual) and pw_plan.reason_key == "fix.reason.logged_in_with_password"
    )


def test_password_login_is_never_switched_off_without_a_proven_key(make_ctx, fake_root):
    ctx = host_with_password_admin(make_ctx, fake_root)
    plan = REGISTRY["SSH-002"](ctx, failing(ctx, "SSH-002"))
    assert isinstance(plan, Manual)


def test_usr001_accepts_a_password_administrator(make_ctx, fake_root):
    ctx = host_with_password_admin(make_ctx, fake_root)
    res = {r.check_id: r for r in accounts.run(ctx)}
    assert res["USR-001"].status is Status.OK and "ops" in res["USR-001"].evidence[0]
    ctx = host_with_password_admin(make_ctx, fake_root, admin_password=False)
    assert {r.check_id: r for r in accounts.run(ctx)}["USR-001"].status is Status.FAIL


def test_usr001_ignores_a_password_when_password_login_is_off(make_ctx, fake_root):
    users = {"root": {"uid": 0}, "ops": {"uid": 1000, "sudo": True, "password": True}}
    build_host(fake_root, users, SSHD_MAIN + "PasswordAuthentication no\n")
    ctx = make_ctx(runner=ssh_runner())
    assert {r.check_id: r for r in accounts.run(ctx)}["USR-001"].status is Status.FAIL


# ---------------- admin flow with a password ----------------


def run_cli(args, ctx, capsys, monkeypatch, tmp_path, answers=()):
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    it = iter(answers)

    def fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", fake_input)
    rc = cli.main(["--lang", "en", "--state-dir", str(tmp_path / "s"), *args], ctx=ctx)
    out = capsys.readouterr()
    return rc, out.out, out.err


@pytest.fixture
def adm(make_ctx, fake_root, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *a: None)
    build_host(fake_root, {"root": {"uid": 0}}, SSHD_MAIN)
    (fake_root / "etc/group").write_text("sudo:x:27:\n")
    (fake_root / "etc/sudoers.d").mkdir(parents=True)
    runner = UserHost(fake_root, ssh_runner())
    return fake_root, make_ctx(runner=runner, env={})


def test_keyless_admin_gets_a_password_and_keeps_sudo_password(adm, capsys, monkeypatch, tmp_path):
    root, ctx = adm
    calls = []
    monkeypatch.setattr("reviveguard.fixflow.run_interactive", lambda a: calls.append(a) or 0)
    rc, out, _ = run_cli(
        ["admin-user"], ctx, capsys, monkeypatch, tmp_path, answers=["ops", "", "y", "y"]
    )
    assert rc == 0 and calls == [["passwd", "ops"]]
    assert "sudo: password" in out and "log in as ops with this password" in out
    assert not (root / "etc/sudoers.d/90-reviveguard-ops").exists()  # sudo keeps asking


def test_declining_the_password_prints_how_to_do_it_later(adm, capsys, monkeypatch, tmp_path):
    _, ctx = adm
    monkeypatch.setattr("reviveguard.fixflow.run_interactive", lambda a: pytest.fail("no passwd"))
    rc, out, _ = run_cli(
        ["admin-user"], ctx, capsys, monkeypatch, tmp_path, answers=["ops", "", "y", "n"]
    )
    assert rc == 0 and "passwd ops" in out


def test_a_failing_passwd_is_reported(adm, capsys, monkeypatch, tmp_path):
    _, ctx = adm
    monkeypatch.setattr("reviveguard.fixflow.run_interactive", lambda a: 1)
    rc, _, err = run_cli(
        ["admin-user"], ctx, capsys, monkeypatch, tmp_path, answers=["ops", "", "y", "y"]
    )
    assert rc == 0 and "password for 'ops' was not set" in err


def test_a_key_admin_does_not_ask_for_a_password(adm, capsys, monkeypatch, tmp_path):
    _, ctx = adm
    monkeypatch.setattr("reviveguard.fixflow.run_interactive", lambda a: pytest.fail("no passwd"))
    rc, out, _ = run_cli(
        ["admin-user"], ctx, capsys, monkeypatch, tmp_path, answers=["ops", KEY, "y"]
    )
    assert rc == 0 and "NOPASSWD" in out


# ---------------- password policy ----------------


class PolicyHost(AptHost):
    def __init__(self, fake_root, **kw):
        super().__init__(**kw)
        self.root = fake_root


def policy_result(ctx):
    return next(r for r in accounts.run(ctx) if r.check_id == "USR-004")


def test_password_policy_is_flagged_without_the_package(make_ctx, fake_root):
    build_host(fake_root, {"root": {"uid": 0}}, SSHD_MAIN)
    ctx = make_ctx(runner=PolicyHost(fake_root))
    r = policy_result(ctx)
    assert r.status is Status.FAIL and "installed: False" in r.evidence[0]


def test_installed_package_with_short_minlen_is_flagged(make_ctx, fake_root):
    build_host(fake_root, {"root": {"uid": 0}}, SSHD_MAIN)
    (fake_root / "etc/security").mkdir(parents=True)
    (fake_root / "etc/security/pwquality.conf").write_text("# minlen = 20\nminlen = 8\n")
    ctx = make_ctx(runner=PolicyHost(fake_root, installed={"libpam-pwquality"}))
    r = policy_result(ctx)
    assert r.status is Status.FAIL and "minlen: 8" in r.evidence[0]
    (fake_root / "etc/security/pwquality.conf").write_text("minlen = 14\n")
    assert policy_result(ctx).status is Status.OK
    (fake_root / "etc/security/pwquality.conf.d").mkdir()
    (fake_root / "etc/security/pwquality.conf.d/50-x.conf").write_text("minlen = 6\n")
    assert policy_result(ctx).status is Status.FAIL  # a later drop-in wins


def test_password_policy_fix_installs_and_writes_the_dropin(make_ctx, fake_root, store):
    from reviveguard.packages import INSTALLABLE

    assert "libpam-pwquality" in INSTALLABLE
    build_host(fake_root, {"root": {"uid": 0}}, SSHD_MAIN)
    host = PolicyHost(fake_root)
    ctx = make_ctx(runner=host)
    spec = REGISTRY["USR-004"](ctx, policy_result(ctx))
    assert (
        isinstance(spec, FixSpec) and spec.packages == ["libpam-pwquality"] and not spec.disruptive
    )
    outcome = run_fix(store, ctx, spec, confirm=lambda s: True)
    assert outcome.status == "applied", outcome
    text = (fake_root / "etc/security/pwquality.conf.d/90-reviveguard.conf").read_text()
    assert "minlen = 12" in text and "minclass = 3" in text
    assert "USR-004" in AUTOMATIC


def test_password_policy_fix_needs_apt_when_package_missing(make_ctx, fake_root):
    build_host(fake_root, {"root": {"uid": 0}}, SSHD_MAIN)
    ctx = make_ctx(runner=FakeRunner())
    from reviveguard.models import CheckResult, Severity

    result = CheckResult("USR-004", "accounts", Severity.MEDIUM, Status.FAIL, "t", "d", "r")
    assert REGISTRY["USR-004"](ctx, result).reason_key == "fix.reason.no_apt"


# ---------------- authorized_keys permissions ----------------


def keys_host(make_ctx, fake_root, mode):
    users = {"root": {"uid": 0}, "alice": {"uid": 1000, "sudo": True, "key": True}}
    build_host(fake_root, users, SSHD_MAIN)

    def stat(path):
        is_file = str(path).endswith("authorized_keys")
        return SimpleNamespace(st_mode=0o100000 | (mode if is_file else 0o700), st_uid=1000)

    return make_ctx(runner=ssh_runner(), stat=stat)


def test_writable_authorized_keys_is_reported(make_ctx, fake_root):
    res = {r.check_id: r for r in ssh_checks.run(keys_host(make_ctx, fake_root, 0o666))}
    assert res["SSH-012"].status is Status.FAIL
    assert "alice" in res["SSH-012"].evidence[0] and "0666" in res["SSH-012"].evidence[0]


def test_correct_authorized_keys_is_ok_and_fix_is_manual(make_ctx, fake_root):
    res = {r.check_id: r for r in ssh_checks.run(keys_host(make_ctx, fake_root, 0o600))}
    assert res["SSH-012"].status is Status.OK
    assert "SSH-012" in REGISTRY and "SSH-012" not in AUTOMATIC


def test_wrong_owner_is_reported(make_ctx, fake_root):
    users = {"alice": {"uid": 1000, "sudo": True, "key": True}}
    build_host(fake_root, users, SSHD_MAIN)
    ctx = make_ctx(
        runner=ssh_runner(), stat=lambda p: SimpleNamespace(st_mode=0o100600, st_uid=4242)
    )
    res = {r.check_id: r for r in ssh_checks.run(ctx)}
    assert (
        res["SSH-012"].status is Status.FAIL and "owned by uid 4242" in res["SSH-012"].evidence[0]
    )
