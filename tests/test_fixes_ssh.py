from __future__ import annotations

import os

import pytest

from reviveguard import remediation
from reviveguard.backup import Store
from reviveguard.checks import ssh as ssh_checks
from reviveguard.fixes import REGISTRY
from reviveguard.fixes import ssh as fixes
from reviveguard.models import Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import SSHD_MAIN, build_host, fake_stat, ssh_runner, write_sshd_config

REMOTE = {"SSH_CONNECTION": "10.0.0.1 5555 10.0.0.2 22"}
ALICE = {"alice": {"uid": 1000, "sudo": True, "key": True}}
ROOT_KEY = {"root": {"uid": 0, "key": True}}


def failing(ctx, check_id):
    return next(
        r for r in ssh_checks.run(ctx) if r.check_id == check_id and r.status is Status.FAIL
    )


def plan(ctx, check_id):
    return REGISTRY[check_id](ctx, failing(ctx, check_id))


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


def env_for(user, remote=True):
    env = dict(REMOTE) if remote else {}
    env["SUDO_USER"] = user
    return env


# ---------- SSH-002: password authentication ----------


def test_password_fix_full_flow(make_ctx, fake_root, store):
    build_host(fake_root, {**ALICE, **ROOT_KEY})
    runner = ssh_runner()
    ctx = make_ctx(runner=runner, env=env_for("alice"))
    spec = plan(ctx, "SSH-002")
    assert isinstance(spec, FixSpec) and spec.disruptive
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied"
    dropin = fake_root / "etc/ssh/sshd_config.d/00-reviveguard-passwordauthentication.conf"
    assert "PasswordAuthentication no" in dropin.read_text()
    assert ["systemctl", "reload", "ssh"] in runner.calls
    assert not any(c[:2] == ["systemctl", "restart"] for c in runner.calls)
    op = store.load(outcome.op_id)
    assert op.status == "applied" and op.check_id == "SSH-002"
    assert op.files[0].existed is False  # rollback will delete the drop-in


def test_password_fix_refused_without_key_for_current_user(make_ctx, fake_root):
    users = {**ALICE, "bob": {"uid": 1001, "sudo": True, "key": False, "password": True}}
    build_host(fake_root, users)
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("bob")), "SSH-002")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.no_key_for_current_user"
    assert not list((fake_root / "etc/ssh/sshd_config.d").iterdir())


def test_password_fix_refused_when_nobody_has_key(make_ctx, fake_root):
    build_host(fake_root, {"alice": {"uid": 1000, "sudo": True, "password": True}})
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("alice", remote=False)), "SSH-002")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.no_admin_access"


def test_password_fix_allowed_locally_if_some_admin_has_key(make_ctx, fake_root):
    build_host(fake_root, ALICE)
    ctx = make_ctx(runner=ssh_runner(), env={})
    assert isinstance(plan(ctx, "SSH-002"), FixSpec)


def test_password_fix_refused_when_pubkey_disabled(make_ctx, fake_root):
    build_host(fake_root, ALICE, SSHD_MAIN + "PubkeyAuthentication no\n")
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("alice")), "SSH-002")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.pubkey_disabled"


def test_password_fix_refused_with_custom_authentication_methods(make_ctx, fake_root):
    build_host(fake_root, ALICE, SSHD_MAIN + "AuthenticationMethods publickey,password\n")
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("alice")), "SSH-002")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.auth_methods"


def test_password_fix_refused_when_allowusers_excludes_user(make_ctx, fake_root):
    build_host(fake_root, ALICE, SSHD_MAIN + "AllowUsers carol\n")
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("alice")), "SSH-002")
    assert isinstance(result, Manual)


def test_world_writable_authorized_keys_is_not_a_working_key(make_ctx, fake_root):
    build_host(fake_root, ALICE)
    ctx = make_ctx(runner=ssh_runner(), env=env_for("alice"), stat=fake_stat(0o100666))
    result = plan(ctx, "SSH-002")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.no_key_for_current_user"


def test_remote_session_with_unknown_user_is_refused(make_ctx, fake_root):
    build_host(fake_root, ALICE)
    ctx = make_ctx(runner=ssh_runner(), env=dict(REMOTE), root=False)
    ctx.env.pop("SUDO_USER", None)
    result = plan(ctx, "SSH-002")
    assert isinstance(result, Manual)


# ---------- SSH-001: root login ----------


def test_root_login_remote_as_root_keeps_key_access(make_ctx, fake_root):
    build_host(fake_root, {**ROOT_KEY, **ALICE}, SSHD_MAIN + "PermitRootLogin yes\n")
    # remote root session: loginuid points to root
    (fake_root / "proc/self").mkdir(parents=True)
    (fake_root / "proc/self/loginuid").write_text("0")
    spec = plan(make_ctx(runner=ssh_runner(), env=dict(REMOTE)), "SSH-001")
    assert isinstance(spec, FixSpec) and "prohibit-password" in spec.change_args["directive"]


def test_root_login_remote_as_root_without_key_refused(make_ctx, fake_root):
    build_host(
        fake_root,
        {"root": {"uid": 0, "password": True}, **ALICE},
        SSHD_MAIN + "PermitRootLogin yes\n",
    )
    (fake_root / "proc/self").mkdir(parents=True)
    (fake_root / "proc/self/loginuid").write_text("0")
    result = plan(make_ctx(runner=ssh_runner(), env=dict(REMOTE)), "SSH-001")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.root_session_no_key"


def test_root_login_disabled_when_current_admin_has_access(make_ctx, fake_root, store):
    build_host(fake_root, {**ROOT_KEY, **ALICE}, SSHD_MAIN + "PermitRootLogin yes\n")
    ctx = make_ctx(runner=ssh_runner(), env=env_for("alice"))
    spec = plan(ctx, "SSH-001")
    assert isinstance(spec, FixSpec) and spec.change_args["directive"] == "PermitRootLogin no"
    assert run_fix(store, ctx, spec).status == "applied"


def test_root_login_refused_when_current_user_not_verified(make_ctx, fake_root):
    users = {**ROOT_KEY, **ALICE, "bob": {"uid": 1001, "sudo": True}}
    build_host(fake_root, users, SSHD_MAIN + "PermitRootLogin yes\n")
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("bob")), "SSH-001")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.no_key_for_current_user"


def test_root_login_password_only_admin_counts_while_password_auth_on(make_ctx, fake_root):
    users = {**ROOT_KEY, "carol": {"uid": 1002, "sudo": True, "password": True}}
    build_host(fake_root, users, SSHD_MAIN + "PermitRootLogin yes\n")
    ctx = make_ctx(runner=ssh_runner(), env=env_for("carol"))
    assert isinstance(plan(ctx, "SSH-001"), FixSpec)


def test_root_login_password_only_admin_does_not_count_if_passwords_off(make_ctx, fake_root):
    users = {"root": {"uid": 0}, "carol": {"uid": 1002, "sudo": True, "password": True}}
    build_host(fake_root, users, SSHD_MAIN + "PermitRootLogin yes\nPasswordAuthentication no\n")
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("carol", remote=False)), "SSH-001")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.no_admin_access"


def test_root_login_locked_password_does_not_count(make_ctx, fake_root):
    users = {"root": {"uid": 0}, "carol": {"uid": 1002, "sudo": True}}  # shadow '!' = locked
    build_host(fake_root, users, SSHD_MAIN + "PermitRootLogin yes\n")
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("carol", remote=False)), "SSH-001")
    assert isinstance(result, Manual)


# ---------- SSH-003 / SSH-004 / prechecks ----------


def test_empty_passwords_and_pubkey_fixes_apply(make_ctx, fake_root, store):
    build_host(fake_root, ALICE, SSHD_MAIN + "PermitEmptyPasswords yes\nPubkeyAuthentication no\n")
    ctx = make_ctx(runner=ssh_runner(), env=env_for("alice"))
    for check_id in ("SSH-003", "SSH-004"):
        spec = plan(ctx, check_id)
        assert isinstance(spec, FixSpec) and not spec.disruptive
        assert run_fix(store, ctx, spec).status == "applied"


def test_precheck_directive_before_include_is_manual(make_ctx, fake_root):
    cfg = "PermitEmptyPasswords yes\n" + SSHD_MAIN
    build_host(fake_root, ALICE, cfg)
    result = plan(make_ctx(runner=ssh_runner()), "SSH-003")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.directive_before_include"


def test_precheck_no_include_is_manual(make_ctx, fake_root):
    build_host(fake_root, ALICE, "# no Include line at all\n")
    result = plan(make_ctx(runner=ssh_runner(), env=env_for("alice")), "SSH-002")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.no_include"


def test_precheck_missing_sshd_is_manual(make_ctx, fake_root):
    build_host(fake_root, ALICE, SSHD_MAIN + "PermitEmptyPasswords yes\n")
    runner = ssh_runner()
    del runner.responses[("sshd", "-t")]  # tool missing
    result = plan(make_ctx(runner=runner), "SSH-003")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.no_sshd"


def test_precheck_invalid_current_config_is_manual(make_ctx, fake_root):
    build_host(fake_root, ALICE, SSHD_MAIN + "PermitEmptyPasswords yes\n")
    runner = ssh_runner(**{"sshd -t": None})
    runner.responses[("sshd", "-t")] = CommandResult(("sshd", "-t"), 255, "", "bad option")
    result = plan(make_ctx(runner=runner), "SSH-003")
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.config_invalid"


# ---------- engine safety net ----------


class FlakyRunner:
    """sshd -t passes for the pre-check, then fails (simulating a bad new config)."""

    def __init__(self, base, fail_after=1, reload_ok=True):
        self.base, self.fail_after, self.validations, self.calls = base, fail_after, 0, []
        self.reload_ok = reload_ok

    def __call__(self, args):
        self.calls.append(list(args))
        if args == ["sshd", "-t"]:
            self.validations += 1
            if self.validations > self.fail_after:
                return CommandResult(tuple(args), 255, "", "Bad configuration option")
        if args[:2] == ["systemctl", "reload"] and not self.reload_ok:
            return CommandResult(tuple(args), 1)
        return self.base(args)


def planned(make_ctx, fake_root, runner, env=None):
    build_host(fake_root, ALICE, SSHD_MAIN + "PermitEmptyPasswords yes\n")
    ctx = make_ctx(runner=runner, env=env or env_for("alice"))
    return ctx, plan(ctx, "SSH-003")


def dropin(fake_root):
    return fake_root / "etc/ssh/sshd_config.d/00-reviveguard-permitemptypasswords.conf"


def test_validation_failure_reverts_and_never_reloads(make_ctx, fake_root, store):
    runner = FlakyRunner(ssh_runner())
    ctx, spec = planned(make_ctx, fake_root, runner)
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "validation_failed" and outcome.reverted and outcome.revert_ok
    assert not dropin(fake_root).exists()
    assert ["systemctl", "reload", "ssh"] not in runner.calls
    assert store.load(outcome.op_id).status == "rolled_back"


def test_reload_failure_reverts_and_reloads_again(make_ctx, fake_root, store):
    runner = FlakyRunner(ssh_runner(), fail_after=99, reload_ok=False)
    ctx, spec = planned(make_ctx, fake_root, runner)
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "activation_failed" and outcome.revert_ok
    assert not dropin(fake_root).exists()
    assert runner.calls.count(["systemctl", "reload", "ssh"]) == 2  # fix, then restore


def test_missing_systemctl_means_no_change_is_kept(make_ctx, fake_root, store):
    runner = ssh_runner()
    del runner.responses[("systemctl", "--version")]
    ctx, spec = planned(make_ctx, fake_root, runner)
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "activation_failed" and not dropin(fake_root).exists()


def test_ineffective_change_fails_verification_and_reverts(make_ctx, fake_root, store):
    ctx, spec = planned(make_ctx, fake_root, ssh_runner())
    spec.apply = lambda: dropin(fake_root).write_text("# does nothing\n")
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "verify_failed" and outcome.revert_ok
    assert not dropin(fake_root).exists()


def test_apply_exception_reverts(make_ctx, fake_root, store):
    ctx, spec = planned(make_ctx, fake_root, ssh_runner())

    def boom():
        dropin(fake_root).write_text("half")
        raise OSError(28, "No space left on device")

    spec.apply = boom
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "apply_failed" and not dropin(fake_root).exists()


def test_keyboard_interrupt_restores_then_propagates(make_ctx, fake_root, store):
    ctx, spec = planned(make_ctx, fake_root, ssh_runner())

    def interrupted():
        dropin(fake_root).write_text("half")
        raise KeyboardInterrupt

    spec.apply = interrupted
    with pytest.raises(KeyboardInterrupt):
        run_fix(store, ctx, spec)
    assert not dropin(fake_root).exists()
    ops, _ = store.list_operations()
    assert ops[0].status == "rolled_back"


def test_backup_failure_prevents_any_change(make_ctx, fake_root, tmp_path):
    ctx, spec = planned(make_ctx, fake_root, ssh_runner())
    blocker = tmp_path / "file"
    blocker.write_text("x")
    outcome = run_fix(Store(blocker / "state"), ctx, spec)  # state dir cannot be created
    assert outcome.status == "backup_failed" and not dropin(fake_root).exists()


def test_failed_revert_is_reported(make_ctx, fake_root, store, monkeypatch):
    runner = FlakyRunner(ssh_runner())
    ctx, spec = planned(make_ctx, fake_root, runner)

    def deny(*a, **k):
        raise remediation.RollbackError("disk gone")

    monkeypatch.setattr(remediation, "execute_rollback", deny)
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "validation_failed" and outcome.revert_ok is False


def test_user_can_roll_back_an_applied_fix(make_ctx, fake_root, store):
    from reviveguard import rollback

    ctx, spec = planned(make_ctx, fake_root, ssh_runner())
    outcome = run_fix(store, ctx, spec)
    assert dropin(fake_root).exists()
    assert rollback.execute_rollback(store, rollback.plan_rollback(store, outcome.op_id)) == []
    assert not dropin(fake_root).exists()


def test_preflight(make_ctx):
    assert remediation.preflight(make_ctx()) is None
    assert remediation.preflight(make_ctx(root=False)) == "fix.err.not_root"
    ctx = make_ctx()
    from reviveguard.system import OsInfo

    ctx.os_info = OsInfo("debian", "11", "Debian 11")
    assert remediation.preflight(ctx) == "fix.err.unsupported_os"


# ---------- SSH-005: permissions ----------


def test_config_perms_fix(make_ctx, fake_root, store, monkeypatch):
    build_host(fake_root, ALICE)
    cfg = fake_root / "etc/ssh/sshd_config"
    cfg.chmod(0o666)
    monkeypatch.setattr(os, "chown", lambda *a: None)  # tests run unprivileged

    def stat(p):  # real mode, but pretend root owns it
        st = os.stat(p)
        return type("S", (), {"st_mode": st.st_mode, "st_uid": 0})()

    ctx = make_ctx(runner=ssh_runner(), stat=stat)
    spec = plan(ctx, "SSH-005")
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied" and (cfg.stat().st_mode & 0o777) == 0o600
    from reviveguard import rollback

    rollback.execute_rollback(store, rollback.plan_rollback(store, outcome.op_id))
    assert (cfg.stat().st_mode & 0o777) == 0o666


def test_write_file_atomic_cleans_up_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "f"
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("x")))
    with pytest.raises(OSError):
        remediation.write_file_atomic(target, "data", 0o644)
    assert list(tmp_path.iterdir()) == []


def test_registry_covers_all_ssh_checks():
    assert {k for k in REGISTRY if k.startswith("SSH-")} == {f"SSH-00{i}" for i in range(1, 6)}
    assert callable(fixes.reload_ssh) and write_sshd_config
