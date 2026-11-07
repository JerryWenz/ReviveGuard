"""Regression: disabling password/root login needs proof that the *current* session used a key.

Real incident: root logged in with the hoster's password while /root/.ssh/authorized_keys held
a key the administrator did not own; the fixes were applied and could have locked them out.
"""

from __future__ import annotations

import pytest

from reviveguard.backup import Store, begin_operation, mark_applied
from reviveguard.checks import ssh as ssh_checks
from reviveguard.fixes import REGISTRY
from reviveguard.models import Status
from reviveguard.remediation import FixSpec, Manual
from reviveguard.ssh_access import current_connection, session_auth_method
from reviveguard.system import CommandResult

from .conftest import JOURNAL, SSHD_MAIN, FakeRunner, build_host, ssh_runner

CONN = {"SSH_CONNECTION": "10.0.0.1 5555 10.0.0.2 22"}
PASSWORD_LOG = "Accepted password for root from 10.0.0.1 port 5555 ssh2\n"
KEY_LOG = "Accepted publickey for root from 10.0.0.1 port 5555 ssh2: ED25519 SHA256:abc\n"
OTHER_SESSION_KEY = "Accepted publickey for root from 9.9.9.9 port 4444 ssh2: ED25519 SHA256:x\n"


def failing(ctx, check_id):
    return next(
        r for r in ssh_checks.run(ctx) if r.check_id == check_id and r.status is Status.FAIL
    )


def root_host(make_ctx, fake_root, log, env=None):
    users = {"root": {"uid": 0, "key": True}, "alice": {"uid": 1000, "sudo": True, "key": True}}
    build_host(fake_root, users, SSHD_MAIN + "PermitRootLogin yes\n")
    (fake_root / "proc/self").mkdir(parents=True)
    (fake_root / "proc/self/loginuid").write_text("0")
    return make_ctx(runner=ssh_runner(accepted=log), env=env or dict(CONN))


@pytest.mark.parametrize("check_id", ["SSH-001", "SSH-002"])
def test_password_login_blocks_narrowing_even_though_root_has_a_key(make_ctx, fake_root, check_id):
    ctx = root_host(make_ctx, fake_root, PASSWORD_LOG)
    plan = REGISTRY[check_id](ctx, failing(ctx, check_id))
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.logged_in_with_password"
    assert plan.args["method"] == "password"


@pytest.mark.parametrize("check_id", ["SSH-001", "SSH-002"])
def test_unknown_login_method_is_refused(make_ctx, fake_root, check_id):
    ctx = root_host(make_ctx, fake_root, OTHER_SESSION_KEY)  # no line for THIS connection
    plan = REGISTRY[check_id](ctx, failing(ctx, check_id))
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.auth_unknown"


@pytest.mark.parametrize("check_id", ["SSH-001", "SSH-002"])
def test_publickey_login_proves_the_key_and_allows_the_fix(make_ctx, fake_root, check_id):
    ctx = root_host(make_ctx, fake_root, KEY_LOG)
    assert isinstance(REGISTRY[check_id](ctx, failing(ctx, check_id)), FixSpec)


def test_local_console_session_is_not_subject_to_the_proof(make_ctx, fake_root):
    users = {"alice": {"uid": 1000, "sudo": True, "key": True}}
    build_host(fake_root, users, SSHD_MAIN)
    ctx = make_ctx(runner=ssh_runner(accepted=""), env={"SUDO_USER": "alice"})
    assert isinstance(REGISTRY["SSH-002"](ctx, failing(ctx, "SSH-002")), FixSpec)


def test_the_matching_connection_wins_over_older_entries(make_ctx, fake_root):
    log = PASSWORD_LOG + OTHER_SESSION_KEY + KEY_LOG  # same ip:port reused later with a key
    ctx = root_host(make_ctx, fake_root, log)
    assert session_auth_method(ctx) == "publickey"


def test_log_falls_back_to_auth_log_when_journal_is_empty(make_ctx, fake_root):
    ctx = root_host(make_ctx, fake_root, "")
    (fake_root / "var/log").mkdir(parents=True)
    (fake_root / "var/log/auth.log").write_text("Jan 1 sshd[1]: " + KEY_LOG)
    assert session_auth_method(ctx) == "publickey"


def test_connection_is_found_through_sshd_when_sudo_dropped_the_environment(make_ctx, fake_root):
    ctx = root_host(make_ctx, fake_root, KEY_LOG, env={"SUDO_USER": "root"})
    proc = fake_root / "proc"
    (proc / "self").mkdir(exist_ok=True)
    (proc / "self/stat").write_text("500 (reviveguard) S 400 1 1 0")
    (proc / "400").mkdir()
    (proc / "400/stat").write_text("400 (sshd) S 1 1 1 0")
    ss = 'ESTAB 0 0 10.0.0.2:22 10.0.0.1:5555 users:(("sshd",pid=400,fd=4),("sshd",pid=390,fd=4))\n'
    base = ctx.runner
    ctx.runner = lambda args, timeout=None: (
        CommandResult(tuple(args), 0, ss) if args[:2] == ["ss", "-H"] else base(args, timeout)
    )
    assert current_connection(ctx) == ("10.0.0.1", "5555")
    assert session_auth_method(ctx) == "publickey"


def test_no_log_at_all_means_unknown(make_ctx, fake_root):
    ctx = root_host(make_ctx, fake_root, "")
    assert session_auth_method(ctx) is None
    runner = FakeRunner({JOURNAL: CommandResult(JOURNAL, 1, "", "no journal")})
    ctx.runner = runner
    assert session_auth_method(ctx) is None


# ---------- rollback reloads the service ----------


def test_rollback_reloads_ssh_after_restoring_files(
    make_ctx, fake_root, tmp_path, capsys, monkeypatch
):
    from reviveguard import cli

    build_host(fake_root, {"alice": {"uid": 1000, "sudo": True, "key": True}}, SSHD_MAIN)
    store = Store(tmp_path / "state")
    target = fake_root / "etc/ssh/sshd_config.d/00-reviveguard-x.conf"
    op = begin_operation(store, "SSH-002", "ssh.x", "x", [target], reload_service="ssh")
    target.write_text("PasswordAuthentication no\n")
    mark_applied(store, op)
    runner = ssh_runner()
    ctx = make_ctx(runner=runner)
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    args = ["--lang", "en", "--state-dir", str(tmp_path / "state"), "rollback", "--id", op.op_id]
    assert cli.main([*args, "--yes"], ctx=ctx) == 0
    out = capsys.readouterr().out
    assert not target.exists() and "service was reloaded" in out
    assert ["sshd", "-t"] in runner.calls and ["systemctl", "reload", "ssh"] in runner.calls
    assert not any(c[:2] == ["systemctl", "restart"] for c in runner.calls)


def test_rollback_does_not_reload_an_invalid_config(
    make_ctx, fake_root, tmp_path, capsys, monkeypatch
):
    from reviveguard import cli

    build_host(fake_root, {"alice": {"uid": 1000, "sudo": True, "key": True}}, SSHD_MAIN)
    store = Store(tmp_path / "state")
    target = fake_root / "etc/ssh/sshd_config.d/00-reviveguard-x.conf"
    op = begin_operation(store, "SSH-002", "ssh.x", "x", [target], reload_service="ssh")
    target.write_text("x\n")
    mark_applied(store, op)
    runner = ssh_runner(**{"x": None})
    runner.responses[("sshd", "-t")] = CommandResult(("sshd", "-t"), 255, "", "bad")
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    args = [
        "--lang",
        "en",
        "--state-dir",
        str(tmp_path / "state"),
        "rollback",
        "--id",
        op.op_id,
        "--yes",
    ]
    assert cli.main(args, ctx=make_ctx(runner=runner)) == 1
    assert ["systemctl", "reload", "ssh"] not in runner.calls
    assert "does not validate" in capsys.readouterr().err
