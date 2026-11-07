from __future__ import annotations

import json

from reviveguard import cli

from .conftest import fake_stat, write_sshd_config


def test_resolve_language_priority():
    from reviveguard.config import Config

    assert cli.resolve_language("ru", Config(language="en"), {}) == "ru"
    assert cli.resolve_language(None, Config(language="ru"), {"LANG": "en_US"}) == "ru"
    assert cli.resolve_language(None, Config(), {"LANG": "ru_RU.UTF-8"}) == "ru"
    assert cli.resolve_language(None, Config(), {"LANG": "de_DE"}) == "en"
    assert cli.resolve_language("zz", Config(), {}) is None


def run_cli(args, ctx, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    rc = cli.main(args, ctx=ctx)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_audit_text_ru(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    write_sshd_config(fake_root, "PermitRootLogin yes\n")
    rc, out, _ = run_cli(["--lang", "ru", "audit"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 0
    assert "Язык: Русский" in out
    assert "[HIGH] Вход root по SSH" in out
    assert "HIGH:     1" in out


def test_audit_is_default_command_and_english(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    write_sshd_config(fake_root, "PermitRootLogin no\n")
    rc, out, _ = run_cli(["--lang", "en"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 0 and "[OK] SSH root login" in out and "Mode: Audit (read-only)" in out


def test_audit_json(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    write_sshd_config(fake_root, "PermitEmptyPasswords yes\n")
    ctx = make_ctx(stat=fake_stat(0o100600))
    rc, out, _ = run_cli(
        ["--lang", "en", "audit", "--format", "json"], ctx, capsys, monkeypatch, tmp_path
    )
    data = json.loads(out)
    assert rc == 0 and data["summary"]["CRITICAL"] == 1
    assert {r["check_id"] for r in data["results"]} >= {"SSH-001", "SSH-003"}


def test_audit_does_not_modify_filesystem(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    write_sshd_config(fake_root, "PermitRootLogin yes\n")
    before = sorted((p, p.stat().st_mtime_ns) for p in fake_root.rglob("*"))
    run_cli(["audit"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert before == sorted((p, p.stat().st_mtime_ns) for p in fake_root.rglob("*"))


def test_unsupported_language(make_ctx, capsys, monkeypatch, tmp_path):
    rc, _, err = run_cli(["--lang", "zz", "audit"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 2 and "zz" in err


def test_bad_config_returns_2(make_ctx, capsys, monkeypatch, tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("bogus = 1")
    rc, _, err = run_cli(["--config", str(bad), "audit"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 2 and "bogus" in err


def test_non_root_note(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    write_sshd_config(fake_root, "")
    _, out, _ = run_cli(["--lang", "en"], make_ctx(root=False), capsys, monkeypatch, tmp_path)
    assert "Not running as root" in out


def _make_op(tmp_path, content="PermitRootLogin yes\n"):
    from reviveguard.backup import Store, begin_operation, mark_applied

    f = tmp_path / "target.conf"
    f.write_text(content)
    store = Store(tmp_path / "state")
    op = begin_operation(store, "SSH-001", "ssh.x", "disable root login", [f])
    f.write_text("changed\n")
    mark_applied(store, op)
    return f, op


def test_history_empty_and_listing(make_ctx, capsys, monkeypatch, tmp_path):
    base = ["--lang", "en", "--state-dir", str(tmp_path / "state")]
    _, out, _ = run_cli([*base, "history"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert "No remediation history." in out
    _, op = _make_op(tmp_path)
    _, out, _ = run_cli([*base, "history"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert op.op_id in out and "SSH-001" in out and "applied" in out


def test_rollback_confirm_yes(make_ctx, capsys, monkeypatch, tmp_path):
    f, op = _make_op(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    args = ["--lang", "ru", "--state-dir", str(tmp_path / "state"), "rollback", "--id", op.op_id]
    rc, out, _ = run_cli(args, make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 0 and "выполнен и проверен" in out and f.read_text() == "PermitRootLogin yes\n"
    assert "восстановить" in out


def test_rollback_declined_changes_nothing(make_ctx, capsys, monkeypatch, tmp_path):
    f, op = _make_op(tmp_path)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    args = ["--lang", "en", "--state-dir", str(tmp_path / "state"), "rollback"]
    rc, out, _ = run_cli(args, make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 1 and "Cancelled" in out and f.read_text() == "changed\n"


def test_rollback_eof_is_decline(make_ctx, capsys, monkeypatch, tmp_path):
    f, _ = _make_op(tmp_path)

    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    args = ["--lang", "en", "--state-dir", str(tmp_path / "state"), "rollback"]
    rc, _, _ = run_cli(args, make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 1 and f.read_text() == "changed\n"


def test_rollback_yes_flag_and_warning(make_ctx, capsys, monkeypatch, tmp_path):
    f, op = _make_op(tmp_path)
    f.write_text("admin edit\n")
    args = ["--lang", "en", "--state-dir", str(tmp_path / "state"), "rollback", "--yes"]
    rc, out, _ = run_cli(args, make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 0 and "WARNING" in out and f.read_text() == "PermitRootLogin yes\n"


def test_rollback_nothing_and_unknown_id(make_ctx, capsys, monkeypatch, tmp_path):
    base = ["--lang", "en", "--state-dir", str(tmp_path / "state"), "rollback"]
    rc, out, _ = run_cli(base, make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 0 and "No operations available" in out
    rc, _, err = run_cli([*base, "--id", "FIX-2026-042"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 1 and "not found" in err
    rc, _, err = run_cli([*base, "--id", "../x"], make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 1


# ---------- fix command ----------


def fix_args(tmp_path, *extra, lang="en"):
    return ["--lang", lang, "--state-dir", str(tmp_path / "state"), "fix", *extra]


def answers(monkeypatch, *values):
    it = iter(values)

    def fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", fake_input)


def fix_host(fake_root):
    from .conftest import SSHD_MAIN, build_host

    users = {"alice": {"uid": 1000, "sudo": True, "key": True}}
    build_host(fake_root, users, SSHD_MAIN + "PermitEmptyPasswords yes\n")


def fix_ctx(make_ctx, **kw):
    from .conftest import ssh_runner

    return make_ctx(runner=ssh_runner(), env={"SUDO_USER": "alice"}, **kw)


def dropin(fake_root, name):
    return fake_root / f"etc/ssh/sshd_config.d/00-reviveguard-{name}.conf"


def test_fix_interactive_apply_one_skip_other(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    fix_host(fake_root)
    answers(monkeypatch, "y", "n")
    rc, out, _ = run_cli(fix_args(tmp_path), fix_ctx(make_ctx), capsys, monkeypatch, tmp_path)
    # SSH-002 asks y, then the disruptive confirmation gets "n" -> skipped; SSH-003 gets EOF -> quit
    assert rc == 0
    assert "Skipped." in out and "Stopped by user." in out
    assert not dropin(fake_root, "passwordauthentication").exists()


def test_fix_applies_after_confirmation_and_verifies(
    make_ctx, fake_root, capsys, monkeypatch, tmp_path
):
    fix_host(fake_root)
    answers(monkeypatch, "y")  # SSH-003 is not disruptive: one confirmation is enough
    rc, out, _ = run_cli(
        fix_args(tmp_path, "--check", "ssh-003"), fix_ctx(make_ctx), capsys, monkeypatch, tmp_path
    )
    assert rc == 0 and "Applied and verified" in out and "Applied: 1" in out
    assert "PermitEmptyPasswords no" in dropin(fake_root, "permitemptypasswords").read_text()
    # the shown plan includes risk, change, files and the service note
    assert "Proposed change" in out and "sshd_config.d" in out and "reloaded (not restarted)" in out


def test_fix_disruptive_requires_separate_yes(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    fix_host(fake_root)
    answers(monkeypatch, "y", "y")  # "y" is not enough for the disruptive confirmation
    rc, out, _ = run_cli(
        fix_args(tmp_path, "--check", "SSH-002"), fix_ctx(make_ctx), capsys, monkeypatch, tmp_path
    )
    assert "Skipped." in out and not dropin(fake_root, "passwordauthentication").exists()
    answers(monkeypatch, "y", "yes")
    rc, out, _ = run_cli(
        fix_args(tmp_path, "--check", "SSH-002"), fix_ctx(make_ctx), capsys, monkeypatch, tmp_path
    )
    assert rc == 0 and dropin(fake_root, "passwordauthentication").exists()


def test_fix_no_terminal_changes_nothing(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    fix_host(fake_root)
    answers(monkeypatch)  # immediate EOF
    rc, out, _ = run_cli(fix_args(tmp_path), fix_ctx(make_ctx), capsys, monkeypatch, tmp_path)
    assert rc == 0 and not list((fake_root / "etc/ssh/sshd_config.d").iterdir())


def test_fix_requires_root(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    fix_host(fake_root)
    rc, _, err = run_cli(
        fix_args(tmp_path), fix_ctx(make_ctx, root=False), capsys, monkeypatch, tmp_path
    )
    assert rc == 1 and "must be run as root" in err


def test_fix_disabled_in_config(make_ctx, capsys, monkeypatch, tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text("[remediation]\nenabled = false\n")
    args = ["--config", str(cfg), *fix_args(tmp_path)]
    rc, _, err = run_cli(args, make_ctx(), capsys, monkeypatch, tmp_path)
    assert rc == 1 and "disabled" in err


def test_fix_lists_manual_when_unsafe_and_russian(
    make_ctx, fake_root, capsys, monkeypatch, tmp_path
):
    from .conftest import SSHD_MAIN, build_host, ssh_runner

    build_host(fake_root, {"alice": {"uid": 1000, "sudo": True, "password": True}}, SSHD_MAIN)
    ctx = make_ctx(runner=ssh_runner(), env={"SUDO_USER": "alice", "SSH_CONNECTION": "a b c d"})
    answers(monkeypatch)
    rc, out, _ = run_cli(
        fix_args(tmp_path, "--check", "SSH-002", lang="ru"), ctx, capsys, monkeypatch, tmp_path
    )
    assert rc == 0 and "Требуется ручное исправление" in out and "вручную: 1" in out
    assert not list((fake_root / "etc/ssh/sshd_config.d").iterdir())


def test_fix_reports_failure_and_revert(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    from .test_fixes_ssh import FlakyRunner

    fix_host(fake_root)
    ctx = fix_ctx(make_ctx)
    ctx.runner = FlakyRunner(ctx.runner)
    answers(monkeypatch, "y")
    rc, _, err = run_cli(
        fix_args(tmp_path, "--check", "SSH-003"), ctx, capsys, monkeypatch, tmp_path
    )
    assert rc == 1 and "was reverted" in err and "restored" in err
    assert not dropin(fake_root, "permitemptypasswords").exists()


def test_fix_nothing_to_do(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    fix_host(fake_root)
    rc, out, _ = run_cli(
        fix_args(tmp_path, "--check", "NOPE-1"), fix_ctx(make_ctx), capsys, monkeypatch, tmp_path
    )
    assert rc == 0 and "No matching findings" in out
