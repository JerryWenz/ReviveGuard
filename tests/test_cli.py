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
