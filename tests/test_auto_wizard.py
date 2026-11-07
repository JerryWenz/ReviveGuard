from __future__ import annotations

from reviveguard import cli

from .conftest import SSHD_MAIN, build_host, ssh_runner

EXTRA = "PermitEmptyPasswords yes\nPubkeyAuthentication no\n"


def host(make_ctx, fake_root):
    users = {"alice": {"uid": 1000, "sudo": True, "key": True}}
    build_host(fake_root, users, SSHD_MAIN + EXTRA)
    return make_ctx(runner=ssh_runner(), env={"SUDO_USER": "alice"})


def dropin(fake_root, name):
    return fake_root / f"etc/ssh/sshd_config.d/00-reviveguard-{name}.conf"


def run(args, ctx, capsys, monkeypatch, tmp_path, answers=()):
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    it = iter(answers)

    def fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", fake_input)
    base = ["--lang", "en", "--state-dir", str(tmp_path / "state")]
    rc = cli.main([*base, *args], ctx=ctx)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_auto_yes_applies_only_eligible_and_explains_the_rest(
    make_ctx, fake_root, capsys, monkeypatch, tmp_path
):
    ctx = host(make_ctx, fake_root)
    rc, out, _ = run(
        ["fix", "--auto", "--yes", "--category", "ssh"], ctx, capsys, monkeypatch, tmp_path
    )
    assert rc == 0
    assert dropin(fake_root, "pubkeyauthentication").exists()  # MEDIUM, safe -> applied
    assert not dropin(fake_root, "permitemptypasswords").exists()  # CRITICAL -> needs policy
    assert not dropin(fake_root, "passwordauthentication").exists()  # disruptive -> not automatic
    assert "Reviewed set of fixes:" in out and "[1/" in out
    assert "allow_critical = true" in out  # SSH-003 (CRITICAL) waits for a policy decision
    assert "public key authentication is disabled" in out  # SSH-002 is manual, with the reason


def test_auto_asks_once_and_default_is_no(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    ctx = host(make_ctx, fake_root)
    rc, out, _ = run(
        ["fix", "--auto", "--category", "ssh"], ctx, capsys, monkeypatch, tmp_path, answers=[""]
    )
    assert rc == 0 and "Skipped." in out and not dropin(fake_root, "pubkeyauthentication").exists()
    rc, out, _ = run(
        ["fix", "--auto", "--category", "ssh"], ctx, capsys, monkeypatch, tmp_path, answers=["y"]
    )
    assert dropin(fake_root, "pubkeyauthentication").exists()


def test_auto_without_terminal_never_applies(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    ctx = host(make_ctx, fake_root)
    rc, _, _ = run(["fix", "--auto", "--category", "ssh"], ctx, capsys, monkeypatch, tmp_path)
    assert not list((fake_root / "etc/ssh/sshd_config.d").iterdir())


def test_policy_in_config_allows_critical(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    ctx = host(make_ctx, fake_root)
    cfg = tmp_path / "c.toml"
    cfg.write_text("[remediation]\nallow_critical = true\n")
    rc, out, _ = run(
        ["--config", str(cfg), "fix", "--auto", "--yes", "--category", "ssh"],
        ctx,
        capsys,
        monkeypatch,
        tmp_path,
    )
    assert rc == 0 and dropin(fake_root, "permitemptypasswords").exists()
    assert dropin(fake_root, "pubkeyauthentication").exists()


def test_auto_stops_after_first_failure(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    from reviveguard.system import CommandResult

    ctx = host(make_ctx, fake_root)
    base = ctx.runner

    def runner(args, timeout=None):  # a bad new config: sshd -t fails once a drop-in exists
        dropins = list((fake_root / "etc/ssh/sshd_config.d").iterdir())
        if args == ["sshd", "-t"] and dropins:
            return CommandResult(tuple(args), 255, "", "Bad configuration option")
        return base(args, timeout)

    ctx.runner = runner
    cfg = tmp_path / "c.toml"
    cfg.write_text("[remediation]\nallow_critical = true\n")
    args = ["--config", str(cfg), "fix", "--auto", "--yes", "--category", "ssh"]
    rc, out, err = run(args, ctx, capsys, monkeypatch, tmp_path)
    assert rc == 1 and "Stopped after a failure" in err
    assert not list((fake_root / "etc/ssh/sshd_config.d").iterdir())  # failed fix was reverted
    assert "[2/" not in out  # nothing ran after the first failure


def test_wizard_runs_all_steps_and_saves_report(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    ctx = host(make_ctx, fake_root)
    rc, out, _ = run(["wizard"], ctx, capsys, monkeypatch, tmp_path, answers=["", "n", "n", "n"])
    assert rc == 0
    for step in ("[1/4]", "[2/4]", "[3/4]", "[4/4]"):
        assert step in out
    assert "Found" in out and "Report saved:" in out
    assert dropin(fake_root, "pubkeyauthentication").exists()  # default answer Y on the safe set
    reports = list((tmp_path / "state" / "reports").glob("report-*.md"))
    assert len(reports) == 1 and "# Security report" in reports[0].read_text()
    assert (reports[0].stat().st_mode & 0o777) == 0o600


def test_wizard_needs_root_and_respects_decline(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    ctx = host(make_ctx, fake_root)
    ctx.running_as_root = False
    rc, _, err = run(["wizard"], ctx, capsys, monkeypatch, tmp_path)
    assert rc == 1 and "must be run as root" in err
    ctx.running_as_root = True
    rc, out, _ = run(["wizard"], ctx, capsys, monkeypatch, tmp_path, answers=["n"])
    assert not dropin(fake_root, "pubkeyauthentication").exists()


def test_wizard_yes_flag_applies_safe_set_without_asking(
    make_ctx, fake_root, capsys, monkeypatch, tmp_path
):
    ctx = host(make_ctx, fake_root)
    rc, out, _ = run(["wizard", "--yes"], ctx, capsys, monkeypatch, tmp_path)
    assert rc == 0 and dropin(fake_root, "pubkeyauthentication").exists()
