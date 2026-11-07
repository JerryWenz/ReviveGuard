from __future__ import annotations

from reviveguard.checks import ssh
from reviveguard.models import Severity, Status
from reviveguard.system import CommandResult

from .conftest import FakeRunner, fake_stat, write_sshd_config


def by_id(results):
    return {r.check_id: r for r in results}


def test_parse_sshd_t_lowercases_and_keeps_first():
    out = "permitrootlogin yes\nPasswordAuthentication No\nhostkey /a\nhostkey /b\n"
    parsed = ssh.parse_sshd_t(out)
    assert parsed["permitrootlogin"] == "yes"
    assert parsed["passwordauthentication"] == "no"
    assert parsed["hostkey"] == "/a"


def test_skipped_when_ssh_not_installed(make_ctx):
    results = ssh.run(make_ctx())
    assert [r.status for r in results] == [Status.SKIPPED]
    assert results[0].check_id == "SSH-000"


def test_fallback_defaults_when_file_is_empty(make_ctx, fake_root):
    write_sshd_config(fake_root, "# nothing set\n")
    res = by_id(ssh.run(make_ctx()))
    assert res["SSH-001"].status is Status.OK  # prohibit-password default
    assert res["SSH-002"].status is Status.FAIL  # password auth defaults to yes
    assert "parsed" in res["SSH-002"].evidence[0]


def test_insecure_file_config(make_ctx, fake_root):
    write_sshd_config(
        fake_root,
        "PermitRootLogin yes\nPasswordAuthentication yes\n"
        "PermitEmptyPasswords yes\nPubkeyAuthentication no\n",
    )
    res = by_id(ssh.run(make_ctx()))
    assert res["SSH-001"].status is Status.FAIL and res["SSH-001"].severity is Severity.HIGH
    assert res["SSH-003"].severity is Severity.CRITICAL
    assert res["SSH-004"].status is Status.FAIL


def test_secure_file_config(make_ctx, fake_root):
    write_sshd_config(
        fake_root,
        "PermitRootLogin no\nPasswordAuthentication no\n"
        "PermitEmptyPasswords no\nPubkeyAuthentication yes\n",
    )
    results = ssh.run(make_ctx())
    assert all(r.status is Status.OK for r in results)


def test_first_occurrence_wins_and_equals_syntax(make_ctx, fake_root):
    write_sshd_config(fake_root, "PermitRootLogin=no\nPermitRootLogin yes\n")
    assert by_id(ssh.run(make_ctx()))["SSH-001"].status is Status.OK


def test_match_block_is_not_global(make_ctx, fake_root):
    write_sshd_config(
        fake_root, "PasswordAuthentication no\nMatch User bob\n    PasswordAuthentication yes\n"
    )
    assert by_id(ssh.run(make_ctx()))["SSH-002"].status is Status.OK


def test_include_directory_is_followed(make_ctx, fake_root):
    write_sshd_config(fake_root, "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n")
    write_sshd_config(fake_root, "PermitRootLogin yes\n", name="sshd_config.d/10-root.conf")
    # include appears first, so its value wins (first match semantics)
    assert by_id(ssh.run(make_ctx()))["SSH-001"].status is Status.FAIL


def test_sshd_t_preferred_over_file(make_ctx, fake_root):
    write_sshd_config(fake_root, "PermitRootLogin yes\n")
    runner = FakeRunner(
        {
            ("sshd", "-T"): CommandResult(
                ("sshd", "-T"),
                0,
                "permitrootlogin no\npasswordauthentication no\n"
                "permitemptypasswords no\npubkeyauthentication yes\n",
            )
        }
    )
    res = by_id(ssh.run(make_ctx(runner=runner)))
    assert res["SSH-001"].status is Status.OK
    assert "sshd -T" in res["SSH-001"].evidence[0]


def test_sshd_t_failure_falls_back_to_file(make_ctx, fake_root):
    write_sshd_config(fake_root, "PermitRootLogin yes\n")
    runner = FakeRunner(
        {("sshd", "-T"): CommandResult(("sshd", "-T"), 1, "", "no hostkeys available")}
    )
    assert by_id(ssh.run(make_ctx(runner=runner)))["SSH-001"].status is Status.FAIL


def test_only_read_only_commands_are_run(make_ctx, fake_root):
    write_sshd_config(fake_root, "")
    runner = FakeRunner()
    ssh.run(make_ctx(runner=runner))
    assert runner.calls == [["sshd", "-T"]]


def test_permissions_world_writable_fails(make_ctx, fake_root):
    write_sshd_config(fake_root, "")
    res = by_id(ssh.run(make_ctx(stat=fake_stat(0o100666))))
    assert res["SSH-005"].status is Status.FAIL
    assert "0666" in res["SSH-005"].evidence[0]


def test_permissions_wrong_owner_fails(make_ctx, fake_root):
    write_sshd_config(fake_root, "")
    assert by_id(ssh.run(make_ctx(stat=fake_stat(0o100600, uid=1000))))["SSH-005"].status is (
        Status.FAIL
    )


def test_permissions_0644_root_is_ok(make_ctx, fake_root):
    write_sshd_config(fake_root, "")
    assert by_id(ssh.run(make_ctx(stat=fake_stat(0o100644))))["SSH-005"].status is Status.OK


def test_permission_error_on_config_is_skipped_not_crash(make_ctx, fake_root):
    path = write_sshd_config(fake_root, "PermitRootLogin yes\n")
    path.chmod(0)
    import os

    if os.geteuid() == 0:  # root ignores mode bits; emulate the failure instead
        ctx = make_ctx()
        ctx.read_text = lambda p: None  # type: ignore[method-assign]
    else:
        ctx = make_ctx()
    assert [r.status for r in ssh.run(ctx)] == [Status.SKIPPED]
    path.chmod(0o600)
