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
    assert parsed["passwordauthentication"] == "No"  # case kept; checks compare lowercase
    assert parsed["hostkey"] == "/a"


def test_case_preserved_and_multivalued_keys_accumulate():
    parsed = ssh.parse_sshd_t("allowusers Alice\nallowusers bob\nauthorizedkeysfile .ssh/Keys\n")
    assert parsed["allowusers"] == "Alice bob"
    assert parsed["authorizedkeysfile"] == ".ssh/Keys"


def test_mixed_case_value_is_understood(make_ctx, fake_root):
    write_sshd_config(fake_root, "PermitRootLogin YES\n")
    assert by_id(ssh.run(make_ctx()))["SSH-001"].status is Status.FAIL


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
        "PermitEmptyPasswords no\nPubkeyAuthentication yes\n"
        "X11Forwarding no\nMaxAuthTries 3\nLoginGraceTime 30\nPort 49222\n",
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


def test_parse_seconds():
    assert ssh.parse_seconds("120") == 120 and ssh.parse_seconds("2m") == 120
    assert ssh.parse_seconds("1h30m") == 5400 and ssh.parse_seconds("") is None
    assert ssh.parse_seconds("abc") is None


def test_hardening_defaults_are_flagged(make_ctx, fake_root):
    write_sshd_config(fake_root, "X11Forwarding yes\n")
    res = by_id(ssh.run(make_ctx()))
    for check_id in ("SSH-006", "SSH-007", "SSH-008", "SSH-010"):
        assert res[check_id].status is Status.FAIL, check_id
    assert "SSH-009" not in res and "SSH-011" not in res  # need sshd -T / two ports


def test_grace_time_with_units_and_zero(make_ctx, fake_root):
    write_sshd_config(fake_root, "LoginGraceTime 30s\n")
    assert by_id(ssh.run(make_ctx()))["SSH-008"].status is Status.OK
    write_sshd_config(fake_root, "LoginGraceTime 0\n")
    assert by_id(ssh.run(make_ctx()))["SSH-008"].status is Status.FAIL


def test_custom_port_is_not_default_and_migration_is_reported(make_ctx, fake_root):
    write_sshd_config(fake_root, "Port 22\nPort 49222\n")
    res = by_id(ssh.run(make_ctx()))
    assert res["SSH-010"].status is Status.OK
    assert res["SSH-011"].status is Status.FAIL and "49222" in res["SSH-011"].evidence[0]


SSHD_T_WEAK = (
    "ciphers aes256-gcm@openssh.com,aes128-cbc,3des-cbc\n"
    "macs hmac-sha2-256,hmac-md5\n"
    "kexalgorithms curve25519-sha256,diffie-hellman-group14-sha1\n"
    "port 22\n"
)


def test_weak_algorithms_only_from_effective_config(make_ctx, fake_root):
    write_sshd_config(fake_root, "")
    runner = FakeRunner({("sshd", "-T"): CommandResult(("sshd", "-T"), 0, SSHD_T_WEAK)})
    r = by_id(ssh.run(make_ctx(runner=runner)))["SSH-009"]
    assert r.status is Status.FAIL and r.severity is Severity.MEDIUM
    text = " ".join(r.evidence)
    assert "aes128-cbc" in text and "3des-cbc" in text and "hmac-md5" in text
    assert "diffie-hellman-group14-sha1" in text and "aes256-gcm" not in text
    good = "ciphers aes256-gcm@openssh.com\nmacs hmac-sha2-256\nkexalgorithms curve25519-sha256\n"
    runner = FakeRunner({("sshd", "-T"): CommandResult(("sshd", "-T"), 0, good)})
    assert by_id(ssh.run(make_ctx(runner=runner)))["SSH-009"].status is Status.OK
