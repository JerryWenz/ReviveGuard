from __future__ import annotations

from reviveguard.checks import fail2ban
from reviveguard.models import Severity, Status
from reviveguard.system import CommandResult

from .conftest import FakeRunner, build_host

OK = {"returncode": 0}


def r(args, out="", rc=0, err=""):
    return tuple(args), CommandResult(tuple(args), rc, out, err)


def f2b_runner(jails="sshd", backend="systemd", bantime="3600", maxretry="5", override=None):
    entries = [
        r(["fail2ban-client", "--version"], "1.0"),
        r(["systemctl", "is-active", "fail2ban"], "active"),
        r(["fail2ban-client", "-t"], "OK: configuration test is successful"),
        r(
            ["fail2ban-client", "status"],
            f"Status\n|- Number of jail:\t1\n`- Jail list:\t{jails}\n",
        ),
        r(["fail2ban-client", "get", "sshd", "backend"], backend),
        r(
            ["fail2ban-client", "get", "sshd", "logpath"],
            "Current monitored log file(s):\n`- /var/log/auth.log\n",
        ),
        r(["fail2ban-client", "get", "sshd", "bantime"], bantime),
        r(["fail2ban-client", "get", "sshd", "findtime"], "600"),
        r(["fail2ban-client", "get", "sshd", "maxretry"], maxretry),
        r(["journalctl", "--version"], "systemd 252"),
    ]
    table = dict(entries)
    table.update(override or {})
    return FakeRunner(table)


def by_id(results):
    return {x.check_id: x for x in results}


def host(fake_root):
    build_host(fake_root, {"alice": {"uid": 1000, "sudo": True, "key": True}})


def test_non_root_skipped(make_ctx):
    res = fail2ban.run(make_ctx(root=False))
    assert res[0].status is Status.SKIPPED and res[0].check_id == "F2B-000"


def test_not_installed(make_ctx):
    res = fail2ban.run(make_ctx(runner=FakeRunner()))
    assert [(x.check_id, x.status) for x in res] == [("F2B-001", Status.FAIL)]


def test_installed_not_running(make_ctx):
    runner = FakeRunner(
        dict(
            [
                r(["fail2ban-client", "--version"], "1.0"),
                r(["systemctl", "is-active", "fail2ban"], "inactive", 3),
            ]
        )
    )
    res = fail2ban.run(make_ctx(runner=runner))
    assert res[0].status is Status.FAIL and "not active" in res[0].evidence[0]


def test_healthy_setup(make_ctx, fake_root):
    host(fake_root)
    res = by_id(fail2ban.run(make_ctx(runner=f2b_runner())))
    assert set(res) == {"F2B-001", "F2B-002", "F2B-003", "F2B-004", "F2B-005"}
    assert all(x.status is Status.OK for x in res.values())


def test_missing_ssh_jail(make_ctx, fake_root):
    host(fake_root)
    res = by_id(fail2ban.run(make_ctx(runner=f2b_runner(jails="nginx-http-auth"))))
    assert res["F2B-002"].status is Status.FAIL and "nginx-http-auth" in res["F2B-002"].evidence[0]
    assert "F2B-004" not in res  # jail-specific checks need the jail


def test_ssh_jail_not_required_without_sshd(make_ctx):
    res = by_id(fail2ban.run(make_ctx(runner=f2b_runner())))  # no sshd_config in fake root
    assert set(res) == {"F2B-001", "F2B-003"}


def test_invalid_config(make_ctx, fake_root):
    host(fake_root)
    bad = r(["fail2ban-client", "-t"], "", 255, "ERROR  Failed during configuration: bad option")
    res = by_id(fail2ban.run(make_ctx(runner=f2b_runner(override=dict([bad])))))
    assert res["F2B-003"].status is Status.FAIL and "Failed during" in res["F2B-003"].evidence[0]


def test_status_unreadable(make_ctx, fake_root):
    host(fake_root)
    bad = r(["fail2ban-client", "status"], "", 255, "Permission denied")
    res = fail2ban.run(make_ctx(runner=f2b_runner(override=dict([bad]))))
    assert res[-1].status is Status.SKIPPED


def test_file_backend_with_existing_log_ok_and_missing_log_fails(make_ctx, fake_root):
    host(fake_root)
    runner = f2b_runner(backend="polling")
    res = by_id(fail2ban.run(make_ctx(runner=runner)))
    assert res["F2B-004"].status is Status.FAIL  # /var/log/auth.log absent in fake root
    log = fake_root / "var/log/auth.log"
    log.parent.mkdir(parents=True)
    log.write_text("")
    res = by_id(fail2ban.run(make_ctx(runner=runner)))
    assert res["F2B-004"].status is Status.OK


def test_systemd_backend_without_journalctl_fails(make_ctx, fake_root):
    host(fake_root)
    runner = f2b_runner()
    del runner.responses[("journalctl", "--version")]
    assert by_id(fail2ban.run(make_ctx(runner=runner)))["F2B-004"].status is Status.FAIL


def test_weak_ban_settings(make_ctx, fake_root):
    host(fake_root)
    weak = by_id(fail2ban.run(make_ctx(runner=f2b_runner(bantime="60"))))["F2B-005"]
    assert weak.status is Status.FAIL and weak.severity is Severity.LOW
    assert (
        by_id(fail2ban.run(make_ctx(runner=f2b_runner(maxretry="50"))))["F2B-005"].status
        is Status.FAIL
    )
    permanent = by_id(fail2ban.run(make_ctx(runner=f2b_runner(bantime="-1"))))["F2B-005"]
    assert permanent.status is Status.OK


def test_unparseable_ban_settings_are_not_guessed(make_ctx, fake_root):
    host(fake_root)
    res = by_id(fail2ban.run(make_ctx(runner=f2b_runner(bantime="weird"))))
    assert "F2B-005" not in res


def test_only_read_only_commands(make_ctx, fake_root):
    host(fake_root)
    runner = f2b_runner()
    fail2ban.run(make_ctx(runner=runner))
    for call in runner.calls:
        assert call[0] in ("fail2ban-client", "systemctl", "journalctl", "sshd")
        assert not any(w in call for w in ("reload", "restart", "start", "stop", "set"))
