from __future__ import annotations

import json

from reviveguard import rollback
from reviveguard.backup import Store
from reviveguard.checks import fail2ban as checks
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.fixes import fail2ban as fixes
from reviveguard.models import Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult
from reviveguard.verification import verify_check_passes

from .conftest import SSHD_MAIN, build_host


class Fail2banHost:
    """Fake fail2ban: the sshd jail appears only after a reload with the drop-in present."""

    def __init__(self, fake_root, reload_ok=True, config_ok=True, installed=True):
        self.root, self.reload_ok, self.config_ok, self.installed = (
            fake_root,
            reload_ok,
            config_ok,
            installed,
        )
        self.calls = []
        self.reloaded = False

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        res = lambda out="", rc=0, err="": CommandResult(tuple(args), rc, out, err)  # noqa: E731
        if args[0] == "fail2ban-client" and not self.installed:
            return CommandResult(tuple(args), None, missing=True)
        if args == ["fail2ban-client", "-t"]:
            return res(rc=0 if self.config_ok else 255, err="" if self.config_ok else "bad config")
        if args == ["fail2ban-client", "--version"]:
            return res("1.0")
        if args in (
            ["systemctl", "is-active", "fail2ban"],
            ["systemctl", "is-active", "--quiet", "fail2ban"],
        ):
            return res("active")
        if args == ["fail2ban-client", "reload"]:
            self.reloaded = self.reload_ok
            return res(rc=0 if self.reload_ok else 1)
        if args == ["fail2ban-client", "status"]:
            dropin = self.root / "etc/fail2ban/jail.d/reviveguard-sshd.local"
            jails = "nginx, sshd" if (self.reloaded and dropin.exists()) else "nginx"
            return res(f"Status\n`- Jail list:\t{jails}\n")
        if args[:3] == ["fail2ban-client", "get", "sshd"]:
            values = {"backend": "systemd", "bantime": "3600", "findtime": "600", "maxretry": "5"}
            return res(values.get(args[3], ""))
        if args == ["journalctl", "--version"]:
            return res("systemd 252")
        return CommandResult(tuple(args), None, missing=True)


def setup(make_ctx, fake_root, **kw):
    build_host(fake_root, {"alice": {"uid": 1000, "sudo": True, "key": True}}, SSHD_MAIN)
    (fake_root / "etc/fail2ban/jail.d").mkdir(parents=True)
    host = Fail2banHost(fake_root, **kw)
    ctx = make_ctx(runner=host)
    failing = next(r for r in checks.run(ctx) if r.check_id == "F2B-002")
    assert failing.status is Status.FAIL
    return host, ctx, failing


def test_enable_ssh_jail_end_to_end(make_ctx, fake_root, tmp_path):
    host, ctx, failing = setup(make_ctx, fake_root)
    spec = REGISTRY["F2B-002"](ctx, failing)
    assert isinstance(spec, FixSpec) and not spec.disruptive
    store = Store(tmp_path / "state")
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied"
    dropin = fake_root / "etc/fail2ban/jail.d/reviveguard-sshd.local"
    assert "[sshd]\nenabled = true\nport = 22" in dropin.read_text()
    assert "backend" not in dropin.read_text()  # auth.log/journal layout unknown in this fake
    assert ["fail2ban-client", "reload"] in host.calls
    assert not any(c[:2] == ["systemctl", "restart"] for c in host.calls)
    assert verify_check_passes(ctx, "F2B-002").ok
    assert rollback.execute_rollback(store, rollback.plan_rollback(store, outcome.op_id)) == []
    assert not dropin.exists()


def test_custom_ssh_port_is_used(make_ctx, fake_root):
    host, ctx, failing = setup(make_ctx, fake_root)
    (fake_root / "etc/ssh/sshd_config").write_text(SSHD_MAIN + "Port 2222\n")
    spec = fixes.plan_ssh_jail(ctx, failing)
    assert spec.change_args["port"] == "2222"


def test_reload_failure_reverts(make_ctx, fake_root, tmp_path):
    host, ctx, failing = setup(make_ctx, fake_root, reload_ok=False)
    outcome = run_fix(Store(tmp_path / "state"), ctx, fixes.plan_ssh_jail(ctx, failing))
    assert outcome.status == "activation_failed" and outcome.revert_ok
    assert not (fake_root / "etc/fail2ban/jail.d/reviveguard-sshd.local").exists()


def test_refuses_when_config_invalid(make_ctx, fake_root):
    host, ctx, failing = setup(make_ctx, fake_root)
    host.config_ok = False
    plan = fixes.plan_ssh_jail(ctx, failing)
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.fail2ban_config_invalid"


def test_refuses_without_jail_dir_or_fail2ban(make_ctx, fake_root):
    host, ctx, failing = setup(make_ctx, fake_root)
    (fake_root / "etc/fail2ban/jail.d").rmdir()
    assert fixes.plan_ssh_jail(ctx, failing).reason_key == "fix.reason.no_fail2ban_dir"
    host.installed = False
    assert fixes.plan_ssh_jail(ctx, failing).reason_key == "fix.reason.fail2ban_missing"


def test_firewall_findings_are_always_manual(make_ctx):
    from reviveguard.models import CheckResult, Severity

    result = CheckResult("FW-001", "firewall", Severity.MEDIUM, Status.FAIL, "t", "d", "r")
    for check_id in ("FW-002", "FW-003", "FW-004"):
        plan = REGISTRY[check_id](make_ctx(), result)
        assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.firewall_manual"
        assert check_id not in AUTOMATIC
    assert "FW-001" in AUTOMATIC  # only the ufw *package* install; enabling stays manual
    assert "F2B-002" in AUTOMATIC and "SSH-002" in AUTOMATIC


def test_verification_maps_check_prefixes(make_ctx):
    assert not verify_check_passes(make_ctx(root=False), "FW-001").ok  # module found, skipped
    assert verify_check_passes(make_ctx(), "ZZZ-1").detail.startswith("no check module")


def test_json_reports_automatic_fix_flag(make_ctx, capsys, monkeypatch, tmp_path):
    from reviveguard import cli

    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    ctx = make_ctx()
    cli.main(["--lang", "en", "audit", "--format", "json"], ctx=ctx)
    data = json.loads(capsys.readouterr().out)
    flags = {r["check_id"]: r["auto_fix_supported"] for r in data["results"]}
    assert flags.get("FW-001") is True and flags.get("UPD-005") is False
