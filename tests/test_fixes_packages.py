from __future__ import annotations

import pytest

from reviveguard.backup import Store
from reviveguard.checks import fail2ban as f2b_checks
from reviveguard.checks import firewall as fw_checks
from reviveguard.fixes import REGISTRY
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import FakeRunner
from .test_updates import AptHost, cr


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


class NoToolsHost(AptHost):
    """apt present, no firewall tools, fail2ban absent until installed."""

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        if args[0] == "fail2ban-client":
            if "fail2ban" not in self.installed:
                return CommandResult(tuple(args), None, missing=True)
            return CommandResult(tuple(args), 0, "")
        if args[:3] == ["systemctl", "is-active", "fail2ban"]:
            return CommandResult(tuple(args), 0 if "fail2ban" in self.installed else 3, "active")
        if args[0] in ("ufw", "nft", "iptables"):
            return CommandResult(tuple(args), None, missing=True)
        if args[:3] == ["systemctl", "is-active", "firewalld"]:
            return CommandResult(tuple(args), 3, "inactive")
        self.calls.pop()  # AptHost records the call itself
        return super().__call__(args, timeout)


def fw_failure(ctx):
    return next(r for r in fw_checks.run(ctx) if r.check_id == "FW-001")


def test_install_ufw_when_no_tool_and_leaves_it_disabled(make_ctx, store):
    host = NoToolsHost()
    ctx = make_ctx(runner=host)
    spec = REGISTRY["FW-001"](ctx, fw_failure(ctx))
    assert isinstance(spec, FixSpec) and not spec.reversible
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied" and "ufw" in host.installed
    assert not any(c[:2] == ["ufw", "enable"] or "enable" in c for c in host.calls)


def test_ufw_install_failure_is_reported(make_ctx, store):
    host = NoToolsHost(fail_on="ufw")
    ctx = make_ctx(runner=host)
    outcome = run_fix(store, ctx, REGISTRY["FW-001"](ctx, fw_failure(ctx)))
    assert outcome.status == "apply_failed" and "ufw" not in host.installed


def test_firewall_fix_is_manual_when_another_tool_is_in_use(make_ctx):
    runner = FakeRunner(dict([cr(["iptables", "-S"], "-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n")]))
    ctx = make_ctx(runner=runner)
    plan = REGISTRY["FW-001"](ctx, fw_failure(ctx))
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.firewall_manual"


def f2b_failure(ctx):
    return next(r for r in f2b_checks.run(ctx) if r.check_id == "F2B-001")


class BareHost(NoToolsHost):
    """A bare cloud image: no fail2ban, no iptables/nft, journald only (no auth.log)."""

    def __init__(self, tmp_root, fail2ban_installed=False, config_error=None, **kw):
        super().__init__(**kw)
        self.root, self.config_error, self.started = tmp_root, config_error, False
        if fail2ban_installed:
            self.installed.add("fail2ban")

    def __call__(self, args, timeout=None):
        if args[0] == "iptables" and "iptables" in self.installed:
            self.calls.append(list(args))
            return CommandResult(tuple(args), 0, "iptables v1.8")
        if args == ["fail2ban-client", "-t"] and "fail2ban" in self.installed:
            self.calls.append(list(args))
            if self.config_error:
                return CommandResult(tuple(args), 255, "", self.config_error)
            return CommandResult(tuple(args), 0, "OK")
        if args[:2] == ["systemctl", "is-active"] and args[-1] == "fail2ban":
            self.calls.append(list(args))
            return CommandResult(tuple(args), 0 if self.started else 3, "active")
        if args == ["systemctl", "enable", "--now", "fail2ban"]:
            self.calls.append(list(args))
            self.started = True
            return CommandResult(tuple(args), 0)
        return super().__call__(args, timeout)


def bare_root(fake_root, auth_log=False, journal=True, action=True):
    (fake_root / "etc/fail2ban/jail.d").mkdir(parents=True)
    if action:
        (fake_root / "etc/fail2ban/action.d").mkdir(parents=True)
        (fake_root / "etc/fail2ban/action.d/iptables-multiport.conf").write_text("")
    if journal:
        (fake_root / "run/systemd/journal").mkdir(parents=True)
    if auth_log:
        (fake_root / "var/log").mkdir(parents=True)
        (fake_root / "var/log/auth.log").write_text("")


CLIENT = {"SSH_CONNECTION": "203.0.113.7 51234 10.0.0.2 22"}


def test_bare_image_gets_everything_fail2ban_needs(make_ctx, fake_root, store):
    bare_root(fake_root)
    host = BareHost(fake_root)
    ctx = make_ctx(runner=host, env=CLIENT)
    spec = REGISTRY["F2B-001"](ctx, f2b_failure(ctx))
    assert isinstance(spec, FixSpec) and spec.reversible
    assert spec.packages == ["fail2ban", "python3-systemd", "iptables"]
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied", outcome
    assert {"fail2ban", "python3-systemd", "iptables"} <= host.installed
    text = (fake_root / "etc/fail2ban/jail.d/reviveguard-base.local").read_text()
    assert "ignoreip = 127.0.0.1/8 ::1 203.0.113.7" in text
    assert "backend = systemd" in text  # no auth.log on this image
    assert "banaction = iptables-multiport" in text
    assert ["systemctl", "enable", "--now", "fail2ban"] in host.calls
    assert not any("restart" in c for c in host.calls)


def test_auth_log_present_means_no_journal_backend(make_ctx, fake_root):
    bare_root(fake_root, auth_log=True)
    from reviveguard.fixes import fail2ban as fixes

    assert not fixes.needs_journal_backend(make_ctx())


def test_no_journal_and_no_auth_log_keeps_default_backend(make_ctx, fake_root):
    bare_root(fake_root, journal=False)
    from reviveguard.fixes import fail2ban as fixes

    assert not fixes.needs_journal_backend(make_ctx())


def test_unknown_ban_mechanism_is_not_forced(make_ctx, fake_root):
    bare_root(fake_root, action=False)
    from reviveguard.fixes import fail2ban as fixes

    ctx = make_ctx(runner=BareHost(fake_root, **{}))
    assert fixes.choose_banaction(ctx) is None


def test_installed_but_stopped_fail2ban_is_started_not_reinstalled(make_ctx, fake_root, store):
    bare_root(fake_root)
    host = BareHost(fake_root, fail2ban_installed=True)
    host.installed |= {"python3-systemd", "iptables"}
    ctx = make_ctx(runner=host, env=CLIENT)
    spec = REGISTRY["F2B-001"](ctx, f2b_failure(ctx))
    assert isinstance(spec, FixSpec) and spec.packages == []
    assert run_fix(store, ctx, spec).status == "applied" and host.started
    assert not any(c[:1] == ["env"] and "install" in c for c in host.calls)


def test_validation_failure_reverts_files_but_packages_remain(make_ctx, fake_root, store):
    bare_root(fake_root)
    error = "ERROR Failed during configuration: Have not found any log file for sshd jail"
    host = BareHost(fake_root, config_error=error)
    ctx = make_ctx(runner=host, env=CLIENT)
    spec = REGISTRY["F2B-001"](ctx, f2b_failure(ctx))
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "validation_failed" and outcome.reverted and outcome.revert_ok
    assert not (fake_root / "etc/fail2ban/jail.d/reviveguard-base.local").exists()
    assert "fail2ban" in host.installed and not host.started  # packages are never removed
    assert "Have not found any log file" in outcome.detail


def test_cli_warns_that_packages_remain(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    from reviveguard import cli

    bare_root(fake_root)
    host = BareHost(fake_root, config_error="ERROR Failed during configuration")
    ctx = make_ctx(runner=host, env=CLIENT)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    args = ["--lang", "en", "--state-dir", str(tmp_path / "s"), "fix", "--check", "F2B-001"]
    rc = cli.main(args, ctx=ctx)
    err = capsys.readouterr().err
    assert rc == 1 and "was reverted" in err and "installed packages stay" in err
    assert "fail2ban, python3-systemd, iptables" in err


def test_hostile_client_address_is_ignored(make_ctx):
    ctx = make_ctx(runner=NoToolsHost(), env={"SSH_CONNECTION": "1.2.3.4; rm -rf / 1 2 3"})
    from reviveguard.fixes import fail2ban as fixes

    assert fixes.client_ip(ctx) is None
