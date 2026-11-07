from __future__ import annotations

import pytest

from reviveguard.backup import Store
from reviveguard.checks import fail2ban as f2b_checks
from reviveguard.checks import firewall as fw_checks
from reviveguard.fixes import REGISTRY
from reviveguard.models import Status
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


def test_firewall_fix_is_manual_when_a_tool_exists(make_ctx):
    runner = FakeRunner(dict([cr(["ufw", "status", "verbose"], "Status: inactive\n")]))
    ctx = make_ctx(runner=runner)
    plan = REGISTRY["FW-001"](ctx, fw_failure(ctx))
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.firewall_manual"


def f2b_failure(ctx):
    return next(r for r in f2b_checks.run(ctx) if r.check_id == "F2B-001")


def test_install_fail2ban_whitelists_current_client(make_ctx, fake_root, store):
    (fake_root / "etc/fail2ban/jail.d").mkdir(parents=True)
    host = NoToolsHost()
    ctx = make_ctx(runner=host, env={"SSH_CONNECTION": "203.0.113.7 51234 10.0.0.2 22"})
    spec = REGISTRY["F2B-001"](ctx, f2b_failure(ctx))
    assert isinstance(spec, FixSpec) and spec.reversible and len(spec.files) == 1
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied" and "fail2ban" in host.installed
    text = (fake_root / "etc/fail2ban/jail.d/reviveguard-ignoreip.local").read_text()
    assert "ignoreip = 127.0.0.1/8 ::1 203.0.113.7" in text
    assert ["fail2ban-client", "reload"] in host.calls


def test_install_fail2ban_without_known_client_is_non_reversible(make_ctx):
    ctx = make_ctx(runner=NoToolsHost(), env={})
    spec = REGISTRY["F2B-001"](ctx, f2b_failure(ctx))
    assert isinstance(spec, FixSpec) and not spec.reversible and spec.files == []


def test_hostile_client_address_is_ignored(make_ctx):
    ctx = make_ctx(runner=NoToolsHost(), env={"SSH_CONNECTION": "1.2.3.4; rm -rf / 1 2 3"})
    from reviveguard.fixes import fail2ban as fixes

    assert fixes.client_ip(ctx) is None


def test_fail2ban_installed_but_inactive_is_manual(make_ctx):
    host = NoToolsHost(installed={"fail2ban"})
    ctx = make_ctx(runner=host)
    host.installed = set()  # produce the failing result first...
    result = f2b_failure(make_ctx(runner=NoToolsHost()))
    host.installed = {"fail2ban"}
    plan = REGISTRY["F2B-001"](ctx, result)
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.fail2ban_inactive"
    assert result.status is Status.FAIL
