from __future__ import annotations

import pytest

from reviveguard import cli
from reviveguard.backup import Store
from reviveguard.checks import firewall as fw_checks
from reviveguard.fixes import REGISTRY
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import SSHD_MAIN, FakeRunner, build_host, ssh_runner

SS = """tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=2,fd=6))
tcp LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=2,fd=7))
tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=3,fd=6))
tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=4,fd=5))
udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*
udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*
"""
INACTIVE = "Status: inactive\n"


class UfwHost:
    """A fake ufw that becomes active after `ufw --force enable` and records every call."""

    def __init__(self, fake_root, ss=SS, fail_on=None):
        self.root, self.ss, self.fail_on = fake_root, ss, fail_on
        self.active, self.rules, self.calls = False, [], []
        self.base = ssh_runner()

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        if args[:2] == ["ss", "-H"]:
            return CommandResult(tuple(args), 0, self.ss)
        if args[0] == "ufw":
            if self.fail_on and self.fail_on in args:
                return CommandResult(tuple(args), 1, "", "ERROR: boom")
            if args[1:] == ["status", "verbose"] or args[1:] == ["status"]:
                text = "Status: active\n" if self.active else INACTIVE
                for rule in self.rules:
                    text += f"{rule}  ALLOW IN  Anywhere\n"
                return CommandResult(tuple(args), 0, text)
            if args[1] == "allow":
                self.rules.append(args[2])
            if args[1:] == ["--force", "enable"]:
                self.active = True
                (self.root / "etc/ufw/ufw.conf").write_text("ENABLED=yes\n")
            if args[1:] == ["--force", "disable"]:
                self.active = False
            return CommandResult(tuple(args), 0)
        return self.base(args, timeout)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


def setup(make_ctx, fake_root, **kw):
    build_host(fake_root, {"alice": {"uid": 1000, "sudo": True, "key": True}}, SSHD_MAIN)
    (fake_root / "etc/ufw").mkdir(parents=True)
    (fake_root / "etc/ufw/ufw.conf").write_text("ENABLED=no\n")
    host = UfwHost(fake_root, **kw)
    ctx = make_ctx(runner=host, env=kw.pop("env", {"SUDO_USER": "alice"}))
    result = next(r for r in fw_checks.run(ctx) if r.check_id == "FW-001")
    return host, ctx, result


def test_enable_keeps_reachable_services_and_blocks_risky_ones(make_ctx, fake_root, store):
    host, ctx, result = setup(make_ctx, fake_root)
    spec = REGISTRY["FW-001"](ctx, result)
    assert isinstance(spec, FixSpec) and spec.disruptive and spec.confirm_key
    allow = spec.change_args["allow"]
    for rule in ("22/tcp", "80/tcp", "443/tcp", "51820/udp"):
        assert rule in allow
    for never in ("68/udp", "6379", "5432"):
        assert never not in allow  # client port, risky exposed, loopback-only
    assert "6379/tcp" in spec.change_args["blocked"]
    outcome = run_fix(store, ctx, spec, confirm=lambda s: True)
    assert outcome.status == "applied" and host.active
    order = [c for c in host.calls if c[0] == "ufw" and c[1] in ("default", "allow", "--force")]
    assert order[0] == ["ufw", "default", "deny", "incoming"]
    assert order[-1] == ["ufw", "--force", "enable"]  # enabled only after every allow rule
    assert order.index(["ufw", "allow", "22/tcp"]) < order.index(["ufw", "--force", "enable"])


def test_no_confirmation_switches_the_firewall_off_again(make_ctx, fake_root, store):
    host, ctx, result = setup(make_ctx, fake_root)
    spec = REGISTRY["FW-001"](ctx, result)
    outcome = run_fix(store, ctx, spec, confirm=lambda s: False)
    assert outcome.status == "confirmation_failed" and outcome.reverted and outcome.revert_ok
    assert not host.active and ["ufw", "--force", "disable"] in host.calls
    assert (fake_root / "etc/ufw/ufw.conf").read_text() == "ENABLED=no\n"  # file restored too


def test_without_a_confirm_hook_the_change_is_reverted(make_ctx, fake_root, store):
    host, ctx, result = setup(make_ctx, fake_root)
    outcome = run_fix(store, ctx, REGISTRY["FW-001"](ctx, result))
    assert outcome.status == "confirmation_failed" and not host.active


def test_a_failing_ufw_command_reverts_and_disables(make_ctx, fake_root, store):
    host, ctx, result = setup(make_ctx, fake_root, fail_on="--force")
    spec = REGISTRY["FW-001"](ctx, result)
    outcome = run_fix(store, ctx, spec, confirm=lambda s: True)
    assert outcome.status == "apply_failed" and "boom" in outcome.detail and not host.active


def test_current_ssh_session_port_is_always_allowed(make_ctx, fake_root):
    host, ctx, result = setup(make_ctx, fake_root)
    ctx.env["SSH_CONNECTION"] = "203.0.113.5 50000 10.0.0.2 2200"
    spec = REGISTRY["FW-001"](ctx, result)
    assert "2200/tcp" in spec.change_args["allow"]


def test_all_ssh_ports_are_allowed_during_a_port_migration(make_ctx, fake_root):
    host, ctx, result = setup(make_ctx, fake_root)
    (fake_root / "etc/ssh/sshd_config").write_text(SSHD_MAIN + "Port 22\nPort 48222\n")
    spec = REGISTRY["FW-001"](ctx, result)
    assert "22/tcp" in spec.change_args["allow"] and "48222/tcp" in spec.change_args["allow"]


def test_refuses_without_ss_or_with_other_firewall_active(make_ctx, fake_root):
    host, ctx, result = setup(make_ctx, fake_root)
    host.ss = ""
    ctx.runner = lambda args, timeout=None: (
        CommandResult(tuple(args), None, missing=True) if args[0] == "ss" else host(args, timeout)
    )
    plan = REGISTRY["FW-001"](ctx, result)
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.ufw_no_ss"
    fwd = ("systemctl", "is-active", "firewalld")
    base = FakeRunner(
        {
            **{("ufw", "status", "verbose"): CommandResult(("u",), 0, INACTIVE)},
            fwd: CommandResult(fwd, 0, "active"),
        }
    )
    plan = REGISTRY["FW-001"](make_ctx(runner=base), result)
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.firewall_manual"


def test_cli_waits_for_confirmation_and_reverts_without_it(
    make_ctx, fake_root, capsys, monkeypatch, tmp_path
):
    host, ctx, _ = setup(make_ctx, fake_root)
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    answers = iter(["y", "yes"])
    monkeypatch.setattr("builtins.input", lambda p="": next(answers))
    monkeypatch.setattr("reviveguard.fixflow.read_confirmation", lambda timeout: False)
    args = ["--lang", "en", "--state-dir", str(tmp_path / "s"), "fix", "--check", "FW-001"]
    rc = cli.main(args, ctx=ctx)
    out = capsys.readouterr()
    assert rc == 1 and "reverted" in out.err and not host.active
    assert "Open a NEW terminal" in out.out and "no answer = the change is reverted" in out.out
    answers = iter(["y", "yes"])
    monkeypatch.setattr("builtins.input", lambda p="": next(answers))
    monkeypatch.setattr("reviveguard.fixflow.read_confirmation", lambda timeout: True)
    rc = cli.main(args, ctx=ctx)
    out = capsys.readouterr().out
    assert rc == 0 and host.active and "Applied and verified" in out and "ufw disable" in out


def test_read_confirmation_without_a_terminal_is_a_no(monkeypatch):
    import io

    from reviveguard import fixflow

    monkeypatch.setattr("sys.stdin", io.StringIO(""))  # EOF / no input
    assert fixflow.read_confirmation(0) is False
