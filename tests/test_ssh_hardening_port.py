from __future__ import annotations

import pytest

from reviveguard.backup import Store
from reviveguard.checks import ssh as ssh_checks
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.models import Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import SSHD_MAIN, FakeRunner, build_host, ssh_runner

ALICE = {"alice": {"uid": 1000, "sudo": True, "key": True}}


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


def failing(ctx, check_id):
    return next(
        r for r in ssh_checks.run(ctx) if r.check_id == check_id and r.status is Status.FAIL
    )


def plan(ctx, check_id):
    return REGISTRY[check_id](ctx, failing(ctx, check_id))


def dropin(fake_root, name):
    return fake_root / f"etc/ssh/sshd_config.d/{name}"


# ---------------- simple hardening ----------------


@pytest.mark.parametrize(
    ("check_id", "config", "name", "expect"),
    [
        ("SSH-006", "X11Forwarding yes\n", "00-reviveguard-x11forwarding.conf", "X11Forwarding no"),
        ("SSH-007", "MaxAuthTries 10\n", "00-reviveguard-maxauthtries.conf", "MaxAuthTries 4"),
        (
            "SSH-008",
            "LoginGraceTime 5m\n",
            "00-reviveguard-logingracetime.conf",
            "LoginGraceTime 30",
        ),
    ],
)
def test_simple_hardening_fixes(make_ctx, fake_root, store, check_id, config, name, expect):
    build_host(fake_root, ALICE, SSHD_MAIN + config)
    ctx = make_ctx(runner=ssh_runner(), env={"SUDO_USER": "alice"})
    spec = plan(ctx, check_id)
    assert isinstance(spec, FixSpec) and not spec.disruptive and check_id in AUTOMATIC
    assert run_fix(store, ctx, spec).status == "applied"
    assert expect in dropin(fake_root, name).read_text()
    assert ssh_checks.run(ctx) and failing_ids(ctx).isdisjoint({check_id})


def failing_ids(ctx):
    return {r.check_id for r in ssh_checks.run(ctx) if r.status is Status.FAIL}


# ---------------- weak algorithms ----------------

SSHD_T = (
    "ciphers aes256-gcm@openssh.com,aes128-cbc\nmacs hmac-sha2-256,hmac-md5\n"
    "kexalgorithms curve25519-sha256\nport 22\n"
)


class SshdTRunner:
    """sshd -T output that reflects the weak algorithms until the drop-in exists."""

    def __init__(self, fake_root, base):
        self.root, self.base, self.calls = fake_root, base, []

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        if args == ["sshd", "-T"]:
            fixed = dropin(self.root, "00-reviveguard-ciphers.conf").exists()
            out = SSHD_T.replace(",aes128-cbc", "").replace(",hmac-md5", "") if fixed else SSHD_T
            return CommandResult(tuple(args), 0, out)
        return self.base(args, timeout)


def test_weak_algorithms_fix_removes_only_the_weak_ones(make_ctx, fake_root, store):
    build_host(fake_root, ALICE, SSHD_MAIN)
    ctx = make_ctx(runner=SshdTRunner(fake_root, ssh_runner()), env={"SUDO_USER": "alice"})
    spec = plan(ctx, "SSH-009")
    assert isinstance(spec, FixSpec) and spec.disruptive  # old clients may break
    assert run_fix(store, ctx, spec).status == "applied"
    text = dropin(fake_root, "00-reviveguard-ciphers.conf").read_text()
    assert "Ciphers -aes128-cbc" in text and "MACs -hmac-md5" in text
    assert "aes256-gcm" not in text  # strong ones are never touched


# ---------------- SSH port: phase 1 ----------------


class PortHost:
    """ss output follows the configured ports once sshd was reloaded."""

    def __init__(self, fake_root, base, socket_active=False):
        self.root, self.base, self.socket_active = fake_root, base, socket_active
        self.reloaded, self.calls = False, []

    def ports(self):
        d = dropin(self.root, "00-reviveguard-port.conf")
        if self.reloaded and d.exists():
            return [int(x.split()[1]) for x in d.read_text().splitlines() if x.startswith("Port")]
        return [22]

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        if args[:2] == ["ss", "-H"]:
            rows = "".join(f"tcp LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:*\n" for p in self.ports())
            return CommandResult(tuple(args), 0, rows)
        if args == ["systemctl", "is-active", "--quiet", "ssh.socket"]:
            return CommandResult(tuple(args), 0 if self.socket_active else 3)
        if args == ["systemctl", "reload", "ssh"]:
            self.reloaded = True
        return self.base(args, timeout)


def port_ctx(make_ctx, fake_root, env=None, config=SSHD_MAIN, **kw):
    build_host(fake_root, ALICE, config)
    host = PortHost(fake_root, ssh_runner(), **kw)
    return host, make_ctx(runner=host, env=env or {"SUDO_USER": "alice"})


def test_port_add_keeps_22_and_adds_a_stable_high_port(make_ctx, fake_root, store):
    host, ctx = port_ctx(make_ctx, fake_root)
    spec = plan(ctx, "SSH-010")
    assert isinstance(spec, FixSpec) and spec.disruptive and spec.next_key == "fix.next.port_added"
    again = plan(ctx, "SSH-010")
    assert spec.change_args == again.change_args  # reproducible proposal
    assert run_fix(store, ctx, spec).status == "applied"
    ports = host.ports()
    assert ports[0] == 22 and 20000 <= ports[1] < 60000 and len(ports) == 2
    text = dropin(fake_root, "00-reviveguard-port.conf").read_text()
    assert "Port 22\n" in text and f"Port {ports[1]}\n" in text


def test_port_add_also_updates_fail2ban_when_installed(make_ctx, fake_root, store):
    (fake_root / "etc/fail2ban/jail.d").mkdir(parents=True)
    host, ctx = port_ctx(make_ctx, fake_root)
    base = host.base
    host.base = lambda args, timeout=None: (
        CommandResult(tuple(args), 0, "1.0")
        if args[0] == "fail2ban-client"
        else base(args, timeout)
    )
    spec = plan(ctx, "SSH-010")
    assert len(spec.files) == 2
    assert run_fix(store, ctx, spec).status == "applied"
    jail = (fake_root / "etc/fail2ban/jail.d/reviveguard-sshd-port.local").read_text()
    assert "[sshd]" in jail and "port = 22," in jail
    assert ["fail2ban-client", "reload"] in host.calls


@pytest.mark.parametrize(
    ("kwargs", "config", "reason"),
    [
        ({"socket_active": True}, SSHD_MAIN, "fix.reason.ssh_socket"),
        ({}, SSHD_MAIN + "Port 22\n", "fix.reason.port_in_main"),
    ],
)
def test_port_add_refusals(make_ctx, fake_root, kwargs, config, reason):
    host, ctx = port_ctx(make_ctx, fake_root, config=config, **kwargs)
    result = REGISTRY["SSH-010"](ctx, failing(ctx, "SSH-010"))
    assert isinstance(result, Manual) and result.reason_key == reason


def test_port_add_refused_when_firewall_would_block_it(make_ctx, fake_root):
    host, ctx = port_ctx(make_ctx, fake_root)
    ufw = (
        "Status: active\nDefault: deny (incoming), allow (outgoing)\n\n"
        "To  Action  From\n--  ------  ----\n22/tcp  ALLOW IN  Anywhere\n"
    )
    base = host.base
    host.base = lambda args, timeout=None: (
        CommandResult(tuple(args), 0, ufw) if args[:2] == ["ufw", "status"] else base(args, timeout)
    )
    result = REGISTRY["SSH-010"](ctx, failing(ctx, "SSH-010"))
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.firewall_open_port"
    assert "ufw allow" in result.args["port"] or result.args["port"].isdigit()


def test_port_add_ok_when_firewall_already_allows_the_port(make_ctx, fake_root):
    host, ctx = port_ctx(make_ctx, fake_root)
    first = plan(ctx, "SSH-010")
    port = first.change_args["ports"].split(",")[-1]
    ufw = (
        "Status: active\nDefault: deny (incoming), allow (outgoing)\n\n"
        f"To  Action  From\n--  ------  ----\n{port}/tcp  ALLOW IN  Anywhere\n"
    )
    base = host.base
    host.base = lambda args, timeout=None: (
        CommandResult(tuple(args), 0, ufw) if args[:2] == ["ufw", "status"] else base(args, timeout)
    )
    assert isinstance(REGISTRY["SSH-010"](ctx, failing(ctx, "SSH-010")), FixSpec)


def test_port_add_reverts_when_sshd_never_listens(make_ctx, fake_root, store, monkeypatch):
    host, ctx = port_ctx(make_ctx, fake_root)
    monkeypatch.setattr("reviveguard.fixes.ssh.time.sleep", lambda s: None)
    host.ports = lambda: [22]  # sshd ignores the new port
    outcome = run_fix(store, ctx, plan(ctx, "SSH-010"))
    assert outcome.status == "verify_failed" and outcome.revert_ok
    assert not dropin(fake_root, "00-reviveguard-port.conf").exists()


# ---------------- SSH port: phase 2 ----------------

MIGRATING = SSHD_MAIN


def migrated(make_ctx, fake_root, env, **kw):
    host, ctx = port_ctx(make_ctx, fake_root, env=env, **kw)
    (fake_root / "etc/ssh/sshd_config.d/00-reviveguard-port.conf").write_text(
        "Port 22\nPort 48222\n"
    )
    host.reloaded = True
    return host, ctx


def test_port_finish_requires_the_current_session_to_use_the_new_port(make_ctx, fake_root, store):
    via_22 = {"SUDO_USER": "alice", "SSH_CONNECTION": "1.2.3.4 5555 10.0.0.2 22"}
    host, ctx = migrated(make_ctx, fake_root, via_22)
    result = REGISTRY["SSH-011"](ctx, failing(ctx, "SSH-011"))
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.reconnect_new_port"
    assert result.args["port"] == "48222"


def test_port_finish_drops_22_after_login_via_new_port(make_ctx, fake_root, store):
    via_new = {"SUDO_USER": "alice", "SSH_CONNECTION": "1.2.3.4 5555 10.0.0.2 48222"}
    host, ctx = migrated(make_ctx, fake_root, via_new)
    spec = REGISTRY["SSH-011"](ctx, failing(ctx, "SSH-011"))
    assert isinstance(spec, FixSpec) and spec.disruptive
    assert run_fix(store, ctx, spec).status == "applied"
    assert host.ports() == [48222]
    assert "Port 22" not in dropin(fake_root, "00-reviveguard-port.conf").read_text()


def test_port_finish_needs_new_port_listening(make_ctx, fake_root):
    via_new = {"SUDO_USER": "alice", "SSH_CONNECTION": "1.2.3.4 5555 10.0.0.2 48222"}
    host, ctx = migrated(make_ctx, fake_root, via_new)
    host.ports = lambda: [22]
    result = REGISTRY["SSH-011"](ctx, failing(ctx, "SSH-011"))
    assert isinstance(result, Manual) and result.reason_key == "fix.reason.port_not_listening"


def test_listening_ports_handles_missing_ss(make_ctx):
    from reviveguard.fixes.ssh import listening_ports

    assert listening_ports(make_ctx(runner=FakeRunner())) == set()
