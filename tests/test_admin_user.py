from __future__ import annotations

import base64
import os
import stat

import pytest

from reviveguard import cli
from reviveguard.backup import Store
from reviveguard.checks import accounts
from reviveguard.fixes.access import parse_pubkey, plan_admin_user, validate_username
from reviveguard.models import Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import SSHD_MAIN, build_host, ssh_runner


def make_key(kind="ssh-ed25519", comment="me@laptop"):
    blob = len(kind).to_bytes(4, "big") + kind.encode() + b"\x00\x00\x00\x20" + b"K" * 32
    return f"{kind} {base64.b64encode(blob).decode()} {comment}"


KEY = make_key()


class UserHost:
    """Fake useradd/visudo: useradd edits passwd/group inside the fake root."""

    def __init__(self, fake_root, base, visudo_ok=True, useradd_ok=True):
        self.root, self.base, self.visudo_ok, self.useradd_ok = (
            fake_root,
            base,
            visudo_ok,
            useradd_ok,
        )
        self.calls = []

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        if args[:2] == ["useradd", "--help"]:
            return CommandResult(tuple(args), 0, "usage")
        if args[0] == "useradd" and "--create-home" in args:
            if not self.useradd_ok:
                return CommandResult(tuple(args), 1, "", "useradd: cannot lock /etc/passwd")
            name = args[-1]
            with open(self.root / "etc/passwd", "a") as fh:
                fh.write(f"{name}:x:1500:1500::/home/{name}:/bin/bash\n")
            group = self.root / "etc/group"
            group.write_text(group.read_text().rstrip("\n") + f",{name}\n")
            (self.root / f"home/{name}").mkdir(parents=True, exist_ok=True)
            return CommandResult(tuple(args), 0)
        if args[:2] == ["visudo", "--version"]:
            return CommandResult(tuple(args), 0, "visudo 1.9")
        if args[:2] == ["visudo", "-cf"]:
            return CommandResult(tuple(args), 0 if self.visudo_ok else 1, "", "syntax error")
        return self.base(args, timeout)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


@pytest.fixture
def host(make_ctx, fake_root, monkeypatch):
    monkeypatch.setattr(os, "chown", lambda *a: None)  # tests run unprivileged
    build_host(fake_root, {"root": {"uid": 0}}, SSHD_MAIN)
    (fake_root / "etc/group").write_text("sudo:x:27:\n")
    (fake_root / "etc/sudoers.d").mkdir(parents=True)
    runner = UserHost(fake_root, ssh_runner())
    return runner, make_ctx(runner=runner, env={})


# ---------------- validation ----------------


@pytest.mark.parametrize("name", ["admin", "ops-1", "j_doe"])
def test_valid_names(name):
    assert validate_username(name) is None


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("Admin", "admin.err.bad_name"),
        ("a", "admin.err.bad_name"),
        ("1bob", "admin.err.bad_name"),
        ("bob;rm", "admin.err.bad_name"),
        ("root", "admin.err.reserved"),
        ("www-data", "admin.err.reserved"),
    ],
)
def test_invalid_names(name, key):
    assert validate_username(name) == key


def test_pubkey_parsing_and_fingerprint():
    line, fingerprint = parse_pubkey(KEY)
    assert line == KEY and fingerprint.startswith("SHA256:") and "=" not in fingerprint
    assert parse_pubkey(make_key("ssh-rsa"))[0].startswith("ssh-rsa ")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "not a key",
        'command="rm -rf /" ' + KEY,  # options are refused
        "ssh-dss AAAAB3NzaC1kc3M= x",  # DSA
        KEY + "\nssh-ed25519 AAAA second",  # not a single line
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "ssh-ed25519 AAAA@@@@ x",
        "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x03abc").decode(),  # blob/type mismatch
    ],
)
def test_bad_keys_rejected(bad):
    assert parse_pubkey(bad) is None


# ---------------- the fix ----------------


def test_creates_key_only_sudo_admin_and_satisfies_the_check(host, store):
    runner, ctx = host
    spec = plan_admin_user(ctx, "ops", KEY)
    assert isinstance(spec, FixSpec) and spec.reversible and spec.next_key == "fix.next.admin_user"
    assert "SHA256:" in spec.change_args["fingerprint"]
    root = ctx.root
    before = {r.check_id: r.status for r in accounts.run(ctx)}
    assert before["USR-001"] is Status.FAIL
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied", outcome
    keys = root / "home/ops/.ssh/authorized_keys"
    assert keys.read_text() == KEY + "\n"
    assert stat.S_IMODE(keys.stat().st_mode) == 0o600
    assert stat.S_IMODE(keys.parent.stat().st_mode) == 0o700
    sudoers = root / "etc/sudoers.d/90-reviveguard-ops"
    assert sudoers.read_text() == "ops ALL=(ALL) NOPASSWD:ALL\n"
    assert stat.S_IMODE(sudoers.stat().st_mode) == 0o440
    assert ["visudo", "-cf", str(sudoers)] in runner.calls
    after = {r.check_id: r.status for r in accounts.run(ctx)}
    assert after["USR-001"] is Status.OK


def test_require_sudo_password_variant_writes_no_sudoers(host, store):
    _, ctx = host
    spec = plan_admin_user(ctx, "ops", KEY, nopasswd=False)
    assert len(spec.files) == 1 and spec.next_key == "fix.next.admin_user_password"
    assert run_fix(store, ctx, spec).status == "applied"
    assert not (ctx.root / "etc/sudoers.d/90-reviveguard-ops").exists()


def test_invalid_sudoers_reverts_files_but_never_deletes_the_user(host, store):
    runner, ctx = host
    runner.visudo_ok = False
    outcome = run_fix(store, ctx, plan_admin_user(ctx, "ops", KEY))
    assert outcome.status == "validation_failed" and outcome.reverted and outcome.revert_ok
    assert not (ctx.root / "etc/sudoers.d/90-reviveguard-ops").exists()
    assert not (ctx.root / "home/ops/.ssh/authorized_keys").exists()
    assert "ops:x:1500" in (ctx.root / "etc/passwd").read_text()  # the account stays


def test_useradd_failure_is_reported_and_leaves_no_files(host, store):
    runner, ctx = host
    runner.useradd_ok = False
    outcome = run_fix(store, ctx, plan_admin_user(ctx, "ops", KEY))
    assert outcome.status == "apply_failed" and "cannot lock" in outcome.detail
    assert not (ctx.root / "home/ops").exists()


@pytest.mark.parametrize(
    ("name", "key", "reason"),
    [
        ("root", KEY, "admin.err.reserved"),
        ("ops", "junk", "admin.err.bad_key"),
        ("root2", KEY, None),
    ],
)
def test_plan_refusals(host, name, key, reason):
    _, ctx = host
    result = plan_admin_user(ctx, name, key)
    if reason:
        assert isinstance(result, Manual) and result.reason_key == reason
    else:
        assert isinstance(result, FixSpec)


def test_existing_user_and_missing_tools(host, make_ctx, fake_root):
    runner, ctx = host
    assert plan_admin_user(ctx, "ops", KEY).files
    (fake_root / "etc/passwd").write_text("ops:x:1000:1000::/home/ops:/bin/bash\n")
    assert plan_admin_user(ctx, "ops", KEY).reason_key == "admin.err.exists"
    (fake_root / "etc/group").write_text("adm:x:4:\n")
    assert plan_admin_user(ctx, "dev", KEY).reason_key == "admin.err.no_sudo_group"


# ---------------- account checks ----------------


def test_accounts_checks(make_ctx, fake_root):
    users = {
        "root": {"uid": 0, "password": True},
        "toor": {"uid": 0},
        "alice": {"uid": 1000, "sudo": True, "key": True},
    }
    build_host(fake_root, users, SSHD_MAIN)
    shadow = (fake_root / "etc/shadow").read_text().replace("toor:!:", "toor::")
    (fake_root / "etc/shadow").write_text(shadow)
    res = {r.check_id: r for r in accounts.run(make_ctx(runner=ssh_runner()))}
    assert res["USR-001"].status is Status.OK and "alice" in res["USR-001"].evidence[0]
    assert res["USR-002"].status is Status.FAIL and "toor" in res["USR-002"].evidence[0]
    assert res["USR-003"].status is Status.FAIL and "toor" in res["USR-003"].evidence[0]


def test_accounts_skip_password_checks_without_root(make_ctx, fake_root):
    build_host(fake_root, {"root": {"uid": 0}}, SSHD_MAIN)
    res = accounts.run(make_ctx(runner=ssh_runner(), root=False))
    assert {r.check_id for r in res} == {"USR-001", "USR-003", "USR-000"}


# ---------------- CLI ----------------


def run_cli(args, ctx, capsys, monkeypatch, tmp_path, answers=()):
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    it = iter(answers)

    def fake_input(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr("builtins.input", fake_input)
    rc = cli.main(["--lang", "en", "--state-dir", str(tmp_path / "s"), *args], ctx=ctx)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_cli_admin_user_with_key_file_and_yes(host, capsys, monkeypatch, tmp_path):
    _, ctx = host
    key_file = tmp_path / "id.pub"
    key_file.write_text(f"# my key\n{KEY}\n")
    args = ["admin-user", "--name", "ops", "--key-file", str(key_file), "--yes"]
    rc, out, _ = run_cli(args, ctx, capsys, monkeypatch, tmp_path)
    assert rc == 0 and "Applied and verified" in out and "Next:" in out
    assert "ssh ops@<server>" in out
    assert (ctx.root / "home/ops/.ssh/authorized_keys").exists()


def test_cli_admin_user_interactive_prompts(host, capsys, monkeypatch, tmp_path):
    _, ctx = host
    rc, out, _ = run_cli(["admin-user"], ctx, capsys, monkeypatch, tmp_path, answers=["Ops2", ""])
    assert rc == 1  # "Ops2" has an uppercase letter
    rc, out, err = run_cli(
        ["admin-user"], ctx, capsys, monkeypatch, tmp_path, answers=["ops", KEY, "y"]
    )
    assert rc == 0 and (ctx.root / "home/ops/.ssh/authorized_keys").exists()
    assert KEY not in out and "SHA256:" in out  # the key itself is not echoed back


def test_cli_admin_user_declined_or_no_terminal(host, capsys, monkeypatch, tmp_path):
    _, ctx = host
    rc, _, _ = run_cli(
        ["admin-user"], ctx, capsys, monkeypatch, tmp_path, answers=["ops", KEY, "n"]
    )
    assert rc == 1 and not (ctx.root / "home/ops").exists()
    rc, _, err = run_cli(["admin-user"], ctx, capsys, monkeypatch, tmp_path)
    assert rc == 1 and not (ctx.root / "home/admin").exists()


def test_cli_admin_user_bad_key_file(host, capsys, monkeypatch, tmp_path):
    _, ctx = host
    args = ["admin-user", "--name", "ops", "--key-file", str(tmp_path / "missing"), "--yes"]
    rc, _, err = run_cli(args, ctx, capsys, monkeypatch, tmp_path)
    assert rc == 1 and "Cannot read the key file" in err


def test_wizard_offers_admin_account_and_stops_for_reconnect(host, capsys, monkeypatch, tmp_path):
    _, ctx = host
    answers = ["n", "y", "ops", KEY, "y"]  # (safe set declined), admin offer, name, key, confirm
    rc, out, err = run_cli(["wizard"], ctx, capsys, monkeypatch, tmp_path, answers=answers)
    assert (ctx.root / "home/ops/.ssh/authorized_keys").exists()
    assert "Account created" in out and "sudo reviveguard wizard" in out
