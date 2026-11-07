"""Shared fixtures. Tests use a fake filesystem root and a fake command runner,
so they never touch the real operating system."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from reviveguard.context import AuditContext
from reviveguard.system import CommandResult, OsInfo


class FakeRunner:
    """Records calls and answers from a table; unknown commands are 'missing'."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> CommandResult:
        self.calls.append(list(args))
        return self.responses.get(tuple(args), CommandResult(tuple(args), None, missing=True))


@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    (tmp_path / "etc" / "ssh").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def make_ctx(fake_root: Path) -> Callable[..., AuditContext]:
    def factory(runner=None, stat=None, root=True, env=None) -> AuditContext:
        return AuditContext(
            root=fake_root,
            runner=runner or FakeRunner(),
            stat=stat or (lambda p: SimpleNamespace(st_mode=0o100600, st_uid=0)),
            os_info=OsInfo("debian", "12", "Debian GNU/Linux 12 (bookworm)"),
            running_as_root=root,
            env=env or {},
        )

    return factory


def write_sshd_config(root: Path, text: str, name: str = "sshd_config") -> Path:
    path = root / "etc" / "ssh" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def fake_stat(mode: int, uid: int = 0):
    return lambda p: SimpleNamespace(st_mode=mode, st_uid=uid)


SSHD_MAIN = "Include /etc/ssh/sshd_config.d/*.conf\n"


def build_host(root: Path, users: dict[str, dict], sshd_config: str = SSHD_MAIN) -> None:
    """Create passwd/group/shadow/home/authorized_keys and sshd_config in a fake root.

    users: name -> {uid, sudo: bool, key: bool, password: bool}
    """
    (root / "etc" / "ssh" / "sshd_config.d").mkdir(parents=True, exist_ok=True)
    write_sshd_config(root, sshd_config)
    passwd, shadow, sudo_members = [], [], []
    for name, spec in users.items():
        uid = spec["uid"]
        home = "/root" if uid == 0 else f"/home/{name}"
        passwd.append(f"{name}:x:{uid}:{uid}::{home}:/bin/bash")
        shadow.append(f"{name}:{'$6$hash' if spec.get('password') else '!'}:19000:0:99999:7:::")
        if spec.get("sudo"):
            sudo_members.append(name)
        if spec.get("key"):
            ssh_dir = root / home.lstrip("/") / ".ssh"
            ssh_dir.mkdir(parents=True, exist_ok=True)
            (ssh_dir / "authorized_keys").write_text("ssh-ed25519 AAAAC3Nza-FAKE user@host\n")
    (root / "etc" / "passwd").write_text("\n".join(passwd) + "\n")
    (root / "etc" / "shadow").write_text("\n".join(shadow) + "\n")
    (root / "etc" / "group").write_text(f"sudo:x:27:{','.join(sudo_members)}\n")


def ssh_runner(**overrides) -> FakeRunner:
    ok = {
        ("sshd", "-t"): CommandResult(("sshd", "-t"), 0),
        ("systemctl", "--version"): CommandResult(("systemctl", "--version"), 0),
        ("systemctl", "is-active", "--quiet", "ssh"): CommandResult(("x",), 0),
        ("systemctl", "reload", "ssh"): CommandResult(("x",), 0),
    }
    ok.update(overrides)
    return FakeRunner(ok)


__all__ = [
    "FakeRunner",
    "write_sshd_config",
    "fake_stat",
    "os",
    "build_host",
    "ssh_runner",
    "SSHD_MAIN",
]
