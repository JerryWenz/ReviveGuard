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
    def factory(runner=None, stat=None, root=True) -> AuditContext:
        return AuditContext(
            root=fake_root,
            runner=runner or FakeRunner(),
            stat=stat or (lambda p: SimpleNamespace(st_mode=0o100600, st_uid=0)),
            os_info=OsInfo("debian", "12", "Debian GNU/Linux 12 (bookworm)"),
            running_as_root=root,
        )

    return factory


def write_sshd_config(root: Path, text: str, name: str = "sshd_config") -> Path:
    path = root / "etc" / "ssh" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def fake_stat(mode: int, uid: int = 0):
    return lambda p: SimpleNamespace(st_mode=mode, st_uid=uid)


__all__ = ["FakeRunner", "write_sshd_config", "fake_stat", "os"]
