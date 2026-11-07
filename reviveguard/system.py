"""Safe access to the host: command execution and OS detection.

All commands run as argument lists (never through a shell) with a timeout.
Missing utilities are reported through the result, not raised.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 15


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int | None  # None: not executed or timed out
    stdout: str = ""
    stderr: str = ""
    missing: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def find_executable(name: str) -> str | None:
    """Locate a tool, including sbin directories that may be absent from PATH."""
    path = os.environ.get("PATH", "") + os.pathsep + "/usr/sbin" + os.pathsep + "/sbin"
    return shutil.which(name, path=path)


def run_command(args: list[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
    """Run a command read-only style: no shell, bounded time, never raises."""
    exe = find_executable(args[0])
    if exe is None:
        return CommandResult(tuple(args), None, missing=True)
    try:
        proc = subprocess.run(  # noqa: S603 - argument list, no shell
            [exe, *args[1:]],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(args), None, timed_out=True)
    except OSError as exc:
        return CommandResult(tuple(args), None, stderr=str(exc), missing=True)
    return CommandResult(tuple(args), proc.returncode, proc.stdout, proc.stderr)


@dataclass(frozen=True)
class OsInfo:
    id: str
    version_id: str
    pretty_name: str

    @property
    def is_supported(self) -> bool:
        """Debian >= 12 or Ubuntu >= 22.04 (the documented target systems)."""
        try:
            major = int(self.version_id.split(".")[0])
        except ValueError:
            return False
        if self.id == "debian":
            return major >= 12
        if self.id == "ubuntu":
            return major >= 22
        return False


def detect_os(path: Path = Path("/etc/os-release")) -> OsInfo:
    values: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return OsInfo("unknown", "", "Unknown Linux")
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, raw = line.partition("=")
            values[key.strip()] = raw.strip().strip('"').strip("'")
    return OsInfo(
        id=values.get("ID", "unknown"),
        version_id=values.get("VERSION_ID", ""),
        pretty_name=values.get("PRETTY_NAME", values.get("NAME", "Unknown Linux")),
    )


def is_root() -> bool:
    return os.geteuid() == 0
