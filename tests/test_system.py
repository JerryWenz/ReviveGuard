from __future__ import annotations

from reviveguard import system


def test_missing_command_is_reported_not_raised():
    res = system.run_command(["definitely-not-a-real-binary-xyz"])
    assert res.missing and not res.ok


def test_run_command_captures_output_without_shell():
    res = system.run_command(["echo", "$HOME; true"])
    assert res.ok and res.stdout.strip() == "$HOME; true"


def test_timeout_is_handled():
    res = system.run_command(["sleep", "5"], timeout=0.2)
    assert res.timed_out and not res.ok


def test_detect_os_parses_os_release(tmp_path):
    f = tmp_path / "os-release"
    f.write_text('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
    info = system.detect_os(f)
    assert info.id == "debian" and info.is_supported


def test_detect_os_missing_file(tmp_path):
    info = system.detect_os(tmp_path / "nope")
    assert info.id == "unknown" and not info.is_supported


def test_support_matrix():
    OsInfo = system.OsInfo
    assert OsInfo("ubuntu", "22.04", "").is_supported
    assert not OsInfo("ubuntu", "20.04", "").is_supported
    assert not OsInfo("debian", "11", "").is_supported
    assert not OsInfo("fedora", "40", "").is_supported
    assert not OsInfo("debian", "sid", "").is_supported
