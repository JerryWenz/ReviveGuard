from __future__ import annotations

from reviveguard import checks
from reviveguard.backup import FileRecord, sha256_file
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.verification import verify_check_passes, verify_file_restored

from .conftest import write_sshd_config


def test_check_passes_after_secure_config(make_ctx, fake_root):
    write_sshd_config(fake_root, "PermitRootLogin no\n")
    assert verify_check_passes(make_ctx(), "SSH-001").ok


def test_check_still_failing_is_not_ok(make_ctx, fake_root):
    write_sshd_config(fake_root, "PermitRootLogin yes\n")
    res = verify_check_passes(make_ctx(), "SSH-001")
    assert not res.ok and "FAIL" in res.detail


def test_unknown_module_and_missing_result(make_ctx, monkeypatch):
    assert not verify_check_passes(make_ctx(), "ZZZ-001").ok
    monkeypatch.setitem(
        checks.REGISTRY,
        "ssh",
        lambda ctx: [CheckResult("SSH-009", "ssh", Severity.INFO, Status.OK, "t", "d", "r")],
    )
    assert not verify_check_passes(make_ctx(), "SSH-001").ok


def test_file_restored_detects_mode_content_and_absence(tmp_path):
    import os

    f = tmp_path / "f"
    f.write_text("a")
    f.chmod(0o600)
    rec = FileRecord(str(f), True, "0-f", sha256_file(f), 0o600, os.getuid(), os.getgid())
    assert verify_file_restored(rec).ok
    f.chmod(0o644)
    assert not verify_file_restored(rec).ok
    f.chmod(0o600)
    f.write_text("b")
    assert not verify_file_restored(rec).ok
    assert verify_file_restored(FileRecord(str(tmp_path / "gone"), False)).ok
    assert not verify_file_restored(FileRecord(str(f), False)).ok
    f.unlink()
    assert not verify_file_restored(rec).ok
