from __future__ import annotations

import json
import os
import shutil

import pytest

from reviveguard import rollback as rb
from reviveguard.backup import (
    BackupError,
    Operation,
    Store,
    begin_operation,
    mark_applied,
    mark_failed,
)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


@pytest.fixture
def target(tmp_path):
    p = tmp_path / "sshd_config"
    p.write_text("PermitRootLogin yes\n")
    p.chmod(0o640)
    return p


def begin(store, *paths, **kw):
    return begin_operation(
        store, "SSH-001", "ssh.root_login.disable", "disable root", list(paths), **kw
    )


def test_begin_creates_backup_and_record(store, target):
    op = begin(store, target)
    assert op.op_id.startswith("FIX-") and op.op_id.endswith("-001") and op.status == "pending"
    rec = op.files[0]
    assert rec.existed and rec.mode == 0o640 and rec.uid == os.getuid()
    backup = store.backup_dir(op.op_id) / rec.backup_name
    assert backup.read_text() == "PermitRootLogin yes\n"
    assert (backup.stat().st_mode & 0o777) == 0o600
    saved = json.loads((store.history / f"{op.op_id}.json").read_text())
    assert saved["check_id"] == "SSH-001" and saved["description"] == "disable root"
    assert (store.root.stat().st_mode & 0o777) == 0o700


def test_ids_increment(store, target):
    a, b = begin(store, target), begin(store, target)
    assert a.op_id.endswith("-001") and b.op_id.endswith("-002")


def test_relative_path_refused(store):
    with pytest.raises(BackupError):
        begin(store, "relative/file")


def test_symlink_refused(store, target, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(BackupError):
        begin(store, link)
    assert not list(store.backups.iterdir()) and not list(store.history.iterdir())


def test_reversible_requires_files(store):
    with pytest.raises(BackupError):
        begin(store)


def test_backup_failure_leaves_nothing_and_blocks_change(store, target, monkeypatch):
    def deny(*a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(shutil, "copyfile", deny)
    with pytest.raises(BackupError):
        begin(store, target)
    assert not list(store.backups.iterdir()) and not list(store.history.iterdir())


def test_rollback_restores_content_mode_and_marks_done(store, target):
    op = begin(store, target)
    target.write_text("PermitRootLogin no\n")
    target.chmod(0o600)
    mark_applied(store, op)
    plan = rb.plan_rollback(store, op.op_id)
    assert plan.can_execute and not plan.actions[0].modified_since
    assert rb.execute_rollback(store, plan) == []
    assert target.read_text() == "PermitRootLogin yes\n"
    assert (target.stat().st_mode & 0o777) == 0o640
    assert store.load(op.op_id).status == "rolled_back"
    assert not list(target.parent.glob(".*reviveguard-tmp"))


def test_rollback_twice_is_refused(store, target):
    op = begin(store, target)
    mark_applied(store, op)
    rb.execute_rollback(store, rb.plan_rollback(store, op.op_id))
    plan = rb.plan_rollback(store, op.op_id)
    assert plan.problems[0][0] == "rollback.err.already"
    with pytest.raises(rb.RollbackError):
        rb.execute_rollback(store, plan)


def test_interrupted_operation_can_be_rolled_back(store, target):
    op = begin(store, target)
    target.write_text("half written")  # crash before mark_applied
    assert store.load(op.op_id).status == "pending"
    plan = rb.plan_rollback(store, op.op_id)
    assert rb.execute_rollback(store, plan) == []
    assert target.read_text() == "PermitRootLogin yes\n"


def test_failed_operation_can_be_rolled_back(store, target):
    op = begin(store, target)
    target.write_text("bad")
    mark_failed(store, op, "verification failed")
    assert rb.execute_rollback(store, rb.plan_rollback(store, op.op_id)) == []
    assert target.read_text() == "PermitRootLogin yes\n"


def test_created_file_is_removed(store, tmp_path):
    new = tmp_path / "new.conf"
    op = begin(store, new)
    new.write_text("created by fix")
    mark_applied(store, op)
    plan = rb.plan_rollback(store, op.op_id)
    assert plan.actions[0].kind == "remove"
    assert rb.execute_rollback(store, plan) == []
    assert not new.exists()


def test_later_modification_is_flagged(store, target):
    op = begin(store, target)
    target.write_text("fixed")
    mark_applied(store, op)
    target.write_text("edited by admin afterwards")
    assert rb.plan_rollback(store, op.op_id).actions[0].modified_since


def test_only_recorded_files_are_touched(store, target, tmp_path):
    other = tmp_path / "other"
    other.write_text("keep me")
    op = begin(store, target)
    target.write_text("x")
    mark_applied(store, op)
    rb.execute_rollback(store, rb.plan_rollback(store, op.op_id))
    assert other.read_text() == "keep me"


def test_corrupt_backup_blocks_rollback(store, target):
    op = begin(store, target)
    target.write_text("changed")
    mark_applied(store, op)
    (store.backup_dir(op.op_id) / op.files[0].backup_name).write_text("tampered")
    plan = rb.plan_rollback(store, op.op_id)
    assert plan.problems[0][0] == "rollback.err.backup_corrupt"
    assert target.read_text() == "changed"


def test_missing_backup_blocks_rollback(store, target):
    op = begin(store, target)
    (store.backup_dir(op.op_id) / op.files[0].backup_name).unlink()
    assert rb.plan_rollback(store, op.op_id).problems[0][0] == "rollback.err.backup_missing"


def test_non_reversible_operation_is_refused(store, tmp_path):
    op = begin_operation(store, "UPD-001", "apt.upgrade", "upgrade", [], reversible=False)
    assert rb.plan_rollback(store, op.op_id).problems[0][0] == "rollback.err.not_reversible"


def test_permission_error_during_restore_is_reported_and_cleaned(store, target, monkeypatch):
    op = begin(store, target)
    target.write_text("changed")
    mark_applied(store, op)

    def deny(*a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "replace", deny)
    with pytest.raises(rb.RollbackError):
        rb.execute_rollback(store, rb.plan_rollback(store, op.op_id))
    assert target.read_text() == "changed"
    assert not list(target.parent.glob(".*reviveguard-tmp"))
    assert store.load(op.op_id).status == "applied"  # still retryable


def test_verification_failure_keeps_operation_open(store, target, monkeypatch):
    op = begin(store, target)
    target.write_text("changed")
    mark_applied(store, op)
    monkeypatch.setattr(rb, "_restore_file", lambda *a: None)  # restore silently does nothing
    failed = rb.execute_rollback(store, rb.plan_rollback(store, op.op_id))
    assert failed == [str(target)]
    assert store.load(op.op_id).status == "applied"


@pytest.mark.parametrize("bad", ["../etc/passwd", "FIX-1", "FIX-2026-001/../x", ""])
def test_invalid_operation_ids_rejected(store, bad):
    with pytest.raises(BackupError):
        store.load(bad)


def test_tampered_record_with_relative_path_rejected(store, target):
    op = begin(store, target)
    path = store.history / f"{op.op_id}.json"
    data = json.loads(path.read_text())
    data["files"][0]["path"] = "etc/passwd"
    path.write_text(json.dumps(data))
    with pytest.raises(BackupError):
        store.load(op.op_id)


def test_tampered_backup_name_rejected(store, target):
    op = begin(store, target)
    path = store.history / f"{op.op_id}.json"
    data = json.loads(path.read_text())
    data["files"][0]["backup_name"] = "../../etc/shadow"
    path.write_text(json.dumps(data))
    with pytest.raises(BackupError):
        store.load(op.op_id)


def test_list_counts_corrupt_records(store, target):
    begin(store, target)
    (store.history / "FIX-2026-999.json").write_text("not json")
    ops, corrupt = store.list_operations()
    assert len(ops) == 1 and corrupt == 1


def test_operation_roundtrip():
    op = Operation("FIX-2026-001", "2026-01-01T00:00:00+00:00", "A-1", "r", "d", True)
    assert Operation.from_dict(op.to_dict()) == op
