"""Rollback of a recorded operation: plan, validate, restore, verify.

Only files recorded for the selected operation are touched. Operations that cannot be
reliably reversed (for example package upgrades) are flagged ``reversible=False`` and
are refused here.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from reviveguard.backup import BackupError, Operation, Store, sha256_file, utc_now
from reviveguard.verification import verify_file_restored


class RollbackError(Exception):
    """Rollback could not be completed; the message is technical detail."""


@dataclass
class RollbackAction:
    path: str
    kind: str  # "restore" or "remove"
    modified_since: bool = False


@dataclass
class RollbackPlan:
    operation: Operation
    actions: list[RollbackAction] = field(default_factory=list)
    problems: list[tuple[str, dict[str, str]]] = field(default_factory=list)  # (i18n key, args)

    @property
    def can_execute(self) -> bool:
        return not self.problems


def plan_rollback(store: Store, op_id: str) -> RollbackPlan:
    op = store.load(op_id)
    plan = RollbackPlan(operation=op)
    if op.status == "rolled_back":
        plan.problems.append(("rollback.err.already", {}))
        return plan
    if not op.reversible:
        plan.problems.append(("rollback.err.not_reversible", {}))
        return plan
    for rec in op.files:
        path = Path(rec.path)
        if rec.existed:
            backup = store.backup_dir(op.op_id) / (rec.backup_name or "")
            if not backup.is_file():
                plan.problems.append(("rollback.err.backup_missing", {"path": rec.path}))
                continue
            if sha256_file(backup) != rec.sha256:
                plan.problems.append(("rollback.err.backup_corrupt", {"path": rec.path}))
                continue
            kind = "restore"
        else:
            kind = "remove"
        modified = False
        if op.status == "applied":
            current = sha256_file(path) if path.is_file() else None
            modified = current != rec.after_sha256
        plan.actions.append(RollbackAction(rec.path, kind, modified))
    return plan


def _restore_file(src: Path, dest: Path, mode: int, uid: int, gid: int) -> None:
    tmp = dest.with_name(f".{dest.name}.reviveguard-tmp")
    try:
        shutil.copyfile(src, tmp)
        os.chmod(tmp, mode)
        st = os.stat(tmp)
        if (st.st_uid, st.st_gid) != (uid, gid):
            os.chown(tmp, uid, gid)
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def execute_rollback(store: Store, plan: RollbackPlan) -> list[str]:
    """Apply a validated plan. Returns paths that failed verification (empty = success).

    The operation is marked ``rolled_back`` only after every file verified. A failure
    raises RollbackError; the plan is idempotent, so it can be retried.
    """
    if not plan.can_execute:
        raise RollbackError("plan has unresolved problems")
    op = plan.operation
    by_path = {rec.path: rec for rec in op.files}
    for action in plan.actions:
        rec = by_path[action.path]
        try:
            if action.kind == "restore":
                _restore_file(
                    store.backup_dir(op.op_id) / (rec.backup_name or ""),
                    Path(rec.path),
                    rec.mode or 0o600,
                    rec.uid or 0,
                    rec.gid or 0,
                )
            elif os.path.lexists(rec.path):
                os.unlink(rec.path)
        except OSError as exc:
            raise RollbackError(f"{rec.path}: {exc.strerror}") from exc
    failed = [rec.path for rec in op.files if not verify_file_restored(rec).ok]
    if not failed:
        op.status = "rolled_back"
        op.rolled_back_at = utc_now()
        try:
            store.save(op)
        except BackupError as exc:
            raise RollbackError(str(exc)) from exc
    return failed
