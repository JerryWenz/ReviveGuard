"""Remediation engine: backup -> apply -> validate -> activate -> verify -> record.

Any failure after the change started triggers an automatic restore from the backup.
Planners (see ``reviveguard.fixes``) decide *whether* a fix is safe and return either a
``FixSpec`` or a ``Manual`` explanation; this module only executes specs.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from reviveguard.backup import (
    BackupError,
    Operation,
    Store,
    begin_operation,
    mark_applied,
    mark_failed,
)
from reviveguard.context import AuditContext
from reviveguard.rollback import RollbackError, execute_rollback, plan_rollback
from reviveguard.verification import verify_check_passes


@dataclass
class Manual:
    """No safe automatic fix: explain why (i18n key + args)."""

    reason_key: str
    args: dict[str, str] = field(default_factory=dict)


@dataclass
class FixSpec:
    fix_id: str
    check_id: str
    description: str  # technical, English; stored in history
    files: list[Path]  # every file the fix may modify (all are backed up)
    apply: Callable[[], None]
    validate: Callable[[], str | None]  # None = valid, else a technical error
    activate: Callable[[], bool] | None  # e.g. reload a service; False = failed
    change_key: str = ""
    change_args: dict[str, str] = field(default_factory=dict)
    service_key: str | None = None
    disruptive: bool = False
    reversible: bool = True  # False: e.g. package installs; recorded, rollback refuses
    verify: Callable[[], str | None] | None = None  # None: re-run the owning check


@dataclass
class Outcome:
    status: str  # applied | backup_failed | apply_failed | validation_failed |
    # activation_failed | verify_failed
    op_id: str | None = None
    detail: str = ""
    reverted: bool = False
    revert_ok: bool = True


def preflight(ctx: AuditContext) -> str | None:
    """Return an i18n error key if fixes must not run on this host, else None."""
    if not ctx.running_as_root:
        return "fix.err.not_root"
    if not ctx.os_info.is_supported:
        return "fix.err.unsupported_os"
    return None


def write_file_atomic(path: Path, text: str, mode: int) -> None:
    """Write via temp file + rename in the same directory; permissions set before rename."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _revert(store: Store, spec: FixSpec, op: Operation, activated: bool) -> bool:
    try:
        failed = execute_rollback(store, plan_rollback(store, op.op_id))
    except (RollbackError, BackupError):
        return False
    if failed:
        return False
    if activated and spec.activate is not None:
        spec.activate()  # best effort: make the running service match the restored files
    return True


def run_fix(store: Store, ctx: AuditContext, spec: FixSpec) -> Outcome:
    """Execute one fix. Never leaves a half-applied change if it can be avoided."""
    try:
        op = begin_operation(
            store, spec.check_id, spec.fix_id, spec.description, spec.files, spec.reversible
        )
    except BackupError as exc:
        return Outcome("backup_failed", detail=str(exc))

    def fail(status: str, detail: str, activated: bool = False) -> Outcome:
        mark_failed(store, op, f"{status}: {detail}")
        if not spec.reversible:
            return Outcome(status, op.op_id, detail, reverted=False)
        ok = _revert(store, spec, op, activated)
        return Outcome(status, op.op_id, detail, reverted=True, revert_ok=ok)

    try:
        spec.apply()
    except BaseException as exc:  # includes KeyboardInterrupt: restore before re-raising
        mark_failed(store, op, f"apply_failed: {type(exc).__name__}")
        ok = _revert(store, spec, op, False) if spec.reversible else True
        if not isinstance(exc, Exception):
            raise
        return Outcome("apply_failed", op.op_id, str(exc), spec.reversible, ok)
    error = spec.validate()
    if error:
        return fail("validation_failed", error)
    if spec.activate is not None:
        try:
            activated_ok = spec.activate()
        except Exception as exc:
            return fail("activation_failed", str(exc), activated=True)
        if not activated_ok:
            return fail("activation_failed", "service did not accept the new configuration", True)
    if spec.verify is not None:
        problem = spec.verify()
        if problem:
            return fail("verify_failed", problem, activated=spec.activate is not None)
    else:
        verification = verify_check_passes(ctx, spec.check_id)
        if not verification.ok:
            return fail("verify_failed", verification.detail, activated=spec.activate is not None)
    mark_applied(store, op)
    return Outcome("applied", op.op_id)
