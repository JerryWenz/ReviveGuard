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
    reload_service: str | None = None  # service to reload after 'reviveguard rollback'
    undo: Callable[[], None] | None = None  # undo runtime state after files were restored
    confirm_key: str | None = None  # needs the user's live confirmation (i18n key), else revert
    confirm_args: dict[str, str] = field(default_factory=dict)
    next_key: str | None = None  # shown after a successful apply: what to do next
    next_args: dict[str, str] = field(default_factory=dict)
    packages: list[str] = field(default_factory=list)  # packages it may install (never undone)
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
    if spec.undo is not None:
        try:
            spec.undo()  # runtime state that restoring files cannot undo (e.g. a loaded firewall)
        except Exception:
            return False
    if activated and spec.activate is not None:
        try:
            spec.activate()  # best effort: make the running service match the restored files
        except Exception:
            pass  # the files are already restored; a failing reload must not undo that
    return True


def run_fix(
    store: Store,
    ctx: AuditContext,
    spec: FixSpec,
    confirm: Callable[[FixSpec], bool] | None = None,
) -> Outcome:
    """Execute one fix. Never leaves a half-applied change if it can be avoided."""
    try:
        op = begin_operation(
            store,
            spec.check_id,
            spec.fix_id,
            spec.description,
            spec.files,
            spec.reversible,
            reload_service=spec.reload_service,
        )
    except BackupError as exc:
        return Outcome("backup_failed", detail=str(exc))

    def fail(status: str, detail: str, activated: bool = False) -> Outcome:
        mark_failed(store, op, f"{status}: {detail}")
        if not spec.reversible:
            return Outcome(status, op.op_id, detail, reverted=False)
        ok = _revert(store, spec, op, activated)
        return Outcome(status, op.op_id, detail, reverted=True, revert_ok=ok)

    phase = "apply"
    try:
        spec.apply()
        phase = "validation"
        error = spec.validate()
        if error:
            return fail("validation_failed", error)
        phase = "activation"
        if spec.activate is not None:
            if not spec.activate():
                return fail(
                    "activation_failed", "service did not accept the new configuration", True
                )
        phase = "verify"
        if spec.verify is not None:
            problem = spec.verify()
            if problem:
                return fail("verify_failed", problem, activated=spec.activate is not None)
        else:
            verification = verify_check_passes(ctx, spec.check_id)
            if not verification.ok:
                return fail(
                    "verify_failed", verification.detail, activated=spec.activate is not None
                )
        phase = "confirmation"
        if spec.confirm_key and not (confirm and confirm(spec)):
            return fail("confirmation_failed", "no confirmation received", activated=True)
        mark_applied(store, op)
        return Outcome("applied", op.op_id)
    except BaseException as exc:
        # Any error or interruption (Ctrl+C, or SIGHUP/SIGTERM when the SSH session drops) in ANY
        # phase restores the original files before the exception moves on.
        try:
            already = store.load(op.op_id).status == "rolled_back"
        except BackupError:
            already = False
        ok = True
        if not already:
            mark_failed(store, op, f"{phase}_failed: {type(exc).__name__}")
            if spec.reversible:
                ok = _revert(store, spec, op, phase in ("activation", "verify", "confirmation"))
        if not isinstance(exc, Exception):
            raise
        detail = f"{type(exc).__name__}: {exc}"[:200]
        return Outcome(f"{phase}_failed", op.op_id, detail, spec.reversible, ok)
