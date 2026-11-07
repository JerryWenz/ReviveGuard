"""Verification helpers: confirm that a state is really what we expect."""

from __future__ import annotations

import os
import stat as stat_mod
from dataclasses import dataclass
from pathlib import Path

from reviveguard.backup import FileRecord, sha256_file
from reviveguard.checks import REGISTRY
from reviveguard.context import AuditContext
from reviveguard.models import Status


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    detail: str = ""


def verify_check_passes(ctx: AuditContext, check_id: str) -> VerificationResult:
    """Re-run the owning check module and require ``check_id`` to report OK."""
    category = check_id.split("-", 1)[0].lower()
    module = REGISTRY.get(category)
    if module is None:
        return VerificationResult(False, f"no check module for {check_id}")
    for result in module(ctx):
        if result.check_id == check_id:
            ok = result.status is Status.OK
            return VerificationResult(ok, f"{check_id}: {result.status.value}")
    return VerificationResult(False, f"{check_id}: result not produced")


def verify_file_restored(rec: FileRecord) -> VerificationResult:
    """Check a file against its pre-change record (content, mode, owner)."""
    path = Path(rec.path)
    if not rec.existed:
        gone = not os.path.lexists(path)
        return VerificationResult(gone, "" if gone else f"{path} still exists")
    try:
        st = os.stat(path)
        digest = sha256_file(path)
    except OSError as exc:
        return VerificationResult(False, f"{path}: {exc.strerror}")
    if digest != rec.sha256:
        return VerificationResult(False, f"{path}: content differs")
    if stat_mod.S_IMODE(st.st_mode) != rec.mode or (st.st_uid, st.st_gid) != (rec.uid, rec.gid):
        return VerificationResult(False, f"{path}: mode or owner differs")
    return VerificationResult(True)
