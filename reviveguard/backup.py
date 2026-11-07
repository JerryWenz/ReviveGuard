"""Backup store and operation history.

Layout under the state directory (default ``/var/lib/reviveguard``)::

    backups/<op-id>/<n>-<name>   copies of files before a change
    history/<op-id>.json         one record per remediation operation
    reports/, config/            reserved

A record is written *before* any system file is touched (status ``pending``), so an
interrupted operation can still be rolled back from its backups.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat as stat_mod
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path("/var/lib/reviveguard")
OP_ID_RE = re.compile(r"^FIX-\d{4}-\d{3,}$")
BACKUP_NAME_RE = re.compile(r"^\d+-[\w.+-]+$")
STATUSES = ("pending", "applied", "failed", "rolled_back")


class BackupError(Exception):
    """Backup could not be created or a record is invalid. Nothing was changed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class FileRecord:
    path: str
    existed: bool
    backup_name: str | None = None
    sha256: str | None = None
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    after_sha256: str | None = None  # content hash after the change (None: absent)


@dataclass
class Operation:
    op_id: str
    timestamp: str
    check_id: str
    remediation_id: str
    description: str
    reversible: bool
    status: str = "pending"
    files: list[FileRecord] = field(default_factory=list)
    note: str = ""
    rolled_back_at: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: object) -> Operation:
        try:
            if not isinstance(data, dict):
                raise TypeError("record must be an object")
            files = [FileRecord(**f) for f in data["files"]]
            op = cls(**{**data, "files": files})
        except (KeyError, TypeError) as exc:
            raise BackupError(f"invalid history record: {exc}") from exc
        if not OP_ID_RE.match(op.op_id) or op.status not in STATUSES:
            raise BackupError("invalid history record: bad id or status")
        for rec in op.files:
            if not Path(rec.path).is_absolute():
                raise BackupError("invalid history record: relative path")
            if rec.backup_name is not None and not BACKUP_NAME_RE.match(rec.backup_name):
                raise BackupError("invalid history record: bad backup name")
        return op


class Store:
    def __init__(self, root: Path = STATE_DIR) -> None:
        self.root = Path(root)
        self.backups = self.root / "backups"
        self.history = self.root / "history"
        self.reports = self.root / "reports"
        self.config = self.root / "config"

    def ensure(self) -> None:
        try:
            for d in (self.root, self.backups, self.history, self.reports, self.config):
                d.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise BackupError(
                f"cannot prepare state directory {self.root}: {exc.strerror}"
            ) from exc

    def backup_dir(self, op_id: str) -> Path:
        return self.backups / op_id

    def save(self, op: Operation) -> None:
        """Atomically write the record (temp file + rename)."""
        target = self.history / f"{op.op_id}.json"
        try:
            fd, tmp = tempfile.mkstemp(dir=self.history, prefix=".tmp-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(op.to_dict(), fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except OSError as exc:
            raise BackupError(f"cannot write history record: {exc.strerror}") from exc

    def load(self, op_id: str) -> Operation:
        if not OP_ID_RE.match(op_id):
            raise BackupError(f"invalid operation id: {op_id!r}")
        try:
            data = json.loads((self.history / f"{op_id}.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise BackupError(f"operation not found: {op_id}") from None
        except (OSError, ValueError) as exc:
            raise BackupError(f"unreadable history record {op_id}: {exc}") from exc
        op = Operation.from_dict(data)
        if op.op_id != op_id:
            raise BackupError("invalid history record: id mismatch")
        return op

    def list_operations(self) -> tuple[list[Operation], int]:
        """Return (operations sorted by id, number of unreadable records)."""
        ops: list[Operation] = []
        corrupt = 0
        if not self.history.is_dir():
            return ops, corrupt
        for path in sorted(self.history.glob("FIX-*.json")):
            try:
                ops.append(self.load(path.stem))
            except BackupError:
                corrupt += 1
        return ops, corrupt

    def _claim_id(self, year: int) -> str:
        prefix = f"FIX-{year}-"
        seq = 1
        for p in self.history.glob(f"{prefix}*.json"):
            tail = p.stem[len(prefix) :]
            if tail.isdigit():
                seq = max(seq, int(tail) + 1)
        for _ in range(100):  # reserve the id atomically
            op_id = f"{prefix}{seq:03d}"
            try:
                os.mkdir(self.backup_dir(op_id), 0o700)
                return op_id
            except FileExistsError:
                seq += 1
        raise BackupError("cannot allocate an operation id")


def begin_operation(
    store: Store,
    check_id: str,
    remediation_id: str,
    description: str,
    paths: list[Path],
    reversible: bool = True,
    now: Callable[[], str] = utc_now,
) -> Operation:
    """Back up ``paths`` and record the intended change. Call before modifying anything.

    Raises BackupError (leaving no partial backup) if any file cannot be saved; the
    caller must then not apply the change.
    """
    if reversible and not paths:
        raise BackupError("a reversible operation must list the files it changes")
    for p in paths:
        if not Path(p).is_absolute():
            raise BackupError(f"path must be absolute: {p}")
    store.ensure()
    timestamp = now()
    op_id = store._claim_id(int(timestamp[:4]))
    bdir = store.backup_dir(op_id)
    records: list[FileRecord] = []
    try:
        for index, raw in enumerate(paths):
            records.append(_backup_one(Path(raw), bdir, index))
        op = Operation(
            op_id=op_id,
            timestamp=timestamp,
            check_id=check_id,
            remediation_id=remediation_id,
            description=description,
            reversible=reversible,
            files=records,
        )
        store.save(op)
    except (BackupError, OSError) as exc:
        shutil.rmtree(bdir, ignore_errors=True)
        if isinstance(exc, BackupError):
            raise
        raise BackupError(f"backup failed: {exc.strerror or exc}") from exc
    return op


def _backup_one(path: Path, bdir: Path, index: int) -> FileRecord:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return FileRecord(path=str(path), existed=False)
    if not stat_mod.S_ISREG(st.st_mode):
        raise BackupError(f"not a regular file (symlinks are refused): {path}")
    safe_name = re.sub(r"[^\w.+-]", "_", path.name)
    name = f"{index}-{safe_name}"
    dest = bdir / name
    shutil.copyfile(path, dest)
    os.chmod(dest, 0o600)
    digest = sha256_file(path)
    if sha256_file(dest) != digest:
        raise BackupError(f"backup verification failed for {path}")
    return FileRecord(
        path=str(path),
        existed=True,
        backup_name=name,
        sha256=digest,
        mode=stat_mod.S_IMODE(st.st_mode),
        uid=st.st_uid,
        gid=st.st_gid,
    )


def mark_applied(store: Store, op: Operation) -> None:
    """Record post-change hashes so rollback can warn about later edits."""
    for rec in op.files:
        p = Path(rec.path)
        rec.after_sha256 = sha256_file(p) if p.is_file() else None
    op.status = "applied"
    store.save(op)


def mark_failed(store: Store, op: Operation, note: str = "") -> None:
    op.status = "failed"
    op.note = note
    store.save(op)
