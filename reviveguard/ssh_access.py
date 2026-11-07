"""Lockout-prevention helpers for SSH remediation (read-only).

The server cannot prove that a client key *works*. What we verify are the
prerequisites sshd itself enforces: the account may log in, public key auth is
enabled, an ``authorized_keys`` file with a valid key exists, and its permissions
satisfy ``StrictModes``. Key contents are never stored or reported.
"""

from __future__ import annotations

import fnmatch
import stat as stat_mod
from dataclasses import dataclass
from pathlib import Path

from reviveguard.context import AuditContext

NO_LOGIN_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")
ADMIN_GROUPS = ("sudo", "admin", "wheel")
KEY_TYPES = ("ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-")
DEFAULT_AUTH_KEYS = ".ssh/authorized_keys .ssh/authorized_keys2"
UNSET_LOGINUID = 4294967295


@dataclass(frozen=True)
class PasswdEntry:
    name: str
    uid: int
    gid: int
    home: str
    shell: str


@dataclass(frozen=True)
class AdminAccess:
    name: str
    uid: int
    permitted: bool  # sshd would let this user in (Allow/Deny rules)
    has_key: bool  # valid authorized_keys that StrictModes accepts
    has_password: bool  # unlocked, non-empty password hash


def read_passwd(ctx: AuditContext) -> list[PasswdEntry]:
    entries = []
    for line in (ctx.read_text("/etc/passwd") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[2].isdigit() and parts[3].isdigit():
            entries.append(PasswdEntry(parts[0], int(parts[2]), int(parts[3]), parts[5], parts[6]))
    return entries


def read_groups(ctx: AuditContext) -> dict[str, tuple[int, set[str]]]:
    groups = {}
    for line in (ctx.read_text("/etc/group") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 4 and parts[2].isdigit():
            members = {m for m in parts[3].split(",") if m}
            groups[parts[0]] = (int(parts[2]), members)
    return groups


def groups_of(entry: PasswdEntry, groups: dict[str, tuple[int, set[str]]]) -> set[str]:
    return {g for g, (gid, members) in groups.items() if entry.name in members or gid == entry.gid}


def current_login_user(ctx: AuditContext, passwd: list[PasswdEntry]) -> str | None:
    """Original login user: kernel loginuid, then SUDO_USER, then the effective user."""
    by_uid = {e.uid: e.name for e in passwd}
    raw = ctx.read_text("/proc/self/loginuid")
    if raw and raw.strip().isdigit() and int(raw) != UNSET_LOGINUID:
        return by_uid.get(int(raw))
    sudo_user = ctx.env.get("SUDO_USER")
    if sudo_user:
        return sudo_user
    return "root" if ctx.running_as_root else ctx.env.get("USER")


def is_remote_session(ctx: AuditContext) -> bool:
    """True if this process runs under SSH (environment, or an ``sshd`` ancestor)."""
    if any(ctx.env.get(k) for k in ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY")):
        return True
    pid = "self"
    for _ in range(32):  # bounded walk up the process tree
        stat_line = ctx.read_text(f"/proc/{pid}/stat")
        if not stat_line or ")" not in stat_line:
            return False
        comm = stat_line[stat_line.find("(") + 1 : stat_line.rfind(")")]
        fields = stat_line[stat_line.rfind(")") + 2 :].split()
        if comm.startswith("sshd"):
            return True
        if len(fields) < 2 or not fields[1].isdigit() or int(fields[1]) <= 1:
            return False
        pid = fields[1]
    return False


def _strict_ok(ctx: AuditContext, absolute: str, owner_uid: int) -> bool:
    try:
        st = ctx.stat(ctx.path(absolute))
    except OSError:
        return False
    mode = stat_mod.S_IMODE(st.st_mode)
    return st.st_uid in (owner_uid, 0) and not mode & 0o022


def has_valid_key(ctx: AuditContext, entry: PasswdEntry, cfg: dict[str, str]) -> bool:
    patterns = cfg.get("authorizedkeysfile", DEFAULT_AUTH_KEYS).split()
    home = entry.home.rstrip("/") or "/"
    for pattern in patterns:
        expanded = pattern.replace("%%", "\0").replace("%h", home).replace("%u", entry.name)
        expanded = expanded.replace("\0", "%")
        path = expanded if expanded.startswith("/") else f"{home}/{expanded}"
        text = ctx.read_text(path)
        if text is None:
            continue
        has_key = any(
            any(tok.startswith(KEY_TYPES) for tok in line.split()[:8])
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        if not has_key:
            continue
        # StrictModes: file, ~/.ssh (when used) and home must be owned by the user or
        # root and not group/world writable.
        locations = [path, str(Path(path).parent), home]
        if all(_strict_ok(ctx, loc, entry.uid) for loc in locations):
            return True
    return False


def has_usable_password(ctx: AuditContext, name: str) -> bool:
    for line in (ctx.read_text("/etc/shadow") or "").splitlines():
        parts = line.split(":")
        if parts[0] == name and len(parts) > 1:
            return bool(parts[1]) and parts[1][0] not in "!*"
    return False


def user_permitted(cfg: dict[str, str], entry: PasswdEntry, groups: set[str]) -> bool:
    def matches(key: str, candidates: set[str]) -> bool:
        return any(
            fnmatch.fnmatchcase(c, pat) for pat in cfg.get(key, "").split() for c in candidates
        )

    if matches("denyusers", {entry.name}) or matches("denygroups", groups):
        return False
    if "allowusers" in cfg and not matches("allowusers", {entry.name}):
        return False
    return not ("allowgroups" in cfg and not matches("allowgroups", groups))


def admin_access(ctx: AuditContext, cfg: dict[str, str]) -> list[AdminAccess]:
    """Accounts that can administer the host: root plus members of sudo/admin/wheel."""
    passwd, groups = read_passwd(ctx), read_groups(ctx)
    result = []
    for entry in passwd:
        member = groups_of(entry, groups)
        is_admin = entry.uid == 0 or bool(member & set(ADMIN_GROUPS))
        if not is_admin or Path(entry.shell).name in NO_LOGIN_SHELLS:
            continue
        result.append(
            AdminAccess(
                name=entry.name,
                uid=entry.uid,
                permitted=user_permitted(cfg, entry, member),
                has_key=has_valid_key(ctx, entry, cfg),
                has_password=has_usable_password(ctx, entry.name),
            )
        )
    return result
