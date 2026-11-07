"""Creating a dedicated administrator account (key-only, sudo).

This needs input from the user (a name and a public key), so it is not part of the plain
fix registry; ``fixflow`` asks for the input and calls :func:`plan_admin_user`.
ReviveGuard never deletes users: a rollback removes the files it wrote, the account stays.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re

from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.remediation import FixSpec, Manual, write_file_atomic
from reviveguard.ssh_access import read_groups, read_passwd

USERNAME = re.compile(r"^[a-z][a-z0-9_-]{1,30}$")
RESERVED = frozenset(
    "root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc "
    "nobody sshd systemd-network messagebus syslog".split()
)
PUBKEY = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)"
    r" ([A-Za-z0-9+/]+={0,3})( [^\n\r]{0,100})?$"
)
SUDOERS_DIR = "/etc/sudoers.d"


def validate_username(name: str) -> str | None:
    """Return an i18n error key, or None if the name is acceptable."""
    if not USERNAME.match(name):
        return "admin.err.bad_name"
    return "admin.err.reserved" if name in RESERVED else None


def parse_pubkey(line: str) -> tuple[str, str] | None:
    """Return (normalized key line, SHA256 fingerprint), or None if the line is not a plain key.

    Options before the key type (``command=...``) are rejected on purpose: they could turn
    the new account into something different from what the user expects.
    """
    line = line.strip()
    if len(line) > 8192 or not (m := PUBKEY.match(line)):
        return None
    try:
        blob = base64.b64decode(m.group(2), validate=True)
    except ValueError:
        return None
    if not blob.startswith(len(m.group(1)).to_bytes(4, "big") + m.group(1).encode()):
        return None  # the blob must start with its own key type
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return line, f"SHA256:{digest}"


def plan_admin_user(
    ctx: AuditContext, username: str, pubkey_line: str | None, nopasswd: bool = True
) -> FixSpec | Manual:
    """Plan the account. ``pubkey_line`` may be empty: the key can be added later (add-key)."""
    problem = validate_username(username)
    if problem:
        return Manual(problem)
    key_line, fingerprint = None, "-"
    if pubkey_line and pubkey_line.strip():
        parsed = parse_pubkey(pubkey_line)
        if parsed is None:
            return Manual("admin.err.bad_key")
        key_line, fingerprint = parsed
    if any(e.name == username for e in read_passwd(ctx)):
        return Manual("admin.err.exists", {"name": username})
    if "sudo" not in read_groups(ctx):
        return Manual("admin.err.no_sudo_group")
    if ctx.runner(["useradd", "--help"]).missing:
        return Manual("admin.err.no_useradd")
    if nopasswd and ctx.runner(["visudo", "--version"]).missing:
        return Manual("admin.err.no_visudo")

    home = f"/home/{username}"
    keys_path = ctx.path(f"{home}/.ssh/authorized_keys")
    sudoers_path = ctx.path(f"{SUDOERS_DIR}/90-reviveguard-{username}")
    files = ([keys_path] if key_line else []) + ([sudoers_path] if nopasswd else [])

    def apply() -> None:
        proc = ctx.runner(
            ["useradd", "--create-home", "--shell", "/bin/bash", "--groups", "sudo", username],
            timeout=60,
        )
        if not proc.ok:
            raise RuntimeError(((proc.stderr or "useradd failed").strip().splitlines() or [""])[0])
        entry = next((e for e in read_passwd(ctx) if e.name == username), None)
        uid, gid = (entry.uid, entry.gid) if entry else (None, None)
        if key_line:
            keys_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(keys_path.parent, 0o700)
            write_file_atomic(keys_path, key_line + "\n", 0o600)
            if uid is not None:
                os.chown(keys_path.parent, uid, gid)
                os.chown(keys_path, uid, gid)
        if nopasswd:
            sudoers_path.parent.mkdir(parents=True, exist_ok=True)
            write_file_atomic(sudoers_path, f"{username} ALL=(ALL) NOPASSWD:ALL\n", 0o440)

    def validate() -> str | None:
        if not nopasswd:
            return None
        proc = ctx.runner(["visudo", "-cf", str(sudoers_path)])
        return None if proc.ok else "sudoers file is invalid (visudo -cf failed)"

    def exists() -> str | None:
        done = any(e.name == username for e in read_passwd(ctx))
        return None if done else "the account was not created"

    if key_line:
        next_key = "fix.next.admin_user" if nopasswd else "fix.next.admin_user_password"
    else:
        next_key = "fix.next.admin_user_nokey"
    return FixSpec(
        fix_id="access.admin_user.create",
        check_id="USR-001",
        description=(
            f"Create administrator '{username}' (sudo{', no sudo password' if nopasswd else ''}, "
            f"{'login by key ' + fingerprint if key_line else 'no login key yet'})"
        ),
        files=files,
        apply=apply,
        validate=validate,
        activate=None,
        change_key="fix.access.admin_user",
        change_args={
            "name": username,
            "fingerprint": fingerprint,
            "sudo": "NOPASSWD" if nopasswd else "password",
        },
        service_key="fix.access.user_stays",
        verify=None if key_line else exists,  # without a key USR-001 cannot pass yet
        next_key=next_key,
        next_args={"name": username},
    )


def plan_add_key(ctx: AuditContext, username: str, pubkey_line: str) -> FixSpec | Manual:
    """Install a login key for an existing account (appends; never overwrites other keys)."""
    entry = next((e for e in read_passwd(ctx) if e.name == username), None)
    if entry is None or entry.uid == 0 or validate_username(username) is not None:
        return Manual("admin.err.no_such_user", {"name": username})
    parsed = parse_pubkey(pubkey_line)
    if parsed is None:
        return Manual("admin.err.bad_key")
    key_line, fingerprint = parsed
    keys_path = ctx.path(f"{entry.home.rstrip('/')}/.ssh/authorized_keys")

    def apply() -> None:
        existing = keys_path.read_text(encoding="utf-8") if keys_path.exists() else ""
        if key_line in existing.splitlines():
            return  # already installed
        keys_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(keys_path.parent, 0o700)
        text = (
            existing + ("" if not existing or existing.endswith("\n") else "\n") + key_line + "\n"
        )
        write_file_atomic(keys_path, text, 0o600)
        os.chown(keys_path.parent, entry.uid, entry.gid)
        os.chown(keys_path, entry.uid, entry.gid)

    return FixSpec(
        fix_id="access.admin_key.add",
        check_id="USR-001",
        description=f"Add login key {fingerprint} for '{username}'",
        files=[keys_path],
        apply=apply,
        validate=lambda: None,
        activate=None,
        change_key="fix.access.add_key",
        change_args={"name": username, "fingerprint": fingerprint},
        next_key="fix.next.key_added",
        next_args={"name": username},
    )


def admin_result() -> CheckResult:
    """Synthetic finding used to run the admin-user fix through the normal engine."""
    return CheckResult(
        "USR-001", "accounts", Severity.MEDIUM, Status.FAIL,
        "accounts.admin_user.title", "accounts.admin_user.desc", "accounts.admin_user.fix",
    )  # fmt: skip
