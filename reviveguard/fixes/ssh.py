"""SSH fixes. Each planner refuses (``Manual``) whenever lockout cannot be ruled out.

Directive fixes never rewrite ``sshd_config``: they add a small drop-in file in
``/etc/ssh/sshd_config.d/`` that sorts first (sshd uses the first value it sees).
The new configuration is validated with ``sshd -t`` and the service is *reloaded*
(never restarted), so existing sessions stay connected.
"""

from __future__ import annotations

import os
from pathlib import Path

from reviveguard.checks.ssh import SSHD_CONFIG, effective_config
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual, write_file_atomic
from reviveguard.ssh_access import (
    admin_access,
    current_login_user,
    is_remote_session,
    read_passwd,
)

DROPIN_DIR = "/etc/ssh/sshd_config.d"


def _validate(ctx: AuditContext) -> str | None:
    proc = ctx.runner(["sshd", "-t"])
    if proc.ok:
        return None
    return (proc.stderr or "sshd -t failed").strip().splitlines()[0][:200]


def reload_ssh(ctx: AuditContext) -> bool:
    """Reload (not restart) the SSH service. A stopped service reads the config on start."""
    if ctx.runner(["systemctl", "--version"]).missing:
        return False  # cannot manage the service safely
    for unit in ("ssh", "sshd"):
        if ctx.runner(["systemctl", "is-active", "--quiet", unit]).ok:
            return ctx.runner(["systemctl", "reload", unit]).ok
    return True


def _precheck(ctx: AuditContext, key: str) -> tuple[dict[str, str], Manual | None]:
    """Common safety checks for drop-in fixes. Returns (effective config, refusal)."""
    found = effective_config(ctx)
    if found is None:
        return {}, Manual("fix.reason.no_sshd")
    cfg, _ = found
    current = ctx.runner(["sshd", "-t"])  # the current configuration must already be valid
    if current.missing:
        return cfg, Manual("fix.reason.no_sshd")
    if not current.ok:
        return cfg, Manual("fix.reason.config_invalid")
    main = ctx.read_text(SSHD_CONFIG) or ""
    include_seen = False
    for raw in main.splitlines():
        parts = raw.split("#", 1)[0].split()
        if not parts:
            continue
        word = parts[0].lower().partition("=")[0]
        if word == "match":
            break
        if word == "include" and any("sshd_config.d" in p for p in parts[1:]):
            include_seen = True
            break
        if word == key:
            return cfg, Manual("fix.reason.directive_before_include", {"key": key})
    if not include_seen:
        return cfg, Manual("fix.reason.no_include")
    if not ctx.path(DROPIN_DIR).is_dir():
        return cfg, Manual("fix.reason.no_include")
    return cfg, None


def _dropin_spec(
    ctx: AuditContext,
    result: CheckResult,
    key: str,
    value: str,
    disruptive: bool,
    service: bool = True,
) -> FixSpec:
    name = f"00-reviveguard-{key.lower()}.conf"
    path = ctx.path(f"{DROPIN_DIR}/{name}")
    text = (
        f"# Managed by ReviveGuard ({result.check_id}). Remove this file to undo.\n{key} {value}\n"
    )
    return FixSpec(
        fix_id=f"ssh.{key.lower()}.{value}",
        check_id=result.check_id,
        description=f"Set {key} to {value} via drop-in {DROPIN_DIR}/{name}",
        files=[path],
        apply=lambda: write_file_atomic(path, text, 0o644),
        validate=lambda: _validate(ctx),
        activate=(lambda: reload_ssh(ctx)) if service else None,
        change_key="fix.ssh.set_directive",
        change_args={"path": f"{DROPIN_DIR}/{name}", "directive": f"{key} {value}"},
        service_key="fix.service.reload_ssh" if service else None,
        disruptive=disruptive,
    )


def plan_root_login(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    cfg, refusal = _precheck(ctx, "permitrootlogin")
    if refusal:
        return refusal
    admins = admin_access(ctx, cfg)
    password_auth = cfg.get("passwordauthentication", "yes").lower() == "yes"

    def usable(a) -> bool:
        return a.permitted and (a.has_key or (password_auth and a.has_password))

    others = [a for a in admins if a.uid != 0 and usable(a)]
    root = next((a for a in admins if a.uid == 0), None)
    root_key = root is not None and root.permitted and root.has_key
    user = current_login_user(ctx, read_passwd(ctx))
    remote = is_remote_session(ctx)

    if remote and user is None:
        return Manual("fix.reason.cannot_determine_user")
    if remote and user == "root":
        # Never cut the branch we are sitting on: keep root key logins.
        if not root_key:
            return Manual("fix.reason.root_session_no_key")
        return _dropin_spec(ctx, result, "PermitRootLogin", "prohibit-password", True)
    if remote and user not in {a.name for a in others}:
        return Manual("fix.reason.no_key_for_current_user", {"user": str(user)})
    if others:
        return _dropin_spec(ctx, result, "PermitRootLogin", "no", True)
    if root_key:
        return _dropin_spec(ctx, result, "PermitRootLogin", "prohibit-password", True)
    return Manual("fix.reason.no_admin_access")


def plan_password_auth(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    cfg, refusal = _precheck(ctx, "passwordauthentication")
    if refusal:
        return refusal
    if cfg.get("pubkeyauthentication", "yes").lower() != "yes":
        return Manual("fix.reason.pubkey_disabled")
    methods = cfg.get("authenticationmethods", "any").lower()
    if methods != "any":
        return Manual("fix.reason.auth_methods")
    admins = admin_access(ctx, cfg)
    with_key = {a.name for a in admins if a.permitted and a.has_key}
    user = current_login_user(ctx, read_passwd(ctx))
    if is_remote_session(ctx):
        if user is None:
            return Manual("fix.reason.cannot_determine_user")
        if user not in with_key:
            return Manual("fix.reason.no_key_for_current_user", {"user": str(user)})
    elif not with_key:
        return Manual("fix.reason.no_admin_access")
    return _dropin_spec(ctx, result, "PasswordAuthentication", "no", True)


def plan_empty_passwords(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    _, refusal = _precheck(ctx, "permitemptypasswords")
    if refusal:
        return refusal
    return _dropin_spec(ctx, result, "PermitEmptyPasswords", "no", False)


def plan_pubkey_auth(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    _, refusal = _precheck(ctx, "pubkeyauthentication")
    if refusal:
        return refusal
    return _dropin_spec(ctx, result, "PubkeyAuthentication", "yes", False)


def plan_config_perms(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    path = ctx.path(SSHD_CONFIG)
    if not path.is_file() or path.is_symlink():
        return Manual("fix.reason.no_sshd")

    def apply() -> None:
        st = os.stat(path)
        if (st.st_uid, st.st_gid) != (0, 0):
            os.chown(path, 0, 0)
        os.chmod(path, 0o600)

    return FixSpec(
        fix_id="ssh.config_perms.harden",
        check_id=result.check_id,
        description=f"Set owner root:root and mode 0600 on {SSHD_CONFIG}",
        files=[Path(path)],
        apply=apply,
        validate=lambda: _validate(ctx),
        activate=None,
        change_key="fix.ssh.chmod",
        change_args={"path": SSHD_CONFIG},
    )
