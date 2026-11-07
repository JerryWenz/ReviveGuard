"""SSH fixes. Each planner refuses (``Manual``) whenever lockout cannot be ruled out.

Directive fixes never rewrite ``sshd_config``: they add a small drop-in file in
``/etc/ssh/sshd_config.d/`` that sorts first (sshd uses the first value it sees).
The new configuration is validated with ``sshd -t`` and the service is *reloaded*
(never restarted), so existing sessions stay connected.
"""

from __future__ import annotations

import hashlib
import os
import socket
import time
from pathlib import Path

from reviveguard.checks.firewall import collect as collect_firewall
from reviveguard.checks.firewall import is_active as firewall_active
from reviveguard.checks.services import parse_ss
from reviveguard.checks.ssh import SSHD_CONFIG, effective_config, ports_of, weak_algorithms
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual, write_file_atomic
from reviveguard.ssh_access import (
    admin_access,
    current_login_user,
    is_remote_session,
    read_passwd,
    session_auth_method,
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
    extra_lines: list[tuple[str, str]] | None = None,
    confirm_key: str | None = None,
    confirm_args: dict[str, str] | None = None,
) -> FixSpec:
    """Drop-in with ``key value`` (plus optional extra directives) for one fix."""
    directives = [(key, value), *(extra_lines or [])]
    name = f"00-reviveguard-{key.lower()}.conf"
    path = ctx.path(f"{DROPIN_DIR}/{name}")
    header = f"# Managed by ReviveGuard ({result.check_id}). Remove this file to undo."
    text = header + "\n" + "".join(f"{k} {v}\n" for k, v in directives)
    shown = "; ".join(f"{k} {v}" for k, v in directives)
    return FixSpec(
        fix_id=f"ssh.{key.lower()}.{value}"[:80],
        check_id=result.check_id,
        description=f"Set {shown} via drop-in {DROPIN_DIR}/{name}",
        files=[path],
        apply=lambda: write_file_atomic(path, text, 0o644),
        validate=lambda: _validate(ctx),
        activate=(lambda: reload_ssh(ctx)) if service else None,
        change_key="fix.ssh.set_directive",
        change_args={"path": f"{DROPIN_DIR}/{name}", "directive": shown},
        service_key="fix.service.reload_ssh" if service else None,
        disruptive=disruptive,
        reload_service="ssh" if service else None,
        # Commit-confirm: a change that can narrow access stays only if the administrator
        # proves, from a NEW session, that they can still get in.
        confirm_key=confirm_key or ("fix.confirm.ssh" if disruptive and service else None),
        confirm_args=confirm_args or {},
    )


def _needs_proof(ctx: AuditContext) -> Manual | None:
    """A remote session must itself have used a public key before access is narrowed.

    ``authorized_keys`` only says a key exists; a password login says nothing about whether the
    administrator holds the matching private key. Only a publickey login proves it.
    """
    if not is_remote_session(ctx):
        return None
    method = session_auth_method(ctx)
    if method == "publickey":
        return None
    if method is None:
        return Manual("fix.reason.auth_unknown")
    return Manual("fix.reason.logged_in_with_password", {"method": method})


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
    names = {a.name for a in others}
    password_admins = sorted(a.name for a in others if password_auth and a.has_password)

    def root_off() -> FixSpec:
        # The live confirmation asks for a login as the administrator (not root), which is
        # exactly the path that must keep working once root is switched off.
        return _dropin_spec(
            ctx,
            result,
            "PermitRootLogin",
            "no",
            True,
            confirm_key="fix.confirm.ssh_root",
            confirm_args={"admins": ", ".join(sorted(names))},
        )

    if password_admins and (not remote or user == "root" or user in names):
        return root_off()  # a password administrator exists: no key proof is needed
    proof = _needs_proof(ctx)
    if proof:
        return proof
    if remote and user == "root":
        # Never cut the branch we are sitting on: keep root key logins.
        if not root_key:
            return Manual("fix.reason.root_session_no_key")
        return _dropin_spec(ctx, result, "PermitRootLogin", "prohibit-password", True)
    if remote and user not in names:
        return Manual("fix.reason.no_key_for_current_user", {"user": str(user)})
    if others:
        return root_off()
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
    proof = _needs_proof(ctx)
    if proof:
        return proof
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


def plan_x11(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    _, refusal = _precheck(ctx, "x11forwarding")
    return refusal or _dropin_spec(ctx, result, "X11Forwarding", "no", False)


def plan_max_auth_tries(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    _, refusal = _precheck(ctx, "maxauthtries")
    return refusal or _dropin_spec(ctx, result, "MaxAuthTries", "4", False)


def plan_grace_time(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    _, refusal = _precheck(ctx, "logingracetime")
    return refusal or _dropin_spec(ctx, result, "LoginGraceTime", "30", False)


def plan_weak_algorithms(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    cfg, refusal = _precheck(ctx, "ciphers")
    if refusal:
        return refusal
    weak = weak_algorithms(cfg)
    if not weak:
        return Manual("fix.reason.nothing_to_fix")
    names = {"ciphers": "Ciphers", "macs": "MACs", "kexalgorithms": "KexAlgorithms"}
    lines = [(names[k], "-" + ",".join(v)) for k, v in weak.items()]  # '-' removes from defaults
    first, rest = lines[0], lines[1:]
    # Disruptive: very old clients that only speak these algorithms would be refused.
    return _dropin_spec(ctx, result, first[0], first[1], True, extra_lines=rest)


# ---------------- changing the SSH port (two phases) ----------------

PORT_DROPIN = "00-reviveguard-port.conf"
JAIL_PORT_FILE = "/etc/fail2ban/jail.d/reviveguard-sshd-port.local"


def stable_port(ctx: AuditContext, taken: set[int]) -> int:
    """A reproducible high port derived from the hostname (re-runs propose the same one)."""
    seed = int(hashlib.sha256(socket.gethostname().encode()).hexdigest(), 16)
    port = 20000 + seed % 40000
    while port in taken:
        port = 20000 + (port - 20000 + 1) % 40000
    return port


def listening_ports(ctx: AuditContext) -> set[int]:
    proc = ctx.runner(["ss", "-H", "-tuln"])
    return {x.port for x in parse_ss(proc.stdout)} if proc.ok else set()


def socket_activated(ctx: AuditContext) -> bool:
    """With ssh.socket, ports come from the socket unit, not from sshd_config."""
    return ctx.runner(["systemctl", "is-active", "--quiet", "ssh.socket"]).ok


def main_config_sets_port(ctx: AuditContext) -> bool:
    for raw in (ctx.read_text(SSHD_CONFIG) or "").splitlines():
        parts = raw.split("#", 1)[0].split()
        if parts and parts[0].lower().partition("=")[0] == "port":
            return True
    return False


def _firewall_blocks(ctx: AuditContext, port: int) -> bool:
    """True if an active firewall would not allow ``port`` (so the new port must not be added)."""
    state = collect_firewall(ctx)
    if not firewall_active(state):
        return False
    if state.ufw_active:
        return not any(
            rule_to.split()[0].split("/")[0] == str(port) and "ALLOW" in action.upper()
            for rule_to, action, _ in state.ufw_rules
        )
    return True  # nft/iptables/firewalld: rules cannot be verified generically


def _wait_listening(ctx: AuditContext, port: int, present: bool = True) -> bool:
    for _ in range(10):
        if (port in listening_ports(ctx)) == present:
            return True
        time.sleep(0.5)
    return False


def _port_files(ctx: AuditContext, ports: list[str]) -> tuple[list[Path], dict, str]:
    """sshd drop-in (+ fail2ban jail port drop-in when fail2ban is installed)."""
    sshd_path = ctx.path(f"{DROPIN_DIR}/{PORT_DROPIN}")
    header = "# Managed by ReviveGuard (SSH port). Remove this file to undo."
    texts = {sshd_path: header + "\n" + "".join(f"Port {p}\n" for p in ports)}
    jail_dir = ctx.path("/etc/fail2ban/jail.d")
    if jail_dir.is_dir() and not ctx.runner(["fail2ban-client", "--version"]).missing:
        jail = ctx.path(JAIL_PORT_FILE)
        texts[jail] = f"{header}\n[sshd]\nport = {','.join(ports)}\n"
    return list(texts), texts, ",".join(ports)


def _port_spec(
    ctx: AuditContext,
    result: CheckResult,
    ports: list[str],
    fix_id: str,
    must_listen: str,
    must_not_listen: str | None,
    next_key: str,
) -> FixSpec:
    files, texts, shown = _port_files(ctx, ports)

    def apply() -> None:
        for path, text in texts.items():
            write_file_atomic(path, text, 0o644)

    def activate() -> bool:
        ok = reload_ssh(ctx)
        if ok and len(files) > 1:
            ctx.runner(["fail2ban-client", "reload"])
        return ok

    def verify() -> str | None:
        if not _wait_listening(ctx, int(must_listen)):
            return f"sshd is not listening on port {must_listen}"
        if must_not_listen and not _wait_listening(ctx, int(must_not_listen), present=False):
            return f"sshd still listens on port {must_not_listen}"
        return None

    return FixSpec(
        fix_id=fix_id,
        check_id=result.check_id,
        description=f"Set SSH ports to {shown}",
        files=files,
        apply=apply,
        validate=lambda: _validate(ctx),
        activate=activate,
        change_key="fix.ssh.ports",
        change_args={"ports": shown},
        service_key="fix.service.reload_ssh",
        disruptive=True,
        reload_service="ssh",
        confirm_key="fix.confirm.ssh_port",
        confirm_args={"port": must_listen},
        verify=verify,
        next_key=next_key,
        next_args={"port": must_listen, "old": must_not_listen or "22"},
    )


def plan_port_add(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    """Phase 1: listen on a new port *and* keep the current one until the user confirms."""
    cfg, refusal = _precheck(ctx, "port")
    if refusal:
        return refusal
    if socket_activated(ctx):
        return Manual("fix.reason.ssh_socket")
    if main_config_sets_port(ctx):
        return Manual("fix.reason.port_in_main")
    current = ports_of(cfg)
    port = stable_port(ctx, listening_ports(ctx) | {int(p) for p in current})
    if _firewall_blocks(ctx, port):
        return Manual("fix.reason.firewall_open_port", {"port": str(port)})
    return _port_spec(
        ctx,
        result,
        [*current, str(port)],
        f"ssh.port.add.{port}",
        str(port),
        None,
        "fix.next.port_added",
    )


def plan_port_finish(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    """Phase 2: drop port 22 only after a login through the new port was verified."""
    cfg, refusal = _precheck(ctx, "port")
    if refusal:
        return refusal
    if socket_activated(ctx):
        return Manual("fix.reason.ssh_socket")
    if main_config_sets_port(ctx):
        return Manual("fix.reason.port_in_main")
    ports = ports_of(cfg)
    keep = [p for p in ports if p != "22"]
    if not keep:
        return Manual("fix.reason.nothing_to_fix")
    if is_remote_session(ctx):
        connected = (ctx.env.get("SSH_CONNECTION") or "").split()
        server_port = connected[3] if len(connected) >= 4 else ""
        if server_port not in keep:
            return Manual("fix.reason.reconnect_new_port", {"port": keep[0]})
    if int(keep[0]) not in listening_ports(ctx):
        return Manual("fix.reason.port_not_listening", {"port": keep[0]})
    return _port_spec(ctx, result, keep, "ssh.port.finish", keep[0], "22", "fix.next.port_finished")
