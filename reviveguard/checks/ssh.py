"""SSH daemon checks (read-only).

The effective configuration comes from ``sshd -T`` when available (needs root
and host keys); otherwise ``/etc/ssh/sshd_config`` is parsed with first-match
semantics and OpenSSH defaults are assumed for unset keys.
"""

from __future__ import annotations

import glob
import stat as stat_mod

from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity, Status

SSHD_CONFIG = "/etc/ssh/sshd_config"
# OpenSSH defaults (Debian/Ubuntu ship these unless the config overrides them).
DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "pubkeyauthentication": "yes",
}
MAX_INCLUDE_DEPTH = 5


def parse_sshd_t(output: str) -> dict[str, str]:
    """Parse ``sshd -T`` output ("key value" per line, lowercase keys)."""
    result: dict[str, str] = {}
    for line in output.splitlines():
        key, _, value = line.strip().partition(" ")
        if key and key not in result:
            result[key.lower()] = value.strip().lower()
    return result


def parse_config_text(ctx: AuditContext, text: str, result: dict[str, str], depth: int = 0) -> bool:
    """Parse sshd_config text into ``result`` (first occurrence wins).

    Returns False once a ``Match`` block is reached: everything after it is
    conditional and must not be treated as global configuration.
    """
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" in line.split()[0]:
            key, _, value = line.partition("=")
        else:
            key, _, value = line.partition(" ")
        key, value = key.strip().lower(), value.strip().strip('"').lower()
        if key == "match":
            return False
        if key == "include" and depth < MAX_INCLUDE_DEPTH:
            for pattern in value.split():
                pattern = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                for found in sorted(glob.glob(str(ctx.path(pattern)))):
                    try:
                        sub = open(found, encoding="utf-8", errors="replace").read()  # noqa: SIM115
                    except OSError:
                        continue
                    if not parse_config_text(ctx, sub, result, depth + 1):
                        return False
            continue
        if key and key not in result:
            result[key] = value
    return True


def effective_config(ctx: AuditContext) -> tuple[dict[str, str], str] | None:
    """Return (settings, source) or None when SSH cannot be inspected."""
    proc = ctx.runner(["sshd", "-T"])
    if proc.ok and proc.stdout.strip():
        return parse_sshd_t(proc.stdout), "sshd -T"
    text = ctx.read_text(SSHD_CONFIG)
    if text is None:
        return None
    settings: dict[str, str] = {}
    parse_config_text(ctx, text, settings)
    return {**DEFAULTS, **settings}, f"{SSHD_CONFIG} (parsed)"


def _result(
    check_id: str,
    name: str,
    severity: Severity,
    failed: bool,
    evidence: str,
    restart: bool = True,
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category="ssh",
        severity=severity if failed else Severity.INFO,
        status=Status.FAIL if failed else Status.OK,
        title_key=f"ssh.{name}.title",
        description_key=f"ssh.{name}.desc",
        remediation_key=f"ssh.{name}.fix",
        evidence=(evidence,),
        restart_required=restart,
    )


def _permissions_check(ctx: AuditContext) -> CheckResult | None:
    try:
        st = ctx.stat(ctx.path(SSHD_CONFIG))
    except OSError:
        return None
    mode = stat_mod.S_IMODE(st.st_mode)
    bad = st.st_uid != 0 or bool(mode & 0o022)
    evidence = f"{SSHD_CONFIG}: owner uid={st.st_uid}, mode={mode:04o}"
    return _result("SSH-005", "config_perms", Severity.HIGH, bad, evidence, restart=False)


def run(ctx: AuditContext) -> list[CheckResult]:
    found = effective_config(ctx)
    if found is None:
        return [
            CheckResult(
                check_id="SSH-000",
                category="ssh",
                severity=Severity.INFO,
                status=Status.SKIPPED,
                title_key="ssh.module.title",
                description_key="ssh.skipped",
                remediation_key="remediation.none",
            )
        ]
    cfg, source = found

    def ev(key: str) -> str:
        return f"{key}={cfg.get(key, 'unset')} (source: {source})"

    root_login = cfg.get("permitrootlogin", DEFAULTS["permitrootlogin"])
    results = [
        _result("SSH-001", "root_login", Severity.HIGH, root_login == "yes", ev("permitrootlogin")),
        _result(
            "SSH-002",
            "password_auth",
            Severity.MEDIUM,
            cfg.get("passwordauthentication", "yes") == "yes",
            ev("passwordauthentication"),
        ),
        _result(
            "SSH-003",
            "empty_passwords",
            Severity.CRITICAL,
            cfg.get("permitemptypasswords", "no") == "yes",
            ev("permitemptypasswords"),
        ),
        _result(
            "SSH-004",
            "pubkey_auth",
            Severity.MEDIUM,
            cfg.get("pubkeyauthentication", "yes") != "yes",
            ev("pubkeyauthentication"),
        ),
    ]
    perms = _permissions_check(ctx)
    if perms is not None:
        results.append(perms)
    return results
