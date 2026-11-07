"""SSH daemon checks (read-only).

The effective configuration comes from ``sshd -T`` when available (needs root
and host keys); otherwise ``/etc/ssh/sshd_config`` is parsed with first-match
semantics and OpenSSH defaults are assumed for unset keys.
"""

from __future__ import annotations

import glob
import stat as stat_mod
from pathlib import Path

from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.ssh_access import authorized_keys_problems

SSHD_CONFIG = "/etc/ssh/sshd_config"
# OpenSSH defaults (Debian/Ubuntu ship these unless the config overrides them).
DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "pubkeyauthentication": "yes",
    "x11forwarding": "no",
    "maxauthtries": "6",
    "logingracetime": "120",
    "port": "22",
}
MAX_AUTH_TRIES = 4
MAX_GRACE_SECONDS = 60
WEAK_CIPHERS = ("3des", "arcfour", "blowfish", "cast128")
WEAK_MACS = ("md5", "-sha1-96", "ripemd160", "umac-64")
WEAK_KEX = (
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
)


def parse_seconds(value: str) -> int | None:
    """sshd time values: plain seconds or with s/m/h/d/w suffixes (``2m``, ``1h30m``)."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    total, number = 0, ""
    for ch in value.strip().lower():
        if ch.isdigit():
            number += ch
        elif ch in units and number:
            total, number = total + int(number) * units[ch], ""
        else:
            return None
    return total + int(number) if number else (total if value.strip() else None)


def ports_of(cfg: dict[str, str]) -> list[str]:
    return [p for p in cfg.get("port", "22").split() if p.isdigit()] or ["22"]


def weak_algorithms(cfg: dict[str, str]) -> dict[str, list[str]]:
    """Weak entries present in the *effective* (sshd -T) algorithm lists."""
    found: dict[str, list[str]] = {}
    for key, marks, exact in (
        ("ciphers", WEAK_CIPHERS, False),
        ("macs", WEAK_MACS, False),
        ("kexalgorithms", WEAK_KEX, True),
    ):
        names = [n for n in cfg.get(key, "").split(",") if n]
        weak = [
            n
            for n in names
            if (n in marks if exact else any(m in n for m in marks))
            or (key == "ciphers" and n.endswith("-cbc"))
        ]
        if weak:
            found[key] = weak
    return found


MAX_INCLUDE_DEPTH = 5
# Keys whose repeated occurrences accumulate instead of "first match wins".
MULTI_VALUED = {"allowusers", "denyusers", "allowgroups", "denygroups", "port"}


def _store(result: dict[str, str], key: str, value: str) -> None:
    """Values keep their original case (user names and paths are case-sensitive)."""
    if key in MULTI_VALUED:
        result[key] = f"{result[key]} {value}" if key in result else value
    elif key and key not in result:
        result[key] = value


def parse_sshd_t(output: str) -> dict[str, str]:
    """Parse ``sshd -T`` output ("key value" per line, lowercase keys)."""
    result: dict[str, str] = {}
    for line in output.splitlines():
        key, _, value = line.strip().partition(" ")
        _store(result, key.lower(), value.strip())
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
        key, value = key.strip().lower(), value.strip().strip('"')
        if key == "match":
            return False
        if key == "include" and depth < MAX_INCLUDE_DEPTH:
            for pattern in value.split():
                pattern = pattern if pattern.startswith("/") else f"/etc/ssh/{pattern}"
                for found in sorted(glob.glob(str(ctx.path(pattern)))):
                    try:
                        sub = Path(found).read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    if not parse_config_text(ctx, sub, result, depth + 1):
                        return False
            continue
        _store(result, key, value)
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
    evidence: str | list[str],
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
        evidence=(evidence,) if isinstance(evidence, str) else tuple(evidence),
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

    root_login = cfg.get("permitrootlogin", DEFAULTS["permitrootlogin"]).lower()
    results = [
        _result("SSH-001", "root_login", Severity.HIGH, root_login == "yes", ev("permitrootlogin")),
        _result(
            "SSH-002",
            "password_auth",
            Severity.MEDIUM,
            cfg.get("passwordauthentication", "yes").lower() == "yes",
            ev("passwordauthentication"),
        ),
        _result(
            "SSH-003",
            "empty_passwords",
            Severity.CRITICAL,
            cfg.get("permitemptypasswords", "no").lower() == "yes",
            ev("permitemptypasswords"),
        ),
        _result(
            "SSH-004",
            "pubkey_auth",
            Severity.MEDIUM,
            cfg.get("pubkeyauthentication", "yes").lower() != "yes",
            ev("pubkeyauthentication"),
        ),
    ]
    grace = parse_seconds(cfg.get("logingracetime", "120"))
    ports = ports_of(cfg)
    results += [
        _result(
            "SSH-006",
            "x11_forwarding",
            Severity.LOW,
            cfg.get("x11forwarding", "no").lower() == "yes",
            ev("x11forwarding"),
        ),
        _result(
            "SSH-007",
            "max_auth_tries",
            Severity.LOW,
            not cfg.get("maxauthtries", "6").isdigit()
            or int(cfg.get("maxauthtries", "6")) > MAX_AUTH_TRIES,
            ev("maxauthtries"),
            restart=True,
        ),
        _result(
            "SSH-008",
            "grace_time",
            Severity.LOW,
            grace is None or grace == 0 or grace > MAX_GRACE_SECONDS,
            ev("logingracetime"),
        ),
        _result(
            "SSH-010",
            "default_port",
            Severity.LOW,
            ports == ["22"],
            [f"port={' '.join(ports)} (source: {source})"],
        ),
    ]
    if len(ports) > 1 and "22" in ports:
        results.append(
            _result(
                "SSH-011",
                "port_migration",
                Severity.LOW,
                True,
                [f"sshd listens on ports {', '.join(ports)}; 22 is still open"],
            )
        )
    if source.startswith("sshd -T"):
        weak = weak_algorithms(cfg)
        evidence = [f"{k}: {', '.join(v)}" for k, v in weak.items()] or ["no weak algorithms"]
        results.append(_result("SSH-009", "weak_algorithms", Severity.MEDIUM, bool(weak), evidence))
    keys_problems = authorized_keys_problems(ctx, cfg)
    results.append(
        _result(
            "SSH-012",
            "authkeys_perms",
            Severity.MEDIUM,
            bool(keys_problems),
            keys_problems or ["authorized_keys files and their directories look correct"],
            restart=False,
        )
    )
    perms = _permissions_check(ctx)
    if perms is not None:
        results.append(perms)
    return results
