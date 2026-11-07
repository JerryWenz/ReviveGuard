"""Sysctl fixes: a ReviveGuard drop-in in /etc/sysctl.d, applied with ``sysctl -p``.

Only settings with a safe, universal value are fixed (see ``Param.set_to``). Routing
related settings (forwarding, rp_filter) are recommendations only. Rolling back restores
the file; values already applied to the running kernel stay until reboot.
"""

from __future__ import annotations

from reviveguard.checks.sysctl import PARAMS, Param
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual, write_file_atomic

SYSCTL_FILE = "/etc/sysctl.d/99-reviveguard.conf"
HEADER = "# Managed by ReviveGuard. Remove this file to undo (takes effect after reboot).\n"


def _keys_for(param: Param) -> dict[str, int]:
    assert param.set_to is not None
    keys = list(param.keys)
    if "accept_redirects" in param.name or "source_route" in param.name:
        keys += [k.replace(".all.", ".default.") for k in param.keys]
    return {k: param.set_to for k in keys}


def parse_existing(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


def plan_sysctl(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    param = next((p for p in PARAMS if p.check_id == result.check_id), None)
    if param is None or param.set_to is None:
        return Manual("fix.reason.sysctl_manual")
    path = ctx.path(SYSCTL_FILE)
    merged = parse_existing(path.read_text(encoding="utf-8") if path.exists() else "")
    wanted = {k: str(v) for k, v in _keys_for(param).items()}
    merged.update(wanted)
    text = HEADER + "".join(f"{k} = {v}\n" for k, v in sorted(merged.items()))

    def apply() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)  # minimal systems may lack the directory
        write_file_atomic(path, text, 0o644)

    return FixSpec(
        fix_id=f"sysctl.{param.name}.set",
        check_id=result.check_id,
        description=f"Set {', '.join(f'{k}={v}' for k, v in wanted.items())} via {SYSCTL_FILE}",
        files=[path],
        apply=apply,
        validate=lambda: None,
        activate=lambda: ctx.runner(["sysctl", "-p", str(path)]).ok,
        change_key="fix.sysctl.set",
        change_args={"settings": ", ".join(f"{k} = {v}" for k, v in wanted.items())},
        service_key="fix.service.sysctl_runtime",
    )
