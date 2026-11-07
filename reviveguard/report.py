"""Security report (markdown / JSON). Secrets are redacted; there is no numeric score."""

from __future__ import annotations

import json
import re
import socket
from typing import Any

from reviveguard import __version__
from reviveguard.backup import Operation
from reviveguard.context import AuditContext
from reviveguard.fixes import AUTOMATIC
from reviveguard.i18n import Translator
from reviveguard.models import Severity, Status
from reviveguard.scanner import AuditReport

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S
)
_SECRET = re.compile(
    r"(?i)\b(password|passwd|passphrase|token|secret|api[_-]?key)\b(\s*[=:]\s*)\S+"
)
_PUBKEY = re.compile(
    r"\b(ssh-[a-z0-9]+|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.\-]+)\s+AAAA[A-Za-z0-9+/=]+"
)


def redact(text: str) -> str:
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    return _PUBKEY.sub(lambda m: f"{m.group(1)} [KEY REDACTED]", text)


def build(
    t: Translator, ctx: AuditContext, report: AuditReport, ops: list[Operation], lang: str
) -> dict[str, Any]:
    failing = [r for r in report.results if r.status is Status.FAIL]
    failing.sort(key=lambda r: (-int(r.severity), r.check_id))
    verification = {
        "applied": "passed",
        "rolled_back": "failed, change reverted",
        "failed": "failed",
        "pending": "interrupted",
    }
    return {
        "reviveguard_version": __version__,
        "hostname": socket.gethostname(),
        "timestamp": report.timestamp,
        "language": lang,
        "os": {
            "id": ctx.os_info.id,
            "version": ctx.os_info.version_id,
            "name": ctx.os_info.pretty_name,
        },
        "running_as_root": ctx.running_as_root,
        "summary": {s.name: n for s, n in report.count_by_severity().items()},
        "checks_performed": [
            {"id": r.check_id, "title": redact(t(r.title_key)), "status": r.status.value}
            for r in report.results
        ],
        "findings": [
            {
                "id": r.check_id,
                "severity": r.severity.name,
                "title": redact(t(r.title_key)),
                "description": redact(t(r.description_key)),
                "evidence": [redact(e) for e in r.evidence],
                "recommendation": redact(t(r.remediation_key)),
                "auto_fix_supported": r.check_id in AUTOMATIC,
                "restart_required": r.restart_required,
                "reboot_required": r.reboot_required,
            }
            for r in failing
        ],
        "applied_fixes": [
            {
                "id": op.op_id,
                "time": op.timestamp,
                "check": op.check_id,
                "description": redact(op.description),
                "status": op.status,
                "verification": verification.get(op.status, op.status),
                "reversible": op.reversible,
            }
            for op in ops
        ],
        "outstanding_risks": [r.check_id for r in failing],
    }


def render_json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def render_markdown(t: Translator, data: dict[str, Any]) -> str:
    out = [f"# {t('report.title')}", ""]
    out += [
        f"- **{t('report.host')}:** {data['hostname']}",
        f"- **{t('report.os')}:** {data['os']['name']}",
        f"- **{t('report.time')}:** {data['timestamp']}",
        f"- **{t('report.version')}:** {data['reviveguard_version']}",
        "",
        f"## {t('report.summary')}",
        "",
    ]
    out += [f"- {sev}: {n}" for sev, n in data["summary"].items()]
    out += ["", f"## {t('report.checks')}", ""]
    out += [f"- `{c['id']}` {c['title']} — {c['status']}" for c in data["checks_performed"]]
    out += ["", f"## {t('report.findings')}", ""]
    if not data["findings"]:
        out.append(t("report.none"))
    for f in data["findings"]:
        out += [f"### [{f['severity']}] {f['id']} — {f['title']}", "", f["description"], ""]
        out += [f"- {t('label.evidence')}: `{e}`" for e in f["evidence"]]
        out += [f"- {t('label.remediation')}: {f['recommendation']}", ""]
    out += [f"## {t('report.fixes')}", ""]
    if not data["applied_fixes"]:
        out.append(t("report.none"))
    for fx in data["applied_fixes"]:
        rev = "" if fx["reversible"] else f" ({t('history.not_reversible')})"
        head = f"- `{fx['id']}` {fx['time']} {fx['check']}: {fx['description']}"
        out.append(f"{head} — {fx['verification']}{rev}")
    out += ["", f"## {t('report.risks')}", ""]
    out.append(", ".join(f"`{i}`" for i in data["outstanding_risks"]) or t("report.none"))
    out += ["", f"_{t('report.note')}_", ""]
    return "\n".join(out)


def severity_counts(data: dict[str, Any]) -> int:
    return sum(n for sev, n in data["summary"].items() if sev != Severity.INFO.name)
