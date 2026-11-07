"""Rendering of audit results as localized text or JSON."""

from __future__ import annotations

import json
import socket

from reviveguard import __version__
from reviveguard.context import AuditContext
from reviveguard.i18n import Translator
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.scanner import AuditReport

_STATUS_TAG = {Status.OK: "OK", Status.SKIPPED: "SKIP", Status.ERROR: "ERROR"}


def _tag(result: CheckResult) -> str:
    if result.status is Status.FAIL:
        return result.severity.name
    return _STATUS_TAG[result.status]


def render_header(t: Translator, ctx: AuditContext, lang: str) -> str:
    return "\n".join(
        [
            t("app.name"),
            t("app.tagline"),
            "",
            f"{t('label.system')}: {ctx.os_info.pretty_name}",
            f"{t('label.mode')}: {t('mode.audit')}",
            f"{t('label.language')}: {t(f'lang.{lang}')}",
            "",
        ]
    )


def render_text(t: Translator, ctx: AuditContext, report: AuditReport, lang: str) -> str:
    lines = [render_header(t, ctx, lang)]
    for r in report.results:
        lines.append(f"[{_tag(r)}] {t(r.title_key)}")
        if r.status is Status.FAIL:
            lines.append(f"    {t(r.description_key)}")
            for item in r.evidence:
                lines.append(f"    {t('label.evidence')}: {item}")
            lines.append(f"    {t('label.remediation')}: {t(r.remediation_key)}")
        elif r.status in (Status.SKIPPED, Status.ERROR):
            lines.append(f"    {t(r.description_key)}")
    lines.append("")
    lines.append(t("summary.completed"))
    lines.append("")
    lines.append(t("summary.findings"))
    counts = report.count_by_severity()
    for sev in sorted(Severity, reverse=True):
        lines.append(f"{sev.name + ':':<10}{counts[sev]}")
    for status, key in ((Status.SKIPPED, "summary.skipped"), (Status.ERROR, "summary.errors")):
        count = report.count_status(status)
        if count:
            lines.append(t(key, count=count))
    lines.append("")
    if not ctx.running_as_root:
        lines.append(t("summary.not_root"))
    if not ctx.os_info.is_supported:
        lines.append(t("summary.unsupported_os"))
    if report.count_status(Status.FAIL):
        lines.append(t("summary.hint_fix"))
    return "\n".join(lines).rstrip() + "\n"


def render_json(t: Translator, ctx: AuditContext, report: AuditReport, lang: str) -> str:
    results = []
    for r in report.results:
        data = r.to_dict()
        data["title"] = t(r.title_key)
        data["description"] = t(r.description_key)
        data["remediation"] = t(r.remediation_key)
        results.append(data)
    payload = {
        "reviveguard_version": __version__,
        "hostname": socket.gethostname(),
        "timestamp": report.timestamp,
        "language": lang,
        "os": {
            "id": ctx.os_info.id,
            "version_id": ctx.os_info.version_id,
            "pretty_name": ctx.os_info.pretty_name,
            "supported": ctx.os_info.is_supported,
        },
        "running_as_root": ctx.running_as_root,
        "modules": report.modules,
        "summary": {s.name: n for s, n in report.count_by_severity().items()},
        "results": results,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
