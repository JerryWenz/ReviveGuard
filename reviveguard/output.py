"""Rendering of audit results as localized text or JSON."""

from __future__ import annotations

import json
import socket

from reviveguard import __version__, ui
from reviveguard.context import AuditContext
from reviveguard.fixes import AUTOMATIC
from reviveguard.i18n import Translator
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.scanner import AuditReport

_STATUS_TAG = {Status.OK: "OK", Status.SKIPPED: "SKIP", Status.ERROR: "ERROR"}


def _tag(result: CheckResult) -> str:
    if result.status is Status.FAIL:
        return result.severity.name
    return _STATUS_TAG[result.status]


def render_header(t: Translator, ctx: AuditContext, lang: str, style: ui.Style) -> str:
    return "\n".join(
        [
            ui.banner(style, t("app.tagline"), __version__).rstrip("\n"),
            "",
            f"{t('label.system')}: {ctx.os_info.pretty_name}",
            f"{t('label.mode')}: {t('mode.audit')}",
            f"{t('label.language')}: {t(f'lang.{lang}')}",
            "",
        ]
    )


def render_text(
    t: Translator, ctx: AuditContext, report: AuditReport, lang: str, style: ui.Style | None = None
) -> str:
    style = style or ui.Style()
    lines = [render_header(t, ctx, lang, style)]
    for r in report.results:
        lines.append(f"{style.tag(_tag(r))} {style.bold(t(r.title_key))}")
        if r.status is Status.FAIL:
            lines.append(f"    {style.markup(t(r.description_key))}")
            for item in r.evidence:
                lines.append(f"    {t('label.evidence')}: {style.dim(item)}")
            lines.append(f"    {t('label.remediation')}: {style.markup(t(r.remediation_key))}")
        elif r.status in (Status.SKIPPED, Status.ERROR):
            lines.append(f"    {style.markup(t(r.description_key))}")
    lines.append("")
    lines.append(style.bold(t("summary.completed")))
    lines.append("")
    lines.append(t("summary.findings"))
    counts = report.count_by_severity()
    for sev in sorted(Severity, reverse=True):
        label = f"{sev.name + ':':<10}"
        shown = style.paint(label, *ui.SEVERITY_STYLE[sev.name]) if counts[sev] else label
        lines.append(f"{shown}{counts[sev]}")
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
        lines.append(style.markup(t("summary.hint_fix")))
    return "\n".join(lines).rstrip() + "\n"


def render_json(t: Translator, ctx: AuditContext, report: AuditReport, lang: str) -> str:
    results = []
    for r in report.results:
        data = r.to_dict()
        data["title"] = t(r.title_key)
        data["description"] = t(r.description_key)
        data["remediation"] = t(r.remediation_key)
        data["auto_fix_supported"] = r.check_id in AUTOMATIC  # a fix exists; it may still refuse
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
