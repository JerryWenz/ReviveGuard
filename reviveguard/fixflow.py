"""Remediation flows: interactive ``fix``, the reviewed batch ``fix --auto``, and ``wizard``."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from reviveguard import __version__, ui
from reviveguard import report as report_mod
from reviveguard.backup import Store
from reviveguard.config import Config
from reviveguard.context import AuditContext
from reviveguard.fixes import REGISTRY as FIXERS
from reviveguard.fixes.access import admin_result, plan_admin_user, validate_username
from reviveguard.i18n import Translator
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.remediation import FixSpec, Manual, preflight, run_fix
from reviveguard.scanner import AuditReport, run_audit


@dataclass
class Item:
    result: CheckResult
    plan: FixSpec | Manual


CONFIRM_SECONDS = 120


def read_confirmation(timeout: int) -> bool:
    """Wait up to ``timeout`` seconds for the user to type 'ok'/'y' (no terminal: False)."""
    import select

    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        line = sys.stdin.readline() if ready else ""
    except (OSError, ValueError):
        return False
    return line.strip().lower() in ("ok", "y", "yes")


def live_confirm(con: Console, spec: FixSpec) -> bool:
    """Commit-confirm: the change stays only if the user confirms in time."""
    con.say(f"  {con.style.bold(con.t(spec.confirm_key or '', **spec.confirm_args))}")
    con.say(f"  {con.t('fix.confirm.waiting', seconds=CONFIRM_SECONDS)}")
    return read_confirmation(CONFIRM_SECONDS)


class Console:
    """Printing with markup highlighting and a prompt that treats EOF as 'no'."""

    def __init__(self, t: Translator, style: ui.Style) -> None:
        self.t, self.style = t, style

    def say(self, text: str = "", err: bool = False) -> None:
        print(self.style.markup(text), file=sys.stderr if err else sys.stdout)

    def ask(self, prompt: str, default: str = "", lower: bool = True) -> str:
        try:
            answer = input(self.style.markup(prompt)).strip()
        except EOFError:
            return "q" if lower else ""  # no terminal: never assume consent
        answer = answer.lower() if lower else answer
        return answer or default


def collect(
    ctx: AuditContext, config: Config, category: str | None = None, check: str | None = None
) -> tuple[AuditReport, list[Item]]:
    report = run_audit(ctx, config)
    items = []
    for r in report.results:
        if r.status is not Status.FAIL:
            continue
        if category and r.category != category.lower():
            continue
        if check and r.check_id != check.upper():
            continue
        planner = FIXERS.get(r.check_id)
        plan = planner(ctx, r) if planner else Manual("fix.reason.no_autofix")
        items.append(Item(r, plan))
    return report, items


def auto_block_reason(config: Config, item: Item) -> str | None:
    """Why a fix may not be part of the reviewed automatic set (None = eligible)."""
    spec = item.plan
    if not isinstance(spec, FixSpec):
        return "fix.auto.skip_manual"
    if spec.disruptive:
        return "fix.auto.skip_disruptive"
    if item.result.severity is Severity.CRITICAL and not config.remediation.allow_critical:
        return "fix.auto.skip_critical"
    if item.result.severity is Severity.HIGH and not config.remediation.allow_high:
        return "fix.auto.skip_high"
    return None


def describe(con: Console, ctx: AuditContext, result: CheckResult, spec: FixSpec) -> None:
    t, s = con.t, con.style
    tag = s.tag(result.severity.name)
    con.say(f"\n{tag} {s.bold(result.check_id)}: {s.bold(t(result.title_key))}")
    con.say(f"  {t('fix.risk')}: {t(result.description_key)}")
    for item in result.evidence:
        con.say(f"  {t('label.evidence')}: {s.dim(item)}")
    con.say(f"  {t('fix.change')}: {t(spec.change_key, **spec.change_args)}")
    root = str(ctx.root).rstrip("/")
    affected = ", ".join(str(p).replace(root, "", 1) for p in spec.files)
    if affected:
        con.say(f"  {t('fix.affects')}: {affected}")
    if spec.service_key:
        con.say(f"  {t(spec.service_key)}")
    if not spec.reversible:
        con.say(f"  {t('fix.not_reversible_note')}")
    con.say(f"  {s.dim(t('fix.backup_note'))}")


def show_manual(con: Console, item: Item) -> None:
    t, s = con.t, con.style
    r, plan = item.result, item.plan
    assert isinstance(plan, Manual)
    con.say(f"\n{s.tag(r.severity.name)} {s.bold(r.check_id)}: {t(r.title_key)}")
    con.say(f"  {t('fix.manual', reason=t(plan.reason_key, **plan.args))}")
    con.say(f"  {t('label.remediation')}: {t(r.remediation_key)}")


def apply_item(con: Console, store: Store, ctx: AuditContext, item: Item) -> bool:
    """Run one fix and print the outcome. Returns True on success."""
    t, s = con.t, con.style
    spec = item.plan
    assert isinstance(spec, FixSpec)
    outcome = run_fix(store, ctx, spec, confirm=lambda sp: live_confirm(con, sp))
    if outcome.status == "applied":
        con.say(f"  {s.paint('OK', 'green', 'bold')} {t('fix.result.applied', id=outcome.op_id)}")
        if spec.next_key:
            con.say(f"  {s.bold(t('fix.next'))} {t(spec.next_key, **spec.next_args)}")
        return True
    msg = t(f"fix.result.{outcome.status}", detail=outcome.detail, id=outcome.op_id)
    con.say(f"  {s.paint('FAILED', 'red', 'bold')} {msg}", err=True)
    if outcome.reverted:
        key = "fix.result.reverted" if outcome.revert_ok else "fix.result.revert_failed"
        con.say(f"  {t(key, id=outcome.op_id)}", err=True)
    elif outcome.op_id:
        con.say(f"  {t('fix.result.not_reversible', id=outcome.op_id)}", err=True)
    if spec.packages:
        con.say(f"  {t('fix.result.packages_remain', packages=', '.join(spec.packages))}", err=True)
    return False


def _guard(con: Console, ctx: AuditContext, config: Config) -> int | None:
    if not config.remediation.enabled:
        con.say(con.t("fix.err.disabled"), err=True)
        return 1
    problem = preflight(ctx)
    if problem:
        con.say(con.t(problem), err=True)
        return 1
    return None


def interactive(
    con: Console, store: Store, ctx: AuditContext, items: list[Item]
) -> tuple[dict[str, int], int]:
    t = con.t
    counts = {"applied": 0, "skipped": 0, "manual": 0, "failed": 0}
    code = 0
    for item in items:
        if isinstance(item.plan, Manual):
            counts["manual"] += 1
            show_manual(con, item)
            continue
        describe(con, ctx, item.result, item.plan)
        answer = con.ask(t("fix.prompt"))
        if answer == "q":
            con.say(t("fix.quit"))
            break
        if answer not in ("y", "yes"):
            counts["skipped"] += 1
            con.say(t("fix.skipped"))
            continue
        if item.plan.disruptive and con.ask(t("fix.prompt_disruptive")) != "yes":
            counts["skipped"] += 1
            con.say(t("fix.skipped"))
            continue
        if apply_item(con, store, ctx, item):
            counts["applied"] += 1
        else:
            counts["failed"] += 1
            code = 1
    return counts, code


def batch(
    con: Console,
    store: Store,
    ctx: AuditContext,
    eligible: list[Item],
    assume_yes: bool,
    default: str,
) -> tuple[int, int]:
    """Show the reviewed set, confirm once, then apply. Returns (applied, failed)."""
    t, s = con.t, con.style
    con.say(f"\n{s.bold(t('fix.auto.header'))}")
    for number, item in enumerate(eligible, 1):
        spec = item.plan
        assert isinstance(spec, FixSpec)
        tag = s.tag(item.result.severity.name)
        con.say(f"  {number}. {tag} {item.result.check_id} {t(item.result.title_key)}")
        con.say(f"       {s.dim(t(spec.change_key, **spec.change_args))}")
    if not assume_yes:
        answer = con.ask(t("fix.auto.confirm", count=len(eligible)), default)
        if answer not in ("y", "yes"):
            con.say(t("fix.skipped"))
            return 0, 0
    applied = 0
    for number, item in enumerate(eligible, 1):
        con.say(f"\n{s.step(number, len(eligible), t(item.result.title_key))}")
        if apply_item(con, store, ctx, item):
            applied += 1
        else:
            con.say(t("fix.auto.stopped"), err=True)
            return applied, 1
    return applied, 0


def split_items(config: Config, items: list[Item]) -> tuple[list[Item], list[Item], list[Item]]:
    eligible = [i for i in items if auto_block_reason(config, i) is None]
    needs_decision = [
        i for i in items if isinstance(i.plan, FixSpec) and auto_block_reason(config, i)
    ]
    manual = [i for i in items if isinstance(i.plan, Manual)]
    return eligible, needs_decision, manual


def cmd_fix(
    t: Translator, style: ui.Style, store: Store, ctx: AuditContext, config: Config, args
) -> int:
    con = Console(t, style)
    blocked = _guard(con, ctx, config)
    if blocked is not None:
        return blocked
    _, items = collect(ctx, config, args.category, args.check)
    if not items:
        con.say(t("fix.nothing"))
        return 0
    if args.auto:
        eligible, needs_decision, manual = split_items(config, items)
        applied, failed = 0, 0
        if eligible:
            applied, failed = batch(con, store, ctx, eligible, args.yes, "")
        else:
            con.say(t("fix.auto.none"))
        if needs_decision:
            con.say(f"\n{style.bold(t('fix.auto.skipped_header'))}")
            for item in needs_decision:
                reason = t(auto_block_reason(config, item) or "")
                con.say(f"  {item.result.check_id} {t(item.result.title_key)} - {reason}")
        for item in manual:
            show_manual(con, item)
        con.say(
            "\n"
            + t(
                "fix.summary",
                applied=applied,
                skipped=len(needs_decision),
                manual=len(manual),
                failed=failed,
            )
        )
        if applied:
            con.say(t("fix.rerun_hint"))
        return 1 if failed else 0
    counts, code = interactive(con, store, ctx, items)
    con.say("\n" + t("fix.summary", **counts))
    if counts["applied"]:
        con.say(t("fix.rerun_hint"))
    return code


def summary_line(con: Console, report: AuditReport) -> str:
    c = report.count_by_severity()
    t = con.t
    total = sum(n for sev, n in c.items() if sev is not Severity.INFO)
    return t(
        "wizard.scan_done",
        count=total,
        critical=c[Severity.CRITICAL],
        high=c[Severity.HIGH],
        medium=c[Severity.MEDIUM],
        low=c[Severity.LOW],
    )


def cmd_wizard(
    t: Translator, style: ui.Style, store: Store, ctx: AuditContext, config: Config, args, lang: str
) -> int:
    con = Console(t, style)
    con.say(ui.banner(style, t("app.tagline"), __version__))
    con.say(t("wizard.intro"))
    blocked = _guard(con, ctx, config)
    if blocked is not None:
        return blocked
    total = 4

    con.say(f"\n{style.step(1, total, t('wizard.step.scan'))}")
    report, items = collect(ctx, config)
    con.say(f"  {summary_line(con, report)}")
    if not items:
        con.say(f"  {t('wizard.nothing_to_do')}")

    eligible, needs_decision, manual = split_items(config, items)
    con.say(f"\n{style.step(2, total, t('wizard.step.safe'))}")
    code = 0
    if eligible:
        con.say(f"  {t('wizard.safe_list')}")
        applied, failed = batch(con, store, ctx, eligible, args.yes, "y")
        code = 1 if failed else 0
        if failed:
            con.say(t("fix.auto.stopped"), err=True)
    else:
        con.say(f"  {t('wizard.safe_none')}")

    con.say(f"\n{style.step(3, total, t('wizard.step.access'))}")
    created_admin = False
    if any(i.result.check_id == "USR-001" for i in manual) and code == 0:
        con.say(f"  {t('wizard.admin_offer')}")
        if con.ask(t("wizard.admin_confirm"), "y") in ("y", "yes"):
            created_admin = admin_flow(con, store, ctx, config) == 0
            manual = [i for i in manual if i.result.check_id != "USR-001"]
    if created_admin:
        con.say(f"  {t('wizard.admin_created')}")
    elif needs_decision and code == 0:
        con.say(f"  {t('wizard.access_intro')}")
        counts, code = interactive(con, store, ctx, needs_decision)
    elif not needs_decision:
        con.say(f"  {t('wizard.access_none')}")
    if manual:
        con.say(f"\n{style.bold(t('wizard.manual_title'))}")
        for item in manual:
            show_manual(con, item)

    con.say(f"\n{style.step(4, total, t('wizard.step.final'))}")
    final = run_audit(ctx, config)
    con.say(f"  {summary_line(con, final)}")
    ops, _ = store.list_operations()
    data = report_mod.build(t, ctx, final, ops, lang)
    try:
        store.ensure()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        path = store.reports / f"report-{stamp}.md"
        path.write_text(report_mod.render_markdown(t, data), encoding="utf-8")
        os.chmod(path, 0o600)
        con.say(f"  {t('wizard.report_saved', path=path)}")
    except Exception:
        con.say(f"  {t('wizard.report_failed')}", err=True)
    con.say(f"\n{t('wizard.done')}")
    return code


def admin_flow(
    con: Console,
    store: Store,
    ctx: AuditContext,
    config: Config,
    name: str | None = None,
    key_line: str | None = None,
    nopasswd: bool = True,
    assume_yes: bool = False,
) -> int:
    """Create a key-only sudo administrator (asks for what is missing)."""
    t = con.t
    blocked = _guard(con, ctx, config)
    if blocked is not None:
        return blocked
    con.say(f"\n{con.style.bold(t('admin.title'))}")
    con.say(f"  {t('admin.intro')}")
    if name is None:
        name = con.ask(t("admin.ask_name"), "admin", lower=False)
    problem = validate_username(name)
    if problem:
        con.say(t(problem), err=True)
        return 1
    if key_line is None:
        con.say(f"  {t('admin.key_help')}")
        key_line = con.ask(t("admin.ask_key"), "", lower=False)
    plan = plan_admin_user(ctx, name, key_line, nopasswd)
    if isinstance(plan, Manual):
        con.say(t(plan.reason_key, **plan.args), err=True)
        return 1
    item = Item(admin_result(), plan)
    describe(con, ctx, item.result, plan)
    if not assume_yes and con.ask(t("fix.prompt"), "y") not in ("y", "yes"):
        con.say(t("fix.skipped"))
        return 1
    return 0 if apply_item(con, store, ctx, item) else 1


def cmd_admin_user(
    t: Translator, style: ui.Style, store: Store, ctx: AuditContext, config: Config, args
) -> int:
    key_line = None
    if args.key_file:
        try:
            lines = args.key_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            Console(t, style).say(
                t("admin.err.key_file", detail=exc.strerror or str(exc)), err=True
            )
            return 1
        key_line = next((x for x in lines if x.strip() and not x.startswith("#")), "")
    return admin_flow(
        Console(t, style),
        store,
        ctx,
        config,
        args.name,
        key_line,
        nopasswd=not args.require_sudo_password,
        assume_yes=args.yes,
    )
