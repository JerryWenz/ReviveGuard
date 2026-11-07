"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from reviveguard import __version__
from reviveguard.backup import STATE_DIR, BackupError, Store
from reviveguard.config import (
    Config,
    ConfigError,
    load_config,
    save_config,
    set_value,
    to_toml,
)
from reviveguard.context import AuditContext
from reviveguard.fixes import REGISTRY as FIXERS
from reviveguard.i18n import FALLBACK_LANGUAGE, Translator, available_languages
from reviveguard.models import Status
from reviveguard.output import render_json, render_text
from reviveguard.remediation import FixSpec, Manual, preflight, run_fix
from reviveguard.rollback import RollbackError, execute_rollback, plan_rollback
from reviveguard.scanner import run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reviveguard")
    parser.add_argument("--version", action="version", version=f"reviveguard {__version__}")
    parser.add_argument("--lang", help="output language code (e.g. en, ru)")
    parser.add_argument("--config", type=Path, help="path to a TOML configuration file")
    parser.add_argument(
        "--state-dir", type=Path, default=STATE_DIR, help="ReviveGuard state directory"
    )
    sub = parser.add_subparsers(dest="command")
    audit = sub.add_parser("audit", help="read-only security audit (default)")
    audit.add_argument("--format", choices=("text", "json"), default="text")
    fix = sub.add_parser("fix", help="review and apply fixes interactively")
    fix.add_argument("--category", help="only findings of this category (e.g. ssh)")
    fix.add_argument("--check", help="only this check ID (e.g. SSH-002)")
    fix.add_argument("--auto", action="store_true", help="(not implemented yet)")
    sub.add_parser("language", help="choose the interface language")
    cfg = sub.add_parser("config", help="show or change settings")
    cfg_sub = cfg.add_subparsers(dest="config_command")
    cfg_set = cfg_sub.add_parser("set", help="e.g. config set language ru")
    cfg_set.add_argument("key")
    cfg_set.add_argument("value")
    cfg_sub.add_parser("show", help="print the effective configuration")
    sub.add_parser("history", help="list recorded remediation operations")
    rollback = sub.add_parser("rollback", help="restore files changed by an operation")
    rollback.add_argument("--id", help="operation id, e.g. FIX-2026-001 (default: latest)")
    rollback.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    return parser


def resolve_language(flag: str | None, config: Config, env: dict[str, str]) -> str | None:
    """Priority: --lang, config file, environment locale, English.

    Returns None when ``flag`` names an unsupported language.
    """
    supported = available_languages()
    if flag is not None:
        return flag if flag in supported else None
    if config.language:
        return config.language
    locale = env.get("LC_ALL") or env.get("LC_MESSAGES") or env.get("LANG") or ""
    code = locale.split("_")[0].split(".")[0].lower()
    return code if code in supported else FALLBACK_LANGUAGE


def main(argv: list[str] | None = None, ctx: AuditContext | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command or "audit"
    fmt = getattr(args, "format", "text")

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        creating = command in ("config", "language") and args.config and not args.config.exists()
        if creating:
            config = Config()  # 'config set' may create the file it was pointed at
        else:
            message = Translator(FALLBACK_LANGUAGE)("error.bad_config", detail=str(exc))
            print(message, file=sys.stderr)
            return 2

    lang = resolve_language(args.lang, config, dict(os.environ))
    if lang is None:
        t = Translator(FALLBACK_LANGUAGE)
        print(t("error.unsupported_lang", lang=args.lang), file=sys.stderr)
        return 2
    t = Translator(lang)

    store = Store(args.state_dir)
    if command == "config":
        return cmd_config(t, config, args)
    if command == "language":
        return cmd_language(t, config, args)
    if command == "fix":
        return cmd_fix(t, store, ctx or AuditContext(), config, args)
    if command == "history":
        return cmd_history(t, store)
    if command == "rollback":
        return cmd_rollback(t, store, args.id, args.yes)
    if command != "audit":
        print(t("error.unknown_command"), file=sys.stderr)
        return 2

    ctx = ctx or AuditContext()
    report = run_audit(ctx, config)
    render = render_json if fmt == "json" else render_text
    sys.stdout.write(render(t, ctx, report, lang))
    return 0


def cmd_history(t: Translator, store: Store) -> int:
    ops, corrupt = store.list_operations()
    if not ops:
        print(t("history.empty"))
    for op in ops:
        line = f"{op.op_id}  {op.timestamp}  {op.check_id}  {t(f'op.status.{op.status}')}"
        if not op.reversible:
            line += f"  [{t('history.not_reversible')}]"
        print(line)
    if corrupt:
        print(t("history.corrupt", count=corrupt))
    return 0


def _latest_rollbackable(store: Store) -> str | None:
    ops, _ = store.list_operations()
    for op in reversed(ops):
        if op.reversible and op.status in ("applied", "pending", "failed"):
            return op.op_id
    return None


def cmd_rollback(t: Translator, store: Store, op_id: str | None, assume_yes: bool) -> int:
    try:
        op_id = op_id or _latest_rollbackable(store)
        if op_id is None:
            print(t("rollback.nothing"))
            return 0
        plan = plan_rollback(store, op_id)
    except BackupError as exc:
        print(t("rollback.not_found", detail=str(exc)), file=sys.stderr)
        return 1
    op = plan.operation
    print(t("rollback.plan", id=op.op_id, check=op.check_id, description=op.description))
    for problem_key, args in plan.problems:
        print(t("rollback.problem", detail=t(problem_key, **args)), file=sys.stderr)
    if not plan.can_execute:
        return 1
    for action in plan.actions:
        print(t(f"rollback.{action.kind}", path=action.path))
        if action.modified_since:
            print(t("rollback.warn_modified", path=action.path))
    if not assume_yes:
        try:
            answer = input(t("rollback.confirm"))
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print(t("rollback.cancelled"))
            return 1
    try:
        failed = execute_rollback(store, plan)
    except RollbackError as exc:
        print(t("rollback.io_error", detail=str(exc)), file=sys.stderr)
        return 1
    if failed:
        for path in failed:
            print(t("rollback.verify_failed", path=path), file=sys.stderr)
        return 1
    print(t("rollback.done", id=op.op_id))
    return 0


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return "q"  # no terminal: never assume consent


def _describe(t: Translator, ctx: AuditContext, result, spec: FixSpec) -> None:
    print(f"\n{t('fix.header', check_id=result.check_id, title=t(result.title_key))}")
    print(f"  {t('fix.risk')}: {t(result.description_key)}")
    for item in result.evidence:
        print(f"  {t('label.evidence')}: {item}")
    print(f"  {t('fix.change')}: {t(spec.change_key, **spec.change_args)}")
    affected = ", ".join(str(p).replace(str(ctx.root).rstrip("/"), "", 1) for p in spec.files)
    print(f"  {t('fix.affects')}: {affected}")
    if spec.service_key:
        print(f"  {t(spec.service_key)}")
    print(f"  {t('fix.backup_note')}")


def cmd_fix(t, store: Store, ctx: AuditContext, config: Config, args) -> int:
    if args.auto:
        print(t("fix.err.auto_not_implemented"), file=sys.stderr)
        return 2
    if not config.remediation.enabled:
        print(t("fix.err.disabled"), file=sys.stderr)
        return 1
    problem = preflight(ctx)
    if problem:
        print(t(problem), file=sys.stderr)
        return 1
    report = run_audit(ctx, config)
    findings = [
        r
        for r in report.results
        if r.status is Status.FAIL
        and (not args.category or r.category == args.category.lower())
        and (not args.check or r.check_id == args.check.upper())
    ]
    if not findings:
        print(t("fix.nothing"))
        return 0
    counts = {"applied": 0, "skipped": 0, "manual": 0, "failed": 0}
    exit_code = 0
    for result in findings:
        planner = FIXERS.get(result.check_id)
        plan = planner(ctx, result) if planner else Manual("fix.reason.no_autofix")
        if isinstance(plan, Manual):
            counts["manual"] += 1
            title = t(result.title_key)
            reason = t(plan.reason_key, **plan.args)
            print(f"\n[{result.check_id}] {title}\n  {t('fix.manual', reason=reason)}")
            print(f"  {t('label.remediation')}: {t(result.remediation_key)}")
            continue
        _describe(t, ctx, result, plan)
        if not plan.reversible:
            print(f"  {t('fix.not_reversible_note')}")
        answer = _ask(t("fix.prompt"))
        if answer == "q":
            print(t("fix.quit"))
            break
        if answer not in ("y", "yes"):
            counts["skipped"] += 1
            print(t("fix.skipped"))
            continue
        if plan.disruptive and _ask(t("fix.prompt_disruptive")) != "yes":
            counts["skipped"] += 1
            print(t("fix.skipped"))
            continue
        outcome = run_fix(store, ctx, plan)
        if outcome.status == "applied":
            counts["applied"] += 1
            print(t("fix.result.applied", id=outcome.op_id))
            continue
        counts["failed"] += 1
        exit_code = 1
        print(
            t(f"fix.result.{outcome.status}", detail=outcome.detail, id=outcome.op_id),
            file=sys.stderr,
        )
        if outcome.reverted:
            key = "fix.result.reverted" if outcome.revert_ok else "fix.result.revert_failed"
            print(t(key, id=outcome.op_id), file=sys.stderr)
        elif outcome.op_id:
            print(t("fix.result.not_reversible", id=outcome.op_id), file=sys.stderr)
    print("\n" + t("fix.summary", **counts))
    if counts["applied"]:
        print(t("fix.rerun_hint"))
    return exit_code


def cmd_config(t: Translator, config: Config, args) -> int:
    if args.config_command == "show":
        sys.stdout.write(to_toml(config))
        return 0
    if args.config_command != "set":
        print(t("config.usage"), file=sys.stderr)
        return 2
    try:
        updated = set_value(config, args.key, args.value)
    except ConfigError as exc:
        print(t("config.bad_value", key=args.key, detail=str(exc)), file=sys.stderr)
        return 2
    try:
        path = save_config(updated, args.config)
    except ConfigError as exc:
        print(t("error.config_write", detail=str(exc)), file=sys.stderr)
        return 1
    value = getattr(updated, args.key, None) if "." not in args.key else args.value
    new_t = Translator(updated.language) if args.key == "language" else t
    print(
        new_t(
            "config.saved",
            key=args.key,
            value=value if value is not None else args.value,
            path=path,
        )
    )
    return 0


def cmd_language(t: Translator, config: Config, args) -> int:
    codes = available_languages()
    for number, code in enumerate(codes, 1):
        print(f"  {number}) {code} - {Translator(code)('lang.native')}")
    try:
        answer = input(t("language.prompt")).strip().lower()
    except EOFError:
        print(t("language.no_terminal"), file=sys.stderr)
        return 1
    chosen = (
        codes[int(answer) - 1] if answer.isdigit() and 0 < int(answer) <= len(codes) else answer
    )
    if chosen not in codes:
        print(t("language.invalid"), file=sys.stderr)
        return 1
    args.config_command, args.key, args.value = "set", "language", chosen
    return cmd_config(t, config, args)
