"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from reviveguard import __version__, ui
from reviveguard import report as report_mod
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
from reviveguard.fixflow import cmd_admin_user, cmd_fix, cmd_wizard
from reviveguard.i18n import FALLBACK_LANGUAGE, Translator, available_languages
from reviveguard.output import render_json, render_text
from reviveguard.rollback import RollbackError, execute_rollback, plan_rollback
from reviveguard.scanner import run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reviveguard")
    parser.add_argument("--version", action="version", version=f"reviveguard {__version__}")
    parser.add_argument("--lang", help="output language code (e.g. en, ru)")
    parser.add_argument("--no-color", action="store_true", help="disable colors")
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
    fix.add_argument("--auto", action="store_true", help="apply the reviewed safe set")
    fix.add_argument("--yes", action="store_true", help="with --auto: skip the confirmation")
    wiz = sub.add_parser("wizard", help="guided hardening: scan, safe fixes, decisions, report")
    wiz.add_argument("--yes", action="store_true", help="apply the safe set without asking")
    rep = sub.add_parser("report", help="security report (markdown or json)")
    rep.add_argument("--format", choices=("markdown", "json"), help="default: from the config")
    rep.add_argument("--output", type=Path, help="write the report to this file")
    adm = sub.add_parser("admin-user", help="create a key-only sudo administrator account")
    adm.add_argument("--name", help="account name (default: ask, suggestion 'admin')")
    adm.add_argument("--key-file", type=Path, help="file with the public key (first key line)")
    adm.add_argument("--require-sudo-password", action="store_true", help="no NOPASSWD sudoers")
    adm.add_argument("--yes", action="store_true", help="do not ask for confirmation")
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
    style = ui.detect(sys.stdout, args.no_color)
    if command == "fix":
        return cmd_fix(t, style, store, ctx or AuditContext(), config, args)
    if command == "admin-user":
        return cmd_admin_user(t, style, store, ctx or AuditContext(), config, args)
    if command == "wizard":
        return cmd_wizard(t, style, store, ctx or AuditContext(), config, args, lang)
    if command == "report":
        return cmd_report(t, store, ctx or AuditContext(), config, args, lang)
    if command == "history":
        return cmd_history(t, store)
    if command == "rollback":
        return cmd_rollback(t, store, args.id, args.yes)
    if command != "audit":
        print(t("error.unknown_command"), file=sys.stderr)
        return 2

    ctx = ctx or AuditContext()
    report = run_audit(ctx, config)
    if fmt == "json":
        sys.stdout.write(render_json(t, ctx, report, lang))
    else:
        sys.stdout.write(render_text(t, ctx, report, lang, style))
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


def cmd_report(
    t: Translator, store: Store, ctx: AuditContext, config: Config, args, lang: str
) -> int:
    report = run_audit(ctx, config)
    ops, _ = store.list_operations()
    data = report_mod.build(t, ctx, report, ops, lang)
    fmt = args.format or config.report.format
    text = report_mod.render_json(data) if fmt == "json" else report_mod.render_markdown(t, data)
    if args.output:
        try:
            args.output.write_text(text, encoding="utf-8")
            args.output.chmod(0o600)
        except OSError as exc:
            print(t("error.report_write", detail=exc.strerror or str(exc)), file=sys.stderr)
            return 1
        print(t("report.saved", path=args.output))
    else:
        sys.stdout.write(text)
    return 0
