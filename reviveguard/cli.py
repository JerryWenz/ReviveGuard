"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from reviveguard import __version__
from reviveguard.backup import STATE_DIR, BackupError, Store
from reviveguard.config import Config, ConfigError, load_config
from reviveguard.context import AuditContext
from reviveguard.i18n import FALLBACK_LANGUAGE, Translator, available_languages
from reviveguard.output import render_json, render_text
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
        print(Translator(FALLBACK_LANGUAGE)("error.bad_config", detail=str(exc)), file=sys.stderr)
        return 2

    lang = resolve_language(args.lang, config, dict(os.environ))
    if lang is None:
        t = Translator(FALLBACK_LANGUAGE)
        print(t("error.unsupported_lang", lang=args.lang), file=sys.stderr)
        return 2
    t = Translator(lang)

    store = Store(args.state_dir)
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
