"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from reviveguard import __version__
from reviveguard.config import Config, ConfigError, load_config
from reviveguard.context import AuditContext
from reviveguard.i18n import FALLBACK_LANGUAGE, Translator, available_languages
from reviveguard.output import render_json, render_text
from reviveguard.scanner import run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reviveguard")
    parser.add_argument("--version", action="version", version=f"reviveguard {__version__}")
    parser.add_argument("--lang", help="output language code (e.g. en, ru)")
    parser.add_argument("--config", type=Path, help="path to a TOML configuration file")
    sub = parser.add_subparsers(dest="command")
    audit = sub.add_parser("audit", help="read-only security audit (default)")
    audit.add_argument("--format", choices=("text", "json"), default="text")
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

    if command != "audit":
        print(t("error.unknown_command"), file=sys.stderr)
        return 2

    ctx = ctx or AuditContext()
    report = run_audit(ctx, config)
    render = render_json if fmt == "json" else render_text
    sys.stdout.write(render(t, ctx, report, lang))
    return 0
