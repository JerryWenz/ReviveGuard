from __future__ import annotations

import json
import re

import pytest

from reviveguard.i18n import _DIR, Translator, available_languages

PLACEHOLDER = re.compile(r"\{(\w+)\}")


def catalog(lang):
    return json.loads((_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def test_languages_present():
    assert {"en", "ru"} <= set(available_languages())


@pytest.mark.parametrize("lang", [lang for lang in available_languages() if lang != "en"])
def test_catalogs_match_english(lang):
    en, other = catalog("en"), catalog(lang)
    assert set(en) == set(other), "keys must match en.json"
    for key in en:
        assert set(PLACEHOLDER.findall(en[key])) == set(PLACEHOLDER.findall(other[key])), key


def test_translation_and_formatting():
    assert Translator("ru")("summary.skipped", count=2) == "Пропущено проверок: 2"
    assert Translator("en")("summary.skipped", count=2) == "Skipped checks: 2"


def test_unknown_language_falls_back_to_english():
    assert Translator("zz")("summary.completed") == "Audit completed."


def test_missing_key_returns_key_and_missing_ru_key_falls_back(monkeypatch):
    t = Translator("ru")
    assert t("no.such.key") == "no.such.key"
    from reviveguard import i18n

    i18n._load.cache_clear()
    monkeypatch.setattr(i18n, "_load", lambda lang: {} if lang == "ru" else {"k": "english"})
    assert Translator("ru")("k") == "english"


def test_bad_format_args_do_not_crash():
    assert "{count}" in Translator("en")("summary.skipped")


def test_every_check_key_exists_in_english():
    en = catalog("en")
    from reviveguard.checks import REGISTRY
    from reviveguard.scanner import run_audit  # noqa: F401

    for key in en:
        assert isinstance(en[key], str)
    for module in REGISTRY:
        assert f"{module}.module.title" in en


def test_message_arguments_may_be_called_key():
    # regression: a message argument named "key" must not clash with the lookup key
    assert Translator("en")("config.saved", key="language", value="ru", path="/x") == (
        "Saved: language = ru (/x)"
    )
