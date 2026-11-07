"""Translation catalogs: flat JSON files, one per language.

Adding a language means adding ``<code>.json`` here; no Python changes needed.
Missing keys fall back to English, then to the key itself.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path

FALLBACK_LANGUAGE = "en"
_DIR = Path(__file__).parent


def available_languages() -> list[str]:
    return sorted(p.stem for p in _DIR.glob("*.json"))


@cache
def _load(lang: str) -> dict[str, str]:
    path = _DIR / f"{lang}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


class Translator:
    def __init__(self, lang: str = FALLBACK_LANGUAGE) -> None:
        self.lang = lang if lang in available_languages() else FALLBACK_LANGUAGE

    def __call__(self, key: str, **kwargs: object) -> str:
        template = _load(self.lang).get(key) or _load(FALLBACK_LANGUAGE).get(key) or key
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return template
