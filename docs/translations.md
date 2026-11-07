# Translations

Catalogs are flat JSON files in `reviveguard/i18n/<code>.json` mapping a key to a
string. English (`en.json`) is the reference and the fallback.

## Adding a language

1. Copy `en.json` to `<code>.json` (ISO 639-1 code, e.g. `de.json`).
2. Translate the values. Do **not** change keys.
3. Keep placeholders such as `{count}` exactly as in English.
4. Add `lang.<code>` (the language's name, in that catalog and in the others).
5. Run `pytest tests/test_i18n.py`: it verifies that keys and placeholders match `en.json`.

No Python changes are needed. The language becomes available to `--lang` and the
`language` config key automatically. Missing keys fall back to English.

## Key naming

`<module>.<check>.title|desc|fix`, plus `summary.*`, `label.*`, `error.*`.
Evidence lines (technical data) are intentionally not translated.
Command names, option names and config keys inside strings stay in English.
