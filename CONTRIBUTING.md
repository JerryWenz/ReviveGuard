# Contributing

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
```

Tests must never touch the real operating system: use the fixtures in
`tests/conftest.py` (fake filesystem root, fake command runner, fake `stat`).

## Conventions

- Code, identifiers, comments, commit messages: English.
- Audit mode is read-only. A check may only run read-only commands, through
  `AuditContext.runner` (no `shell=True`, always with a timeout).
- Never put secrets (keys, passwords, tokens) into evidence.
- No user-facing strings in Python code: use translation keys.

## Adding a check

1. Create `reviveguard/checks/<category>.py` with `run(ctx: AuditContext) -> list[CheckResult]`.
2. Read the host only through `ctx` (`ctx.read_text`, `ctx.runner`, `ctx.stat`, `ctx.path`).
3. Use unique IDs like `SSH-001`. A missing tool or service yields `Status.SKIPPED`, not a crash.
4. Register it in `reviveguard/checks/__init__.py` and add `<category>.module.title` to the catalogs.
5. Add translation keys for title/description/remediation (see `docs/translations.md`).
6. Add tests covering OK, FAIL, tool missing, and unreadable-file cases.

## Adding a fix

Fixes are not implemented yet. They will require backup, validation before apply,
verification after apply, and a documented rollback story. See the roadmap in the README.

## Adding a translation

See [docs/translations.md](docs/translations.md).
