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

A fix is a *planner* `plan(ctx, result) -> FixSpec | Manual` registered in
`reviveguard/fixes/__init__.py` under the check ID. The engine (`remediation.run_fix`) does the rest:
backup -> `apply` -> `validate` -> `activate` -> `verify` -> optional live confirmation -> record,
and restores the files automatically if any step fails or is interrupted.

Rules a fix must follow:

1. Return `Manual(reason_key)` whenever safety cannot be shown (missing tool, unclear state, lockout risk).
   Prefer a drop-in file over editing a main config; list **every** file you may change in `files`.
2. Validate before activating (`sshd -t`, `fail2ban-client -t`, `visudo -cf`) and **reload, never restart**.
3. Anything that can narrow access or affect running services sets `disruptive=True`; access changes also set
   `confirm_key` (live "type ok from a NEW terminal" confirmation) and `reload_service`.
4. Package operations go through `reviveguard/packages.py` (allow-listed, never remove); list them in `packages`
   and set `reversible=False` unless a file is also changed. Never reboot or restart services.
5. Never write secrets into evidence, descriptions or history. Add i18n keys for `change_key`, reasons and next steps.
6. Tests: success, refusal (`Manual`), failure after apply (must revert), interruption, and an unsafe-state case.
   Use the fake host helpers in `tests/` (`build_host`, `ssh_runner`); never touch the real system.

## Adding a translation

See [docs/translations.md](docs/translations.md).
