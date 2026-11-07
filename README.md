# ReviveGuard

Lightweight Linux server security auditor with (planned) controlled auto-remediation.

> **Status: early development (0.1.0.dev0).** Only read-only auditing of SSH settings is
> implemented. Not production-ready, not security-reviewed. Русская версия: [README.ru.md](README.ru.md).

## What works today

- `reviveguard audit` — read-only; never modifies the system.
- SSH checks `SSH-001`..`SSH-005`: root login, password authentication, empty passwords,
  public key authentication, `sshd_config` ownership/permissions.
- `reviveguard fix [--category ssh] [--check SSH-002]` — interactive fixes for the SSH findings
  (needs root). Every fix is explained, backed up, confirmed by you, validated, verified and
  recorded; failures restore the original files automatically.
- `reviveguard history` / `reviveguard rollback [--id FIX-YYYY-NNN] [--yes]` — backup store and
  rollback engine (used by future fixes; covered by tests, but no fix creates operations yet).
- Output in English and Russian (`--lang en|ru`), plain text or JSON.

## Not implemented yet

`fix --auto`, `report`, `config set`, and the firewall, fail2ban, Docker,
updates, permissions, services and sysctl checks. See the roadmap below.

## Requirements and tested platforms

- Python 3.11+; standard library only.
- Target: Debian 12+, Ubuntu 22.04+. Development and tests so far ran on Ubuntu 24.04 only;
  no other OS has been verified yet.

## Install and run

```bash
pip install -e .
reviveguard audit
reviveguard --lang ru audit
reviveguard audit --format json
sudo reviveguard audit   # root gives the most accurate SSH results (sshd -T)
```

Without root, SSH settings are read from `/etc/ssh/sshd_config` (with `Include` support and
OpenSSH defaults) instead of `sshd -T`; the report says which source was used.

## Configuration

TOML, default path `/etc/reviveguard/config.toml` or `--config FILE`; see
[examples/config.toml](examples/config.toml). Unknown keys are rejected.
Language priority: `--lang`, config `language`, locale (`LANG`), English.

## Security model

- Audit mode is read-only by design and covered by a test.
- Commands run as argument lists (no shell) with timeouts; missing tools are handled.
- Evidence contains configuration values only, never secrets.
- Future remediation will never change access (SSH, firewall) without backup, validation,
  verification and explicit confirmation. Package upgrades will be documented as non-reversible.

## SSH remediation safety

- Fixes add a small drop-in (`/etc/ssh/sshd_config.d/00-reviveguard-<option>.conf`) instead of
  rewriting `sshd_config`. Undo = `reviveguard rollback` (or delete the file).
- Order: pre-checks (current config must pass `sshd -t`, `Include` present, root, supported OS) →
  backup → write → `sshd -t` → **reload** (never restart) → re-run the check → record.
  A failure at any step restores the backup; if restoring itself fails you get an explicit
  instruction to run `reviveguard rollback --id ...`.
- Changing root login or password authentication needs a separate typed `yes`, and is **refused
  (manual remediation)** unless an alternative is verified: for a remote session the *current
  login user* must have a valid `authorized_keys` (permissions as `StrictModes` requires), be
  allowed by `AllowUsers`/`AllowGroups`/`Deny*`, and `AuthenticationMethods` must be default.
  Remote root sessions only ever get `prohibit-password`, and only if root has a key.
- Remote sessions are detected from `SSH_*` variables and an `sshd` ancestor process; the login
  user from `/proc/self/loginuid`, `SUDO_USER`, or the effective user.
- The server cannot prove that a client key actually works; it checks the prerequisites above.
  **Keep a second SSH session open** while applying disruptive fixes.

## Backup and rollback

State lives in `/var/lib/reviveguard` (`backups/`, `history/`, `reports/`, `config/`; mode 0700;
override with `--state-dir`). Before a fix changes a file, its content, mode and owner are saved
with a SHA-256 checksum, and the operation is recorded (check ID, remediation ID, intended change)
*before* the change, so an interrupted operation can still be rolled back.

`rollback` shows what will be restored, warns if a file was edited after the fix, validates the
backup checksum, asks for confirmation (or `--yes`), restores only the files of that operation,
and verifies content, mode and owner afterwards. It does **not** restart services: after rolling
back a service configuration, reload it yourself.

Limitations: package upgrades and external service changes cannot be reliably reversed and will
be recorded as non-reversible; symlinks are refused rather than backed up; backups of
sensitive files (e.g. `/etc/shadow`) are stored with mode 0600 inside a 0700 directory.

## Known limitations

- SSH fixes are covered by tests with a faked system; they have **not** been run against a real
  `sshd`/`systemd` yet. Try them on a non-critical machine first.
- Directives set in `sshd_config` before its `Include` line, or a missing `Include`, make the fix
  manual. `fix --auto` is not implemented.

- `Match` blocks in `sshd_config` are not evaluated; only global settings are checked.
- The file fallback assumes OpenSSH defaults and cannot see settings from other sources.

## Roadmap

1. (this) foundation, audit engine, SSH checks, i18n, CI
2. backup, history, rollback, verification
3. SSH fixes with lockout prevention, interactive `fix`
4. firewall and fail2ban checks and fixes
5. updates, permissions, sysctl, services, Docker
6. reports, `fix --auto` with policy, `config set`
7. documentation hardening, 0.1.0

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · Security: [SECURITY.md](SECURITY.md) · License: MIT
