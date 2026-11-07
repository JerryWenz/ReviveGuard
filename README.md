# ReviveGuard

Lightweight Linux server security auditor with (planned) controlled auto-remediation.

> **Status: early development (0.1.0.dev1).** Audits (SSH, firewall, fail2ban, updates, permissions,
> sysctl, services) and interactive fixes work in tests. On one real Ubuntu 22.04 server the installer,
> the audit and the sysctl and fail2ban fixes were tried (reported working by the author); all other
> fixes (SSH, apt updates, ufw, permissions) have only run against a faked system.
> Not production-ready, not security-reviewed. Русская версия: [README.ru.md](README.ru.md).

## Quick start

```bash
sudo reviveguard wizard        # guided: scan -> safe fixes (one confirmation) -> decisions -> report
sudo reviveguard report        # full report (markdown; --format json, --output FILE)
sudo reviveguard fix --auto    # show the reviewed safe set, confirm once, apply
```

The terminal UI shows a logo and colors only on a real terminal (`--no-color` or `NO_COLOR=1`
turns colors off; pipes and logs get plain text). Automatic mode never applies fixes that can
affect access or restart services, and skips CRITICAL/HIGH findings unless the config policy
(`allow_critical`, `allow_high`) allows them.

## What works today

- Modules: SSH, firewall, fail2ban, system updates, file permissions, kernel (sysctl), services/ports,
  accounts, Docker, time synchronization and time zone.
- Professional hardening, step by step: a dedicated key-only administrator (`admin-user`), then switch off
  root login and passwords, move SSH to another port in two safe phases (the old port stays until you log in
  through the new one), fail2ban on the right ports, ufw with default deny and a live-confirmation safety net.
- On a bare server `reviveguard fix` can, **after asking you each time**: refresh the apt index,
  apply *security-only* updates, enable automatic security updates, install `ufw` (left disabled),
  install `fail2ban` (your current SSH client address is whitelisted), tighten file permissions,
  apply safe sysctl values and fix SSH settings. Package operations are recorded in the history but
  **cannot be rolled back**; ReviveGuard never removes packages, reboots, or restarts services.

- `reviveguard audit` — read-only; never modifies the system.
- SSH checks `SSH-001`..`SSH-005`: root login, password authentication, empty passwords,
  public key authentication, `sshd_config` ownership/permissions.
- Firewall checks `FW-001`..`FW-004` (UFW, nftables, iptables, firewalld) — findings only;
  firewall changes are always manual. Fail2ban checks `F2B-001`..`F2B-005`; the missing SSH jail
  (`F2B-002`) can be enabled by `fix`. Both modules need root to read their state.
- `reviveguard fix [--category ssh|updates|permissions|sysctl|firewall|fail2ban] [--check SSH-002]` — interactive fixes for the SSH findings
  (needs root). Every fix is explained, backed up, confirmed by you, validated, verified and
  recorded; failures restore the original files automatically.
- `reviveguard history` / `reviveguard rollback [--id FIX-YYYY-NNN] [--yes]` — backup store and
  rollback engine (used by future fixes; covered by tests, but no fix creates operations yet).
- Output in English and Russian (`--lang en|ru`), plain text or JSON.

## Not implemented yet

2FA for SSH, auditd and a password-quality policy (planned). See the roadmap below.

## Requirements and tested platforms

- Python 3.10+ (Ubuntu 22.04 system Python is fine). Standard library only; `tomli` is pulled in
  automatically on 3.10.
- Target: Debian 12+, Ubuntu 22.04+. Development and tests so far ran on Ubuntu 24.04 only;
  no other OS has been verified yet.

## Install and run

One command on a Debian/Ubuntu server (as root). The script lists what it will do, asks for
confirmation, installs only missing prerequisites (`python3`, `python3-venv`, `ca-certificates`)
into the system and ReviveGuard into its own virtualenv, then runs a read-only audit:

```bash
curl -fsSLO https://raw.githubusercontent.com/JerryWenz/ReviveGuard/main/install.sh
sudo bash install.sh
```

(No `curl`? `apt-get update && apt-get install -y curl`. The ref in the URL and the script
changes to a release tag once there is one.) Or manually:

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

Choose the language with `reviveguard language`, or `reviveguard config set language ru`
(the installer asks, too). See all settings with `reviveguard config show`.

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

Three independent layers protect against lockout when access is narrowed (root login, passwords,
algorithms, port):

1. **Proof from the SSH log** that *your current session* logged in with a public key. A key in
   `authorized_keys` proves nothing about what you hold; password or unknown logins are refused.
2. **Commit-confirm:** after applying, you must log in from a NEW terminal and type `ok` within 180 s,
   otherwise ReviveGuard restores the files and reloads SSH by itself (no terminal = reverted).
3. **Validation and rollback:** `sshd -t` before reload, automatic restore on any failure, and
   `reviveguard rollback` reloads the service after restoring.

Still keep a provider console (VNC/rescue) at hand on a first run.

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

- SSH, apt, ufw and permission fixes are covered by tests with a faked system only; they have
  **not** been run on a real server yet (sysctl and fail2ban were, once, on Ubuntu 22.04). See [docs/vps-testing.ru.md](docs/vps-testing.ru.md).
- Tests run on Python 3.10–3.13 (3.10–3.13 locally and in the CI matrix); the installer and `audit` were
  confirmed by the author on one real Ubuntu 22.04.5 server (read-only audit only).
- Firewall checks read the rule sets as-is; conflicts are only detected for ufw + firewalld.
  Without an active firewall the policy/rule checks are not reported.
-  Try them on a non-critical machine first.
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
