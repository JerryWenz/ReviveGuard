# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/); versions below 1.0.0 may change
interfaces between minor releases.

## [Unreleased]

### Added
- Project foundation: package layout, `pyproject.toml`, CI (ruff + pytest).
- Read-only audit engine with a common `CheckResult` model and per-check error isolation.
- SSH checks `SSH-001`..`SSH-005` (root login, password auth, empty passwords,
  pubkey auth, `sshd_config` permissions), using `sshd -T` with a file-parsing fallback.
- Localization (ru/en) with English fallback.
- TOML configuration with strict validation.
- `reviveguard audit [--format text|json]`.

- Backup store and operation history (`/var/lib/reviveguard`), checksummed backups preserving
  mode and ownership, atomic history records written before any change.
- `reviveguard history` and `reviveguard rollback [--id ID] [--yes]` with plan preview,
  backup validation, confirmation and post-restore verification.
- Verification helpers (re-run a check, verify restored files).

- `reviveguard fix [--category C] [--check ID]`: interactive remediation for `SSH-001`..`SSH-005`
  (explain, show change and files, back up, confirm, apply, `sshd -t`, reload, verify, record).
  Any failure after the change started restores the original files automatically.
- SSH lockout prevention (`ssh_access.py`): fixes that could remove access are refused
  (manual remediation) unless a working alternative is verified.

### Changed
- sshd configuration values keep their original case (user names and paths are case-sensitive).

### Not implemented yet
`fix --auto`, reports, and all check modules except SSH. Fixes exist only for SSH and have
not been exercised against a real `sshd` yet (see README, Known limitations).
