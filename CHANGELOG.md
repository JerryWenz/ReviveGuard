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

### Not implemented yet
Remediation (`fix`) itself, reports, and all check modules except SSH. Backup and rollback are
in place but nothing creates operations yet, so `history` is empty on a fresh system.
