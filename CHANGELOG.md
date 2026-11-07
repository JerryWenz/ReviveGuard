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

### Not implemented yet
Remediation (`fix`), backup/rollback, reports, and all other check modules.
