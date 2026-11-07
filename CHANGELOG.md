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

- Firewall checks `FW-001`..`FW-004` (UFW, nftables, iptables, firewalld): active, default
  incoming policy, dangerous rules (exposed database/admin ports, accept-all), ufw+firewalld conflict.
  Findings are **manual-only**: ReviveGuard never enables, changes or flushes firewall rules.
- Fail2ban checks `F2B-001`..`F2B-005`: running, configuration test, sshd jail, log source,
  ban settings. Automatic fix for `F2B-002` (drop-in enabling the sshd jail, `reload` not restart).
- Guide for testing on a real server (`docs/vps-testing.ru.md`).

- Update checks `UPD-001`..`UPD-005` and apt-based fixes (index refresh, security-only upgrades,
  unattended-upgrades, install ufw/fail2ban). Package operations are non-reversible and recorded.
- Permission checks `PERM-001`..`PERM-004` with a fix that only removes permission bits.
- Sysctl checks `SYS-001`..`SYS-008`; safe values applied via `/etc/sysctl.d/99-reviveguard.conf`;
  skipped in containers; forwarding judged in context (Docker/VPN).
- Services/ports checks `SVC-001`, `SVC-002` (findings only; services are never stopped).
- `install.sh`: one-command installer (confirmation, only missing prerequisites, own virtualenv).
- Python 3.10 support (Ubuntu 22.04 system Python).

- `reviveguard language` (interactive choice) and `reviveguard config set|show`
  (e.g. `config set language ru`); `install.sh` asks for the language (`--lang en|ru`).

### Changed
- `install.sh` no longer lets needrestart restart services (list-only mode).
- Check titles are neutral topic names (a green `[OK]` never reads like a problem).
- sshd configuration values keep their original case (user names and paths are case-sensitive).

### Not implemented yet
`fix --auto`, reports, the Docker module, and enabling a firewall (manual by design).
Fixes (SSH, fail2ban) have not been exercised against real services yet (see README).
