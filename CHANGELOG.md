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

- REVIVE logo, colors and command highlighting (TTY only, `--no-color`/`NO_COLOR`).
- `reviveguard wizard`: guided scan -> one-confirmation safe fixes -> separate decisions -> final scan
  and saved report.
- `reviveguard fix --auto [--yes]`: reviewed set, one confirmation, policy for CRITICAL/HIGH,
  disruptive fixes excluded, stops at the first failure.
- `reviveguard report [--format markdown|json] [--output FILE]`: findings by severity, applied fixes with
  verification, outstanding risks, secrets redacted, deliberately no numeric score.

- SSH hardening `SSH-006`..`SSH-009` (X11, MaxAuthTries, LoginGraceTime, weak algorithms) and a
  two-phase SSH port change `SSH-010`/`SSH-011` (new port added while 22 stays; 22 closed only after a
  login through the new port; refuses with socket activation, `Port` in sshd_config, or a blocking firewall).
- Accounts `USR-001`..`USR-003` and `reviveguard admin-user` (key-only sudo administrator, strict key validation,
  sudoers validated with `visudo -cf`); the wizard offers it and tells you how to continue after a test login.
- Safe ufw enable (`FW-001` when ufw is installed but off): default deny, keeps every currently reachable service,
  blocks risky exposed ports, and needs a live confirmation within 120 s or switches the firewall off again.
- Docker checks `DOC-001`..`DOC-008` (socket, docker group, exposed API, privileged/host-network/capabilities/
  sensitive mounts/root containers). Findings only.

### Security
- Disabling password login or root login now requires proof from the SSH log that the *current* session
  authenticated with a public key (`publickey`). A key in `authorized_keys` proves nothing about what the
  administrator holds: found when `wizard` disabled passwords for a root session that had logged in with a
  password. Unknown or password logins are refused (manual).
- The wizard no longer continues to the access-narrowing steps after the administrator account failed.

- Every SSH change that can narrow access (root login, passwords, algorithms, port) now uses commit-confirm:
  the change stays only if you type `ok` after logging in from a NEW terminal within 180 s; otherwise the files
  are restored and SSH is reloaded automatically (no terminal = reverted).

### Changed
- `reviveguard rollback` reloads the service the operation touched (ssh/fail2ban, after validating sshd) so restored files
  take effect.
- The administrator's public key is optional at creation; `reviveguard add-key --name NAME` adds it later.
- Fail2ban setup now works on bare images (found on a real Ubuntu 22.04 server): journald backend
  (`python3-systemd`) when there is no `/var/log/auth.log`, `iptables` + matching `banaction` when no
  firewall tool exists, and an installed-but-stopped fail2ban is started. The CLI states that
  installed packages stay after a reverted fix.
- `install.sh` re-runs now really update an existing install (`--force-reinstall --no-cache-dir`);
  pip kept the old code when the version number was unchanged. Version bumped to 0.1.0.dev1.
- `install.sh` no longer lets needrestart restart services (list-only mode).
- Check titles are neutral topic names (a green `[OK]` never reads like a problem).
- sshd configuration values keep their original case (user names and paths are case-sensitive).

### Not implemented yet
`fix --auto`, reports, the Docker module, and enabling a firewall (manual by design).
Fixes (SSH, fail2ban) have not been exercised against real services yet (see README).
