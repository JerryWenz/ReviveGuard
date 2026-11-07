"""Configuration loading and validation (TOML, standard library only).

Safety-relevant defaults are conservative. Unknown keys and wrong types are
rejected instead of being silently ignored.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field, fields
from pathlib import Path

from reviveguard.i18n import available_languages

if sys.version_info >= (3, 11):
    import tomllib
else:  # Python 3.10 (Ubuntu 22.04 system Python)
    import tomli as tomllib

DEFAULT_CONFIG_PATH = Path("/etc/reviveguard/config.toml")
REPORT_FORMATS = ("markdown", "json")


class ConfigError(Exception):
    """Raised for unreadable or invalid configuration."""


@dataclass(frozen=True)
class AuditConfig:
    ssh: bool = True
    firewall: bool = True
    fail2ban: bool = True
    docker: bool = True
    updates: bool = True
    permissions: bool = True
    services: bool = True
    sysctl: bool = True
    accounts: bool = True

    def enabled_modules(self) -> list[str]:
        return [f.name for f in fields(self) if getattr(self, f.name)]


@dataclass(frozen=True)
class RemediationConfig:
    enabled: bool = True
    require_confirmation: bool = True
    allow_critical: bool = False
    allow_high: bool = False
    backup_before_change: bool = True
    verify_after_change: bool = True


@dataclass(frozen=True)
class ReportConfig:
    format: str = "markdown"
    redact_secrets: bool = True


@dataclass(frozen=True)
class Config:
    language: str | None = None  # None: detect from the environment
    audit: AuditConfig = field(default_factory=AuditConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)
    report: ReportConfig = field(default_factory=ReportConfig)


def _build_section(cls: type, name: str, raw: object):
    if not isinstance(raw, dict):
        raise ConfigError(f"[{name}] must be a table")
    allowed = {f.name: f for f in fields(cls)}
    defaults = cls()
    values = {}
    for key, value in raw.items():
        if key not in allowed:
            raise ConfigError(f"unknown key '{name}.{key}'")
        expected = type(getattr(defaults, key))
        if not isinstance(value, expected):
            raise ConfigError(f"'{name}.{key}' must be of type {expected.__name__}")
        values[key] = value
    section = cls(**values)
    if cls is ReportConfig and section.format not in REPORT_FORMATS:
        raise ConfigError(f"'report.format' must be one of {', '.join(REPORT_FORMATS)}")
    if cls is ReportConfig and not section.redact_secrets:
        raise ConfigError("'report.redact_secrets' cannot be disabled")
    return section


def parse_config(data: dict) -> Config:
    known = {"language", "audit", "remediation", "report"}
    for key in data:
        if key not in known:
            raise ConfigError(f"unknown key '{key}'")
    language = data.get("language")
    if language is not None:
        if not isinstance(language, str) or language not in available_languages():
            raise ConfigError(f"'language' must be one of {', '.join(available_languages())}")
    return Config(
        language=language,
        audit=_build_section(AuditConfig, "audit", data.get("audit", {})),
        remediation=_build_section(RemediationConfig, "remediation", data.get("remediation", {})),
        report=_build_section(ReportConfig, "report", data.get("report", {})),
    )


def load_config(path: Path | None = None) -> Config:
    """Load configuration. A missing default file yields defaults; a missing
    explicitly requested file is an error."""
    explicit = path is not None
    target = path or DEFAULT_CONFIG_PATH
    try:
        raw = target.read_bytes()
    except FileNotFoundError:
        if explicit:
            raise ConfigError(f"configuration file not found: {target}") from None
        return Config()
    except OSError as exc:
        raise ConfigError(f"cannot read {target}: {exc.strerror}") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{target}: {exc}") from exc
    return parse_config(data)


def config_to_dict(config: Config) -> dict:
    data: dict = {}
    if config.language is not None:
        data["language"] = config.language
    for name in ("audit", "remediation", "report"):
        data[name] = {
            f.name: getattr(getattr(config, name), f.name) for f in fields(getattr(config, name))
        }
    return data


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return json.dumps(str(value), ensure_ascii=False)  # JSON string escapes are valid TOML


def to_toml(config: Config) -> str:
    data = config_to_dict(config)
    lines = ["# ReviveGuard configuration. Edit by hand or use 'reviveguard config set'."]
    if "language" in data:
        lines.append(f"language = {_toml_value(data.pop('language'))}")
    for section, values in data.items():
        lines += ["", f"[{section}]"] + [f"{k} = {_toml_value(v)}" for k, v in values.items()]
    return "\n".join(lines) + "\n"


def set_value(config: Config, key: str, raw: str) -> Config:
    """Return a new Config with ``key`` (e.g. ``language`` or ``audit.ssh``) set from text."""
    data = config_to_dict(config)
    target, _, leaf = key.rpartition(".")
    table = data.get(target) if target else data
    if not isinstance(table, dict) or (
        leaf not in table and not (not target and leaf == "language")
    ):
        raise ConfigError(f"unknown setting: {key}")
    current = table.get(leaf)
    if isinstance(current, bool):
        if raw.lower() not in ("true", "false"):
            raise ConfigError(f"{key} must be true or false")
        value: object = raw.lower() == "true"
    else:
        value = raw
    table[leaf] = value
    return parse_config(data)  # full validation, including safety rules


def save_config(config: Config, path: Path | None = None) -> Path:
    target = path or DEFAULT_CONFIG_PATH
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".config-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(to_toml(config))
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except OSError as exc:
        raise ConfigError(exc.strerror or str(exc)) from exc
    return target
