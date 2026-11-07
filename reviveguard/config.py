"""Configuration loading and validation (TOML, standard library only).

Safety-relevant defaults are conservative. Unknown keys and wrong types are
rejected instead of being silently ignored.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

from reviveguard.i18n import available_languages

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
