from __future__ import annotations

import pytest

from reviveguard.config import Config, ConfigError, load_config


def test_missing_default_file_gives_safe_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    cfg = load_config()
    assert cfg == Config()
    assert cfg.remediation.allow_critical is False and cfg.remediation.allow_high is False
    assert cfg.remediation.backup_before_change is True


def test_missing_explicit_file_is_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "none.toml")


def test_valid_config(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('language = "ru"\n[audit]\nssh = false\n')
    cfg = load_config(p)
    assert cfg.language == "ru" and cfg.audit.ssh is False and cfg.audit.firewall is True
    assert "ssh" not in cfg.audit.enabled_modules()


@pytest.mark.parametrize(
    "text",
    [
        "language = 'xx'",
        "bogus = 1",
        "[audit]\nssh = 'yes'",
        "[audit]\nnope = true",
        "[report]\nformat = 'pdf'",
        "[report]\nredact_secrets = false",
        "this is not toml",
        "audit = 3",
    ],
)
def test_invalid_config_rejected(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text)
    with pytest.raises(ConfigError):
        load_config(p)


def test_unreadable_config_is_error(tmp_path):
    p = tmp_path / "c.toml"
    p.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ConfigError):
        load_config(p)
