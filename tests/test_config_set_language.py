from __future__ import annotations

import pytest

from reviveguard import cli
from reviveguard.config import (
    Config,
    ConfigError,
    load_config,
    parse_config,
    save_config,
    set_value,
    to_toml,
    tomllib,
)


def test_roundtrip_defaults_and_language(tmp_path):
    cfg = set_value(Config(), "language", "ru")
    path = save_config(cfg, tmp_path / "etc/reviveguard/config.toml")
    assert load_config(path) == cfg and cfg.language == "ru"
    assert (path.stat().st_mode & 0o777) == 0o644


def test_to_toml_is_valid_and_complete():
    text = to_toml(Config(language="en"))
    assert 'language = "en"' in text and "[remediation]" in text
    assert "allow_critical = false" in text and "redact_secrets = true" in text


def test_serialised_config_parses_back_identically():
    cfg = set_value(set_value(Config(), "audit.docker", "false"), "language", "en")
    assert parse_config(tomllib.loads(to_toml(cfg))) == cfg


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("audit.ssh", "maybe"),
        ("nope", "1"),
        ("audit.nope", "true"),
        ("language", "xx"),
        ("report.redact_secrets", "false"),
    ],
)
def test_invalid_settings_rejected(key, value):
    with pytest.raises(ConfigError):
        set_value(Config(), key, value)


def test_set_dotted_bool():
    assert set_value(Config(), "audit.ssh", "false").audit.ssh is False


def test_save_to_unwritable_location_is_error(tmp_path):
    blocker = tmp_path / "f"
    blocker.write_text("x")
    with pytest.raises(ConfigError):
        save_config(Config(), blocker / "config.toml")


def run(args, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "default.toml")
    rc = cli.main(args)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_cli_config_set_show_and_language_is_used_next_run(capsys, monkeypatch, tmp_path):
    cfg = str(tmp_path / "c.toml")
    state = str(tmp_path / "state")
    rc, out, _ = run(
        ["--config", cfg, "config", "set", "language", "ru"], capsys, monkeypatch, tmp_path
    )
    assert rc == 0 and "Сохранено: language = ru" in out
    rc, out, _ = run(["--config", cfg, "config", "show"], capsys, monkeypatch, tmp_path)
    assert rc == 0 and 'language = "ru"' in out
    rc, out, _ = run(
        ["--config", cfg, "--state-dir", state, "history"], capsys, monkeypatch, tmp_path
    )
    assert "История исправлений пуста." in out


def test_cli_config_errors(capsys, monkeypatch, tmp_path):
    cfg = str(tmp_path / "c.toml")
    rc, _, err = run(
        ["--lang", "en", "--config", cfg, "config", "set", "audit.x", "1"],
        capsys,
        monkeypatch,
        tmp_path,
    )
    assert rc == 2 and "Invalid value for audit.x" in err
    rc, _, err = run(["--lang", "en", "config"], capsys, monkeypatch, tmp_path)
    assert rc == 2 and "Usage" in err
    blocker = tmp_path / "f"
    blocker.write_text("x")
    rc, _, err = run(
        ["--lang", "en", "--config", str(blocker / "c.toml"), "config", "set", "language", "en"],
        capsys,
        monkeypatch,
        tmp_path,
    )
    assert rc == 1 and "Cannot write the configuration" in err


def test_cli_language_menu(capsys, monkeypatch, tmp_path):
    cfg = tmp_path / "c.toml"
    base = ["--lang", "en", "--config", str(cfg), "language"]
    monkeypatch.setattr("builtins.input", lambda prompt="": "2")
    rc, out, _ = run(base, capsys, monkeypatch, tmp_path)
    assert rc == 0 and "1) en - English" in out and "2) ru - Русский" in out
    assert load_config(cfg).language == "ru"

    monkeypatch.setattr("builtins.input", lambda prompt="": "zz")
    rc, _, err = run(base, capsys, monkeypatch, tmp_path)
    assert rc == 1 and "Invalid choice" in err and load_config(cfg).language == "ru"

    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    rc, _, err = run(base, capsys, monkeypatch, tmp_path)
    assert rc == 1 and "No terminal" in err
