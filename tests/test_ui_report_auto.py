from __future__ import annotations

import io
import json
import re

import pytest

from reviveguard import cli, report, ui
from reviveguard.backup import Store
from reviveguard.config import AuditConfig, Config, RemediationConfig
from reviveguard.fixflow import auto_block_reason, split_items
from reviveguard.i18n import Translator
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.remediation import FixSpec
from reviveguard.scanner import run_audit

from .conftest import SSHD_MAIN, build_host, ssh_runner

ANSI = re.compile(r"\033\[[0-9;]*m")


# ---------------- ui ----------------


def test_logo_spells_revive_and_fits_80_columns():
    lines = ui.logo_lines()
    assert len(lines) == 5 and max(len(x) for x in lines) <= 80
    assert "_____" in lines[0] and "\\_/" in lines[4]


def test_no_color_on_pipe_or_dumb_terminal_or_flag():
    class Tty(io.StringIO):
        def isatty(self):
            return True

    assert not ui.detect(io.StringIO(), env={}).enabled  # a pipe
    assert ui.detect(Tty(), env={"TERM": "xterm"}).enabled
    assert not ui.detect(Tty(), env={"TERM": "dumb"}).enabled
    assert not ui.detect(Tty(), env={"NO_COLOR": "1", "TERM": "xterm"}).enabled
    assert not ui.detect(Tty(), no_color=True, env={"TERM": "xterm"}).enabled
    assert ui.detect(Tty(), no_color=True, env={}).fancy  # logo still shown on a TTY


def test_plain_style_never_emits_escape_codes():
    style = ui.Style()
    assert style.paint("x", "red") == "x" and style.markup("run 'reviveguard fix'") == (
        "run 'reviveguard fix'"
    )
    assert "\033" not in ui.banner(style, "tagline", "1.0")


def test_color_style_highlights_commands_and_severity():
    style = ui.Style(enabled=True, fancy=True)
    assert "\033[" in style.tag("HIGH") and ANSI.sub("", style.tag("HIGH")) == "[HIGH]"
    marked = style.markup("run 'reviveguard fix' now")
    assert ANSI.sub("", marked) == "run 'reviveguard fix' now" and "\033[36;1m" in marked
    banner = ui.banner(style, "Auditor", "1.0")
    assert "REVIVE"[0] and ANSI.sub("", banner).count("|") > 5 and "ReviveGuard" in banner


# ---------------- report ----------------


def test_redaction_masks_secrets():
    text = "password = hunter2 and token: abc123 and ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"
    text += "\n-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END OPENSSH PRIVATE KEY-----"
    out = report.redact(text)
    for leaked in ("hunter2", "abc123", "AAAAC3Nza", "SECRET"):
        assert leaked not in out
    assert "[REDACTED]" in out and "[REDACTED PRIVATE KEY]" in out


def make_report(make_ctx, fake_root, tmp_path):
    build_host(
        fake_root,
        {"alice": {"uid": 1000, "sudo": True, "key": True}},
        SSHD_MAIN + "PermitEmptyPasswords yes\n",
    )
    ctx = make_ctx(runner=ssh_runner(), env={"SUDO_USER": "alice"})
    audit = run_audit(
        ctx,
        Config(
            audit=AuditConfig(
                firewall=False,
                fail2ban=False,
                updates=False,
                permissions=False,
                services=False,
                sysctl=False,
            )
        ),
    )
    return ctx, audit


def test_report_contents_and_sorting(make_ctx, fake_root, tmp_path):
    ctx, audit = make_report(make_ctx, fake_root, tmp_path)
    t = Translator("en")
    data = report.build(t, ctx, audit, [], "en")
    assert (
        data["hostname"]
        and data["os"]["name"]
        and data["timestamp"]
        and data["reviveguard_version"]
    )
    assert data["findings"][0]["severity"] == "CRITICAL"  # most severe first
    assert data["outstanding_risks"][0] == "SSH-003"
    assert "score" not in json.dumps(data).lower().replace("no numeric score", "")
    md = report.render_markdown(t, data)
    assert "# Security report" in md and "SSH-003" in md and "numeric score" in md
    assert "none" in md  # no applied fixes yet


def test_report_lists_applied_fixes_with_verification(make_ctx, fake_root, tmp_path):
    from reviveguard.backup import begin_operation, mark_applied

    ctx, audit = make_report(make_ctx, fake_root, tmp_path)
    store = Store(tmp_path / "state")
    f = tmp_path / "x"
    f.write_text("a")
    op = begin_operation(store, "SSH-003", "ssh.x", "disable empty passwords", [f])
    mark_applied(store, op)
    data = report.build(Translator("ru"), ctx, audit, [store.load(op.op_id)], "ru")
    assert data["applied_fixes"][0]["verification"] == "passed"
    assert "Отчёт по безопасности" in report.render_markdown(Translator("ru"), data)


def test_report_command_json_stdout_and_file(make_ctx, fake_root, capsys, monkeypatch, tmp_path):
    ctx, _ = make_report(make_ctx, fake_root, tmp_path)
    monkeypatch.setattr("reviveguard.config.DEFAULT_CONFIG_PATH", tmp_path / "none.toml")
    base = ["--lang", "en", "--state-dir", str(tmp_path / "s")]
    assert cli.main([*base, "report", "--format", "json"], ctx=ctx) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["CRITICAL"] == 1
    out_file = tmp_path / "r.md"
    assert cli.main([*base, "report", "--output", str(out_file)], ctx=ctx) == 0
    assert "# Security report" in out_file.read_text()  # config default is markdown
    assert (out_file.stat().st_mode & 0o777) == 0o600
    bad = tmp_path / "nodir" / "r.md"
    assert cli.main([*base, "report", "--output", str(bad)], ctx=ctx) == 1


# ---------------- auto policy ----------------


def result(sev):
    return CheckResult("X-1", "x", sev, Status.FAIL, "t", "d", "r")


def spec(disruptive=False):
    return FixSpec("f", "X-1", "d", [], lambda: None, lambda: None, None, disruptive=disruptive)


@pytest.mark.parametrize(
    ("sev", "disruptive", "allow", "expected"),
    [
        (Severity.MEDIUM, False, {}, None),
        (Severity.LOW, False, {}, None),
        (Severity.MEDIUM, True, {}, "fix.auto.skip_disruptive"),
        (Severity.HIGH, False, {}, "fix.auto.skip_high"),
        (Severity.HIGH, False, {"allow_high": True}, None),
        (Severity.CRITICAL, False, {}, "fix.auto.skip_critical"),
        (Severity.CRITICAL, False, {"allow_critical": True}, None),
        (Severity.CRITICAL, True, {"allow_critical": True}, "fix.auto.skip_disruptive"),
    ],
)
def test_auto_policy(sev, disruptive, allow, expected):
    from reviveguard.fixflow import Item

    config = Config(remediation=RemediationConfig(**allow))
    assert auto_block_reason(config, Item(result(sev), spec(disruptive))) == expected


def test_split_puts_manual_findings_apart():
    from reviveguard.fixflow import Item
    from reviveguard.remediation import Manual

    items = [
        Item(result(Severity.LOW), spec()),
        Item(result(Severity.LOW), Manual("m")),
        Item(result(Severity.HIGH), spec()),
    ]
    eligible, decide, manual = split_items(Config(), items)
    assert (len(eligible), len(decide), len(manual)) == (1, 1, 1)
