from __future__ import annotations

from reviveguard import checks
from reviveguard.config import AuditConfig, Config
from reviveguard.models import CheckResult, Severity, Status
from reviveguard.scanner import run_audit


def ok_result():
    return CheckResult("X-1", "ssh", Severity.INFO, Status.OK, "t", "d", "r")


def test_broken_check_is_isolated(make_ctx, monkeypatch):
    def boom(ctx):
        raise RuntimeError("secret detail must not leak into the message")

    monkeypatch.setitem(checks.REGISTRY, "ssh", boom)
    only_ssh = Config(
        audit=AuditConfig(
            firewall=False,
            fail2ban=False,
            updates=False,
            permissions=False,
            services=False,
            sysctl=False,
            accounts=False,
            docker=False,
        )
    )
    report = run_audit(make_ctx(), only_ssh)
    assert len(report.results) == 1
    assert report.results[0].status is Status.ERROR
    assert report.results[0].evidence == ("RuntimeError",)


def test_disabled_module_is_not_run(make_ctx, monkeypatch):
    called = []
    monkeypatch.setitem(checks.REGISTRY, "ssh", lambda ctx: called.append(1) or [])
    from reviveguard.config import AuditConfig

    run_audit(make_ctx(), Config(audit=AuditConfig(ssh=False)))
    assert called == []


def test_counts_only_failures(make_ctx, monkeypatch):
    fail = CheckResult("X-2", "ssh", Severity.HIGH, Status.FAIL, "t", "d", "r")
    monkeypatch.setitem(checks.REGISTRY, "ssh", lambda ctx: [ok_result(), fail])
    report = run_audit(make_ctx(), Config())
    counts = report.count_by_severity()
    assert counts[Severity.HIGH] == 1 and counts[Severity.INFO] == 0
