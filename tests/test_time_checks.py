from __future__ import annotations

import pytest

from reviveguard.backup import Store
from reviveguard.checks import timesync
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.models import Severity, Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import FakeRunner
from .test_updates import AptHost

SHOW_OK = "Timezone=Etc/UTC\nLocalRTC=no\nCanNTP=yes\nNTP=yes\nNTPSynchronized=yes\n"
SHOW_OFF = "Timezone=Europe/Moscow\nLocalRTC=no\nCanNTP=yes\nNTP=no\nNTPSynchronized=no\n"
SHOW_NO_SERVICE = "Timezone=UTC\nCanNTP=no\nNTP=no\nNTPSynchronized=no\n"
SHOW_WAITING = "Timezone=UTC\nCanNTP=yes\nNTP=yes\nNTPSynchronized=no\n"


class TimeHost(AptHost):
    """timedatectl whose state changes with `set-ntp true` / installing systemd-timesyncd."""

    def __init__(self, show, fail_set_ntp=False, **kw):
        super().__init__(**kw)
        self.show, self.fail_set_ntp = show, fail_set_ntp

    def __call__(self, args, timeout=None):
        if args == ["timedatectl", "show"]:
            self.calls.append(list(args))
            return CommandResult(tuple(args), 0, self.show)
        if args == ["timedatectl", "set-ntp", "true"]:
            self.calls.append(list(args))
            if self.fail_set_ntp:
                return CommandResult(tuple(args), 1, "", "Failed to set ntp: no service")
            self.show = self.show.replace("NTP=no", "NTP=yes").replace("CanNTP=no", "CanNTP=yes")
            return CommandResult(tuple(args), 0)
        return super().__call__(args, timeout)


def by_id(results):
    return {r.check_id: r for r in results}


def test_synchronized_utc_host_is_ok(make_ctx):
    res = by_id(timesync.run(make_ctx(runner=TimeHost(SHOW_OK))))
    assert res["TIME-001"].status is Status.OK and res["TIME-002"].status is Status.OK


def test_unsynchronized_clock_and_local_timezone(make_ctx):
    res = by_id(timesync.run(make_ctx(runner=TimeHost(SHOW_OFF))))
    assert res["TIME-001"].status is Status.FAIL and res["TIME-001"].severity is Severity.MEDIUM
    assert "enabled: no" in res["TIME-001"].evidence[0]
    assert res["TIME-002"].status is Status.FAIL and res["TIME-002"].severity is Severity.LOW
    assert "Europe/Moscow" in res["TIME-002"].evidence[0]


@pytest.mark.parametrize("zone", ["UTC", "Etc/UTC", "Universal", "Zulu"])
def test_all_utc_spellings_are_accepted(make_ctx, zone):
    show = SHOW_OK.replace("Etc/UTC", zone)
    assert by_id(timesync.run(make_ctx(runner=TimeHost(show))))["TIME-002"].status is Status.OK


def test_skipped_without_timedatectl_or_in_a_container(make_ctx):
    res = timesync.run(make_ctx(runner=FakeRunner()))
    assert [r.check_id for r in res] == ["TIME-000"] and res[0].status is Status.SKIPPED
    container = FakeRunner(
        {("systemd-detect-virt", "--container"): CommandResult(("x",), 0, "lxc\n")}
    )
    res = timesync.run(make_ctx(runner=container))
    assert res[0].description_key == "time.container"


def test_only_read_only_commands_run_during_audit(make_ctx):
    host = TimeHost(SHOW_OFF)
    timesync.run(make_ctx(runner=host))
    assert all(c[0] in ("timedatectl", "systemd-detect-virt") for c in host.calls)
    assert ["timedatectl", "set-ntp", "true"] not in host.calls


def failing(ctx, check_id):
    return next(r for r in timesync.run(ctx) if r.check_id == check_id)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


def test_fix_enables_ntp(make_ctx, store):
    host = TimeHost(SHOW_OFF)
    ctx = make_ctx(runner=host)
    spec = REGISTRY["TIME-001"](ctx, failing(ctx, "TIME-001"))
    assert isinstance(spec, FixSpec) and not spec.disruptive and "TIME-001" in AUTOMATIC
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied" and ["timedatectl", "set-ntp", "true"] in host.calls
    assert not any("timezone" in " ".join(c) for c in host.calls)  # zone is never touched


def test_fix_installs_timesyncd_on_a_bare_image(make_ctx, store):
    host = TimeHost(SHOW_NO_SERVICE)
    ctx = make_ctx(runner=host)
    spec = REGISTRY["TIME-001"](ctx, failing(ctx, "TIME-001"))
    assert spec.packages == ["systemd-timesyncd"]
    assert run_fix(store, ctx, spec).status == "applied"
    assert "systemd-timesyncd" in host.installed


def test_fix_failure_is_reported(make_ctx, store):
    host = TimeHost(SHOW_OFF, fail_set_ntp=True)
    ctx = make_ctx(runner=host)
    outcome = run_fix(store, ctx, REGISTRY["TIME-001"](ctx, failing(ctx, "TIME-001")))
    assert outcome.status == "apply_failed" and "no service" in outcome.detail


def test_enabled_but_unsynchronized_is_manual(make_ctx):
    ctx = make_ctx(runner=TimeHost(SHOW_WAITING))
    plan = REGISTRY["TIME-001"](ctx, failing(ctx, "TIME-001"))
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.ntp_waiting"


def test_missing_service_without_apt_is_manual(make_ctx):
    base = FakeRunner({("timedatectl", "show"): CommandResult(("t",), 0, SHOW_NO_SERVICE)})
    ctx = make_ctx(runner=base)
    from reviveguard.models import CheckResult

    result = CheckResult("TIME-001", "time", Severity.MEDIUM, Status.FAIL, "t", "d", "r")
    assert REGISTRY["TIME-001"](ctx, result).reason_key == "fix.reason.no_apt"


def test_timezone_is_manual_only(make_ctx):
    ctx = make_ctx(runner=TimeHost(SHOW_OFF))
    plan = REGISTRY["TIME-002"](ctx, failing(ctx, "TIME-002"))
    assert isinstance(plan, Manual) and plan.reason_key == "fix.reason.timezone_manual"
    assert "TIME-002" not in AUTOMATIC
