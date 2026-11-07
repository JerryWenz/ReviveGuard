from __future__ import annotations

import os
import time

import pytest

from reviveguard import packages
from reviveguard.backup import Store
from reviveguard.checks import updates
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.fixes import updates as fixes
from reviveguard.models import Severity, Status
from reviveguard.remediation import FixSpec, Manual, run_fix
from reviveguard.system import CommandResult

from .conftest import FakeRunner

UPGRADABLE = """Listing...
openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.19 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
libc6/jammy-updates,jammy-security 2.35-0ubuntu3.9 amd64 [upgradable from: 2.35-0ubuntu3.8]
vim/jammy-updates 2:8.2.3995-1ubuntu2.20 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.18]
"""


def cr(args, out="", rc=0, err=""):
    return tuple(args), CommandResult(tuple(args), rc, out, err)


class AptHost:
    """Fake apt: records calls; upgrading clears the upgradable list."""

    def __init__(self, upgradable=UPGRADABLE, fail_on=None, installed=()):
        self.upgradable, self.fail_on, self.installed = upgradable, fail_on, set(installed)
        self.calls: list[list[str]] = []
        self.timeouts: list[float | None] = []
        self.periodic = ""

    def __call__(self, args, timeout=None):
        self.calls.append(list(args))
        self.timeouts.append(timeout)
        out = lambda s="", rc=0, err="": CommandResult(tuple(args), rc, s, err)  # noqa: E731
        if args[0] == "apt-get" and "--version" in args:
            return out("apt 2.4")
        if args[:2] == ["apt", "list"]:
            return out(self.upgradable)
        if args[:2] == ["apt-config", "dump"]:
            return out(self.periodic)
        if args[0] == "dpkg-query":
            ok = args[-1] in self.installed
            return out("install ok installed" if ok else "", 0 if ok else 1)
        if args[0] == "env" and "apt-get" in args:
            if self.fail_on and self.fail_on in args:
                return out("", 100, "E: Unable to locate package")
            if "--only-upgrade" in args:
                self.upgradable = "Listing...\n"
            if "install" in args and "--only-upgrade" not in args:
                self.installed |= {a for a in args if a in packages.INSTALLABLE}
            return out()
        return CommandResult(tuple(args), None, missing=True)


def set_index_age(fake_root, days):
    lists = fake_root / "var/lib/apt/lists"
    lists.mkdir(parents=True, exist_ok=True)
    f = lists / "archive.ubuntu.com_Packages"
    f.write_text("x")
    t = time.time() - days * 86400
    os.utime(f, (t, t))


def by_id(results):
    return {r.check_id: r for r in results}


def test_parse_separates_security_from_ordinary():
    security, other = updates.parse_upgradable(UPGRADABLE)
    assert security == ["openssl", "libc6"] and other == ["vim"]


def test_parse_rejects_hostile_package_names():
    security, _ = updates.parse_upgradable(
        "evil;rm -rf/jammy-security 1 amd64\n-x/jammy-security 1\n"
    )
    assert security == []


def test_no_apt_is_skipped(make_ctx):
    res = by_id(updates.run(make_ctx(runner=FakeRunner())))
    assert res["UPD-000"].status is Status.SKIPPED and "UPD-001" not in res


def test_never_downloaded_index_fails_and_hides_update_judgement(make_ctx):
    res = by_id(updates.run(make_ctx(runner=AptHost())))
    assert res["UPD-001"].status is Status.FAIL and "never" in res["UPD-001"].evidence[0]
    assert res["UPD-002"].status is Status.SKIPPED  # stale index: cannot judge


def test_old_index_fails(make_ctx, fake_root):
    set_index_age(fake_root, 30)
    assert by_id(updates.run(make_ctx(runner=AptHost())))["UPD-001"].status is Status.FAIL


def test_fresh_index_with_security_updates(make_ctx, fake_root):
    set_index_age(fake_root, 0.1)
    res = by_id(updates.run(make_ctx(runner=AptHost())))
    assert res["UPD-001"].status is Status.OK
    r = res["UPD-002"]
    assert r.status is Status.FAIL and r.severity is Severity.HIGH
    assert "security updates: 2" in r.evidence[0] and "other updates: 1" in r.evidence[1]


def test_only_ordinary_updates_are_not_a_finding(make_ctx, fake_root):
    set_index_age(fake_root, 0.1)
    host = AptHost(upgradable="Listing...\nvim/jammy-updates 1 amd64 [upgradable from: 0]\n")
    assert by_id(updates.run(make_ctx(runner=host)))["UPD-002"].status is Status.OK


def test_reboot_required(make_ctx, fake_root):
    (fake_root / "var/run").mkdir(parents=True)
    (fake_root / "var/run/reboot-required").write_text("*** System restart required ***")
    (fake_root / "var/run/reboot-required.pkgs").write_text("linux-image-5.15\n")
    r = by_id(updates.run(make_ctx(runner=AptHost())))["UPD-003"]
    assert r.status is Status.FAIL and r.reboot_required and "linux-image" in r.evidence[0]


def test_auto_updates_need_package_and_config(make_ctx):
    host = AptHost()
    assert by_id(updates.run(make_ctx(runner=host)))["UPD-004"].status is Status.FAIL
    host.installed, host.periodic = (
        {"unattended-upgrades"},
        'APT::Periodic::Unattended-Upgrade "1";\n',
    )
    assert by_id(updates.run(make_ctx(runner=host)))["UPD-004"].status is Status.OK


def test_os_support_finding(make_ctx):
    from reviveguard.system import OsInfo

    ctx = make_ctx(runner=AptHost())
    ctx.os_info = OsInfo("debian", "11", "Debian 11")
    assert by_id(updates.run(ctx))["UPD-005"].status is Status.FAIL


def test_checks_only_run_read_only_commands(make_ctx, fake_root):
    set_index_age(fake_root, 0.1)
    host = AptHost()
    updates.run(make_ctx(runner=host))
    assert all(c[0] != "env" for c in host.calls)  # no apt-get install/update during audit


# ---------- fixes ----------


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "state")


def failing(ctx, check_id):
    return next(r for r in updates.run(ctx) if r.check_id == check_id and r.status is Status.FAIL)


def test_refresh_index_fix(make_ctx, store):
    host = AptHost()
    ctx = make_ctx(runner=host)
    spec = REGISTRY["UPD-001"](ctx, failing(ctx, "UPD-001"))
    assert isinstance(spec, FixSpec) and not spec.reversible
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied"
    update_call = next(c for c in host.calls if "update" in c and c[0] == "env")
    assert "DEBIAN_FRONTEND=noninteractive" in update_call and "NEEDRESTART_MODE=l" in update_call
    assert max(t for t in host.timeouts if t) >= 600  # long-running operations get a long timeout
    op = store.load(outcome.op_id)
    assert op.reversible is False and op.files == []


def test_security_updates_fix_only_upgrades_listed_security_packages(make_ctx, fake_root, store):
    set_index_age(fake_root, 0.1)
    host = AptHost()
    ctx = make_ctx(runner=host)
    spec = REGISTRY["UPD-002"](ctx, failing(ctx, "UPD-002"))
    assert isinstance(spec, FixSpec) and spec.disruptive and not spec.reversible
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied"
    call = next(c for c in host.calls if "--only-upgrade" in c)
    assert call[-2:] == ["openssl", "libc6"] and "vim" not in call
    assert not any("dist-upgrade" in c or "upgrade" in c[:4] for c in host.calls if c[0] == "env")
    assert not any("remove" in c or "purge" in c for c in host.calls)


def test_security_updates_fix_failure_is_recorded_not_rolled_back(make_ctx, fake_root, store):
    set_index_age(fake_root, 0.1)
    host = AptHost(fail_on="--only-upgrade")
    ctx = make_ctx(runner=host)
    outcome = run_fix(store, ctx, REGISTRY["UPD-002"](ctx, failing(ctx, "UPD-002")))
    assert outcome.status == "apply_failed" and not outcome.reverted
    assert store.load(outcome.op_id).status == "failed"
    from reviveguard import rollback

    plan = rollback.plan_rollback(store, outcome.op_id)
    assert plan.problems[0][0] == "rollback.err.not_reversible"


def test_security_fix_manual_without_apt_or_updates(make_ctx, fake_root):
    set_index_age(fake_root, 0.1)
    ctx = make_ctx(runner=AptHost())
    result = failing(ctx, "UPD-002")
    ctx2 = make_ctx(runner=AptHost(upgradable="Listing...\n"))
    assert REGISTRY["UPD-002"](ctx2, result).reason_key == "fix.reason.nothing_to_upgrade"
    assert REGISTRY["UPD-002"](make_ctx(runner=FakeRunner()), result).reason_key == (
        "fix.reason.no_apt"
    )


def test_auto_updates_fix_installs_and_writes_config(make_ctx, fake_root, store):
    (fake_root / "etc/apt/apt.conf.d").mkdir(parents=True)
    host = AptHost()
    ctx = make_ctx(runner=host)
    spec = REGISTRY["UPD-004"](ctx, failing(ctx, "UPD-004"))

    def enable():  # the written config is what apt-config would report afterwards
        host.periodic = 'APT::Periodic::Unattended-Upgrade "1";\n'

    original_apply = spec.apply
    spec.apply = lambda: (original_apply(), enable())
    outcome = run_fix(store, ctx, spec)
    assert outcome.status == "applied"
    cfg = fake_root / "etc/apt/apt.conf.d/20auto-upgrades"
    assert 'Unattended-Upgrade "1"' in cfg.read_text()
    assert "unattended-upgrades" in host.installed


def test_install_is_limited_to_allow_list(make_ctx):
    ctx = make_ctx(runner=AptHost())
    assert "not allowed" in packages.install(ctx, ["telnetd"])
    assert packages.upgrade_only(ctx, ["bad name; rm"]) == "invalid package list"
    assert packages.upgrade_only(ctx, []) == "invalid package list"


def test_manual_only_findings(make_ctx):
    for check_id, reason in (
        ("UPD-003", "fix.reason.reboot_manual"),
        ("UPD-005", "fix.reason.os_manual"),
    ):
        plan = REGISTRY[check_id](make_ctx(), None)
        assert isinstance(plan, Manual) and plan.reason_key == reason
        assert check_id not in AUTOMATIC
    assert {"UPD-001", "UPD-002", "UPD-004"} <= AUTOMATIC
    assert fixes.AUTO_UPGRADES.endswith("20auto-upgrades")
