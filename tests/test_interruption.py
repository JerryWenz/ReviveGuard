"""An interruption in ANY phase must restore the original files (SSH session dropped, Ctrl+C)."""

from __future__ import annotations

import os
import signal

import pytest

from reviveguard.backup import Store
from reviveguard.fixflow import Console, Item, apply_item, guard_signals
from reviveguard.i18n import Translator
from reviveguard.remediation import FixSpec, run_fix
from reviveguard.ui import Style


@pytest.fixture
def setup(tmp_path, make_ctx):
    target = tmp_path / "conf"
    target.write_text("original\n")

    def spec(**kw):
        def apply():
            target.write_text("changed\n")

        base = dict(
            fix_id="t.fix",
            check_id="X-1",
            description="test",
            files=[target],
            apply=apply,
            validate=lambda: None,
            activate=None,
            verify=lambda: None,
        )
        base.update(kw)
        return FixSpec(**base)

    return target, spec, Store(tmp_path / "state"), make_ctx()


def interrupt():
    raise KeyboardInterrupt


@pytest.mark.parametrize("phase", ["validate", "activate", "verify"])
def test_interrupt_in_a_later_phase_restores_files_and_propagates(setup, phase):
    target, spec, store, ctx = setup
    kw = {phase: interrupt}
    with pytest.raises(KeyboardInterrupt):
        run_fix(store, ctx, spec(**kw))
    assert target.read_text() == "original\n"
    ops, _ = store.list_operations()
    assert ops[0].status == "rolled_back"


def test_interrupt_while_waiting_for_confirmation_reverts(setup):
    target, spec, store, ctx = setup
    with pytest.raises(KeyboardInterrupt):
        run_fix(store, ctx, spec(confirm_key="fix.confirm.ssh"), confirm=lambda s: interrupt())
    assert target.read_text() == "original\n"


@pytest.mark.parametrize(
    ("phase", "status"),
    [
        ("validate", "validation_failed"),
        ("verify", "verify_failed"),
        ("activate", "activation_failed"),
    ],
)
def test_unexpected_errors_in_any_phase_revert_instead_of_crashing(setup, phase, status):
    target, spec, store, ctx = setup

    def boom(*a):
        raise OSError(5, "I/O error")

    outcome = run_fix(store, ctx, spec(**{phase: boom}))
    assert outcome.status == status and outcome.reverted and outcome.revert_ok
    assert target.read_text() == "original\n" and "I/O error" in outcome.detail


@pytest.mark.parametrize("sig", [signal.SIGHUP, signal.SIGTERM])
def test_dropped_ssh_session_signal_reverts_the_change(setup, sig, capsys):
    target, spec, store, ctx = setup
    previous = signal.getsignal(sig)

    def apply():
        target.write_text("half applied\n")
        os.kill(os.getpid(), sig)  # what sshd does to the process when the session dies

    con = Console(Translator("en"), Style())
    with pytest.raises(KeyboardInterrupt):
        apply_item(con, store, ctx, Item(_result(), spec(apply=apply)))
    assert target.read_text() == "original\n"
    assert signal.getsignal(sig) == previous  # the handler is removed again


def test_guard_signals_restores_handlers():
    before = (signal.getsignal(signal.SIGHUP), signal.getsignal(signal.SIGTERM))
    with guard_signals():
        assert signal.getsignal(signal.SIGHUP) != before[0]
    assert (signal.getsignal(signal.SIGHUP), signal.getsignal(signal.SIGTERM)) == before


def _result():
    from reviveguard.models import CheckResult, Severity, Status

    return CheckResult("X-1", "x", Severity.LOW, Status.FAIL, "t", "d", "r")
