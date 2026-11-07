from __future__ import annotations

import json
from types import SimpleNamespace

from reviveguard.checks import docker
from reviveguard.fixes import AUTOMATIC, REGISTRY
from reviveguard.models import Severity, Status
from reviveguard.system import CommandResult

from .conftest import FakeRunner

CONTAINERS = [
    {
        "Name": "/web",
        "Config": {"User": "1000"},
        "HostConfig": {"Privileged": False, "NetworkMode": "bridge", "CapAdd": None, "Binds": None},
        "Mounts": [],
    },
    {
        "Name": "/agent",
        "Config": {"User": ""},
        "HostConfig": {
            "Privileged": True,
            "NetworkMode": "host",
            "CapAdd": ["sys_admin"],
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/data:/data"],
        },
        "Mounts": [{"Type": "bind", "Source": "/etc"}],
    },
]


def runner(containers=CONTAINERS, ps_ok=True):
    table = {
        ("docker", "--version"): CommandResult(("d",), 0, "Docker 26"),
        ("docker", "ps", "-q"): CommandResult(
            ("d",), 0 if ps_ok else 1, "aa\nbb\n" if containers else ""
        ),
        ("docker", "inspect", "aa", "bb"): CommandResult(("d",), 0, json.dumps(containers)),
    }
    return FakeRunner(table)


def by_id(results):
    return {r.check_id: r for r in results}


def test_not_installed_is_skipped(make_ctx):
    res = docker.run(make_ctx(runner=FakeRunner()))
    assert [r.check_id for r in res] == ["DOC-000"] and res[0].status is Status.SKIPPED


def test_container_findings(make_ctx):
    res = by_id(docker.run(make_ctx(runner=runner())))
    for check_id in ("DOC-004", "DOC-005", "DOC-006", "DOC-007", "DOC-008"):
        assert res[check_id].status is Status.FAIL, check_id
        assert (
            "agent" in res[check_id].evidence[0]
            and "web" not in res[check_id].evidence[0]
            or (check_id == "DOC-008")
        )
    assert res["DOC-004"].severity is Severity.HIGH and res["DOC-007"].severity is Severity.HIGH
    assert "web" not in res["DOC-004"].evidence[0]


def test_clean_containers(make_ctx):
    clean = [CONTAINERS[0]]
    clean[0] = {**CONTAINERS[0], "Config": {"User": "1000"}}
    r = runner(clean)
    r.responses[("docker", "inspect", "aa", "bb")] = CommandResult(("d",), 0, json.dumps(clean))
    res = by_id(docker.run(make_ctx(runner=r)))
    assert all(res[i].status is Status.OK for i in ("DOC-004", "DOC-005", "DOC-006", "DOC-007"))


def test_socket_permissions(make_ctx, fake_root):
    sock = fake_root / "var/run/docker.sock"
    sock.parent.mkdir(parents=True)
    sock.write_text("")
    bad = make_ctx(runner=runner([]), stat=lambda p: SimpleNamespace(st_mode=0o140666, st_uid=0))
    assert by_id(docker.run(bad))["DOC-001"].status is Status.FAIL
    good = make_ctx(runner=runner([]), stat=lambda p: SimpleNamespace(st_mode=0o140660, st_uid=0))
    assert by_id(docker.run(good))["DOC-001"].status is Status.OK


def test_docker_group_and_exposed_api(make_ctx, fake_root):
    (fake_root / "etc/group").write_text("docker:x:999:alice,bob\n")
    (fake_root / "etc/docker").mkdir(parents=True)
    (fake_root / "etc/docker/daemon.json").write_text(
        json.dumps({"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]})
    )
    res = by_id(docker.run(make_ctx(runner=runner([]))))
    assert res["DOC-002"].status is Status.FAIL and "alice, bob" in res["DOC-002"].evidence[0]
    assert res["DOC-003"].status is Status.FAIL and "2375" in res["DOC-003"].evidence[0]
    (fake_root / "etc/docker/daemon.json").write_text(
        json.dumps({"hosts": ["tcp://127.0.0.1:2375"]})
    )
    assert by_id(docker.run(make_ctx(runner=runner([]))))["DOC-003"].status is Status.OK


def test_broken_daemon_json_is_not_a_crash(make_ctx, fake_root):
    (fake_root / "etc/docker").mkdir(parents=True)
    (fake_root / "etc/docker/daemon.json").write_text("{not json")
    assert by_id(docker.run(make_ctx(runner=runner([]))))["DOC-003"].status is Status.OK


def test_needs_root_and_unreadable_daemon(make_ctx):
    res = docker.run(make_ctx(runner=runner(), root=False))
    assert res[-1].check_id == "DOC-000" and "DOC-004" not in {r.check_id for r in res}
    res = docker.run(make_ctx(runner=runner(ps_ok=False)))
    assert res[-1].status is Status.SKIPPED and "DOC-004" not in {r.check_id for r in res}


def test_read_only_and_manual_only(make_ctx):
    r = runner()
    docker.run(make_ctx(runner=r))
    allowed = {"--version", "ps", "inspect"}
    assert all(c[0] == "docker" and c[1] in allowed for c in r.calls)
    for i in range(1, 9):
        assert f"DOC-00{i}" in REGISTRY and f"DOC-00{i}" not in AUTOMATIC
