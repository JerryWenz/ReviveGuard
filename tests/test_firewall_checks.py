from __future__ import annotations

from reviveguard.checks import firewall
from reviveguard.models import Severity, Status
from reviveguard.system import CommandResult

from .conftest import FakeRunner

UFW_ACTIVE = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""
UFW_OPEN_DB = UFW_ACTIVE + "3306/tcp                   ALLOW IN    Anywhere\n"
UFW_ALLOW_ALL = UFW_ACTIVE.replace("22/tcp  ", "Anywhere", 1)
UFW_DEFAULT_ALLOW = UFW_ACTIVE.replace("deny (incoming)", "allow (incoming)")
NFT_DROP = """table inet filter {
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept
\t\ttcp dport 22 accept
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t}
}
"""
NFT_OPEN = NFT_DROP.replace("policy drop", "policy accept").replace("tcp dport 22 accept", "accept")
IPT_DROP = "-P INPUT DROP\n-P FORWARD DROP\n-A INPUT -i lo -j ACCEPT\n"
IPT_EMPTY = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n"


def runner(**outputs):
    """outputs: ufw / nft / iptables / firewalld stdout; absent key = tool missing."""
    table = {}
    cmds = {
        "ufw": ("ufw", "status", "verbose"),
        "nft": ("nft", "list", "ruleset"),
        "iptables": ("iptables", "-S"),
    }
    for name, args in cmds.items():
        if name in outputs:
            table[args] = CommandResult(args, 0, outputs[name])
    fw = ("systemctl", "is-active", "firewalld")
    table[fw] = CommandResult(
        fw, 0 if outputs.get("firewalld") else 3, outputs.get("firewalld", "inactive")
    )
    return FakeRunner(table)


def by_id(results):
    return {r.check_id: r for r in results}


def test_non_root_is_skipped(make_ctx):
    res = firewall.run(make_ctx(root=False))
    assert [r.status for r in res] == [Status.SKIPPED] and res[0].check_id == "FW-000"


def test_no_firewall_tool_is_a_finding(make_ctx):
    res = firewall.run(make_ctx(runner=runner()))
    assert [(r.check_id, r.status) for r in res] == [("FW-001", Status.FAIL)]


def test_tools_present_but_unreadable_is_skipped(make_ctx):
    table = {("ufw", "status", "verbose"): CommandResult(("ufw",), 1, "", "ERROR: need root")}
    table[("systemctl", "is-active", "firewalld")] = CommandResult(("x",), 3, "inactive")
    res = firewall.run(make_ctx(runner=FakeRunner(table)))
    assert [r.status for r in res] == [Status.SKIPPED]


def test_ufw_active_default_deny_ok(make_ctx):
    res = by_id(firewall.run(make_ctx(runner=runner(ufw=UFW_ACTIVE))))
    assert all(r.status is Status.OK for r in res.values())
    assert set(res) == {"FW-001", "FW-002", "FW-003", "FW-004"}


def test_ufw_inactive(make_ctx):
    res = by_id(firewall.run(make_ctx(runner=runner(ufw="Status: inactive\n"))))
    assert res["FW-001"].status is Status.FAIL and "FW-002" not in res


def test_ufw_default_allow_flagged(make_ctx):
    res = by_id(firewall.run(make_ctx(runner=runner(ufw=UFW_DEFAULT_ALLOW))))
    assert res["FW-002"].status is Status.FAIL and "allow" in res["FW-002"].evidence[0]


def test_ufw_exposed_database_flagged_high(make_ctx):
    res = by_id(firewall.run(make_ctx(runner=runner(ufw=UFW_OPEN_DB))))
    assert res["FW-003"].status is Status.FAIL and res["FW-003"].severity is Severity.HIGH
    assert "MySQL" in res["FW-003"].evidence[0]


def test_ssh_rule_is_not_dangerous():
    state = firewall.FirewallState()
    firewall.parse_ufw(UFW_ACTIVE, state)
    assert firewall.dangerous_rules(state) == []


def test_ufw_allow_all_ports_flagged():
    state = firewall.FirewallState()
    firewall.parse_ufw(UFW_ALLOW_ALL, state)
    assert any("all ports" in r for r in firewall.dangerous_rules(state))


def test_nft_policy_drop_ok_and_open_flagged(make_ctx):
    ok = by_id(firewall.run(make_ctx(runner=runner(nft=NFT_DROP))))
    assert ok["FW-001"].status is Status.OK and ok["FW-002"].status is Status.OK
    assert ok["FW-003"].status is Status.OK
    bad = by_id(firewall.run(make_ctx(runner=runner(nft=NFT_OPEN))))
    assert bad["FW-002"].status is Status.FAIL and bad["FW-003"].status is Status.FAIL


def test_iptables_policy_drop_and_empty(make_ctx):
    ok = by_id(firewall.run(make_ctx(runner=runner(iptables=IPT_DROP))))
    assert ok["FW-001"].status is Status.OK and ok["FW-002"].status is Status.OK
    empty = by_id(firewall.run(make_ctx(runner=runner(iptables=IPT_EMPTY))))
    assert empty["FW-001"].status is Status.FAIL


def test_iptables_unconditional_accept_flagged(make_ctx):
    out = "-P INPUT DROP\n-A INPUT -j ACCEPT\n"
    res = by_id(firewall.run(make_ctx(runner=runner(iptables=out))))
    assert res["FW-003"].status is Status.FAIL


def test_iptables_final_drop_counts_as_default_deny():
    state = firewall.FirewallState()
    firewall.parse_iptables(
        "-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP\n", state
    )
    assert firewall.default_deny(state) is True


def test_ufw_plus_firewalld_conflict(make_ctx):
    res = by_id(firewall.run(make_ctx(runner=runner(ufw=UFW_ACTIVE, firewalld="active\n"))))
    assert res["FW-004"].status is Status.FAIL


def test_firewalld_only_policy_unknown(make_ctx):
    res = by_id(firewall.run(make_ctx(runner=runner(firewalld="active\n", iptables=IPT_EMPTY))))
    assert res["FW-001"].status is Status.OK and res["FW-002"].status is Status.SKIPPED


def test_only_read_only_commands_run(make_ctx):
    r = runner(ufw=UFW_ACTIVE, nft=NFT_DROP, iptables=IPT_DROP)
    firewall.run(make_ctx(runner=r))
    allowed = {
        ("ufw", "status", "verbose"),
        ("nft", "list", "ruleset"),
        ("iptables", "-S"),
        ("systemctl", "is-active", "firewalld"),
    }
    assert {tuple(c) for c in r.calls} <= allowed
