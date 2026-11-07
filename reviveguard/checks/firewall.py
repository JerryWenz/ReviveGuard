"""Firewall checks (read-only): UFW, nftables, iptables and firewalld detection.

Every supported tool is queried with read-only commands. Reading rule sets needs root,
so without root the module reports a single skipped result rather than guessing.
The module never suggests flushing or replacing rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from reviveguard.context import AuditContext
from reviveguard.models import CheckResult, Severity, Status

# Ports of data services and admin interfaces that should rarely be open to everyone.
SENSITIVE_PORTS = {
    "2375": "Docker API (unencrypted)",
    "2376": "Docker API",
    "3306": "MySQL/MariaDB",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "11211": "Memcached",
    "27017": "MongoDB",
    "5900": "VNC",
    "3389": "RDP",
}
DENY_POLICIES = {"deny", "reject", "drop"}
_UFW_DEFAULT = re.compile(r"Default:\s*(\w+)\s*\(incoming\)", re.I)
_NFT_CHAIN = re.compile(r"chain\s+\S+\s*\{")
_NFT_HOOK = re.compile(r"hook\s+input\b.*?policy\s+(\w+)", re.I)


@dataclass
class NftChain:
    policy: str
    rules: list[str] = field(default_factory=list)


@dataclass
class FirewallState:
    tools_present: set[str] = field(default_factory=set)
    tools_readable: set[str] = field(default_factory=set)
    ufw_active: bool = False
    ufw_default_in: str | None = None
    ufw_rules: list[tuple[str, str, str]] = field(default_factory=list)  # to, action, from
    nft_chains: list[NftChain] = field(default_factory=list)
    ipt_policy: str | None = None
    ipt_rules: list[str] = field(default_factory=list)
    firewalld_active: bool = False


def parse_ufw(text: str, state: FirewallState) -> None:
    state.ufw_active = bool(re.search(r"^Status:\s*active", text, re.I | re.M))
    match = _UFW_DEFAULT.search(text)
    state.ufw_default_in = match.group(1).lower() if match else None
    in_table = False
    for line in text.splitlines():
        if line.startswith("--"):
            in_table = True
            continue
        if in_table and line.strip():
            cols = re.split(r"\s{2,}", line.strip())
            if len(cols) >= 3:
                state.ufw_rules.append((cols[0], cols[1], cols[2]))


def parse_nft(text: str, state: FirewallState) -> None:
    current: NftChain | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if _NFT_CHAIN.match(line):
            current = None
            continue
        hook = _NFT_HOOK.search(line)
        if hook:
            current = NftChain(policy=hook.group(1).lower())
            state.nft_chains.append(current)
            continue
        if line == "}":
            current = None
        elif current is not None and line and not line.startswith("type "):
            current.rules.append(line)


def parse_iptables(text: str, state: FirewallState) -> None:
    for line in text.splitlines():
        parts = line.split()
        if line.startswith("-P INPUT") and len(parts) >= 3:
            state.ipt_policy = parts[2].lower()
        elif line.startswith("-A INPUT"):
            state.ipt_rules.append(line.strip())


def collect(ctx: AuditContext) -> FirewallState:
    state = FirewallState()
    for tool, args, parser in (
        ("ufw", ["ufw", "status", "verbose"], parse_ufw),
        ("nft", ["nft", "list", "ruleset"], parse_nft),
        ("iptables", ["iptables", "-S"], parse_iptables),
    ):
        proc = ctx.runner(args)
        if proc.missing:
            continue
        state.tools_present.add(tool)
        if proc.ok:
            state.tools_readable.add(tool)
            parser(proc.stdout, state)
    fwd = ctx.runner(["systemctl", "is-active", "firewalld"])
    state.firewalld_active = fwd.ok and fwd.stdout.strip() == "active"
    return state


def is_active(state: FirewallState) -> bool:
    return (
        state.ufw_active
        or state.firewalld_active
        or any(c.policy in DENY_POLICIES or c.rules for c in state.nft_chains)
        or state.ipt_policy in DENY_POLICIES
        or bool(state.ipt_rules)
    )


def default_deny(state: FirewallState) -> bool | None:
    """True/False when the incoming default policy is known, None when it is not."""
    if state.ufw_active and state.ufw_default_in:
        return state.ufw_default_in in DENY_POLICIES
    if any(c.policy in DENY_POLICIES for c in state.nft_chains):
        return True
    if state.ipt_policy in DENY_POLICIES:
        return True
    last = state.ipt_rules[-1].split() if state.ipt_rules else []
    if last in (["-A", "INPUT", "-j", "DROP"], ["-A", "INPUT", "-j", "REJECT"]):
        return True  # unconditional DROP/REJECT as the last INPUT rule
    for chain in state.nft_chains:
        if chain.rules and chain.rules[-1].replace("counter", "").strip() in ("drop", "reject"):
            return True
    if state.firewalld_active and not state.ufw_active:
        return None  # firewalld zones are not inspected; iptables/nft views may be empty
    if state.nft_chains or state.ipt_policy or state.ufw_active:
        return False
    return None


def dangerous_rules(state: FirewallState) -> list[str]:
    found = []
    for to, action, source in state.ufw_rules:
        port = to.split()[0].split("/")[0]
        if "ALLOW" in action.upper() and source.lower().startswith("anywhere"):
            if port in SENSITIVE_PORTS:
                found.append(f"ufw: {to} {action} {source} ({SENSITIVE_PORTS[port]})")
            elif to.lower().startswith("anywhere"):
                found.append(f"ufw: {to} {action} {source} (allows all ports)")
    for line in state.ipt_rules:
        if line.split() == ["-A", "INPUT", "-j", "ACCEPT"]:
            found.append("iptables: unconditional ACCEPT rule in INPUT")
    for chain in state.nft_chains:
        if any(r.replace("counter", "").strip() == "accept" for r in chain.rules):
            found.append("nftables: unconditional accept rule in an input chain")
    return found


def _result(
    check_id: str, name: str, severity: Severity, failed: bool, evidence: list[str]
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category="firewall",
        severity=severity if failed else Severity.INFO,
        status=Status.FAIL if failed else Status.OK,
        title_key=f"firewall.{name}.title",
        description_key=f"firewall.{name}.desc",
        remediation_key=f"firewall.{name}.fix",
        evidence=tuple(evidence),
    )


def _skipped(check_id: str, reason_key: str) -> list[CheckResult]:
    return [
        CheckResult(
            check_id=check_id,
            category="firewall",
            severity=Severity.INFO,
            status=Status.SKIPPED,
            title_key="firewall.module.title",
            description_key=reason_key,
            remediation_key="remediation.none",
        )
    ]


def run(ctx: AuditContext) -> list[CheckResult]:
    if not ctx.running_as_root:
        return _skipped("FW-000", "firewall.needs_root")
    state = collect(ctx)
    if not state.tools_present and not state.firewalld_active:
        return [
            _result("FW-001", "active", Severity.MEDIUM, True, ["no firewall tool found"]),
        ]
    if state.tools_present and not state.tools_readable and not state.firewalld_active:
        return _skipped("FW-000", "firewall.unreadable")

    active = is_active(state)
    tools = ", ".join(sorted(state.tools_readable)) or "firewalld"
    evidence = [f"readable tools: {tools}"]
    if state.ufw_active:
        evidence.append("ufw: active")
    if state.firewalld_active:
        evidence.append("firewalld: active")
    results = [_result("FW-001", "active", Severity.MEDIUM, not active, evidence)]
    conflict = state.ufw_active and state.firewalld_active
    results.append(
        _result(
            "FW-004",
            "conflict",
            Severity.MEDIUM,
            conflict,
            ["ufw and firewalld are both active"] if conflict else ["no conflicting managers"],
        )
    )
    if not active:
        return results  # policy and rule checks are meaningless without a firewall

    deny = default_deny(state)
    if deny is None:
        results.append(_skipped("FW-002", "firewall.policy_unknown")[0])
    else:
        shown = state.ufw_default_in or state.ipt_policy or "see rules"
        results.append(
            _result("FW-002", "default_policy", Severity.MEDIUM, not deny, [f"incoming: {shown}"])
        )
    bad = dangerous_rules(state)
    results.append(
        _result("FW-003", "dangerous_rules", Severity.HIGH, bool(bad), bad or ["none found"])
    )
    return results
