"""Every check/fix text key referenced by the code must exist in all catalogs."""

from __future__ import annotations

import json

import pytest

from reviveguard.checks import permissions, sysctl
from reviveguard.i18n import _DIR, available_languages

DYNAMIC = {
    "ssh": [
        "root_login",
        "password_auth",
        "empty_passwords",
        "pubkey_auth",
        "config_perms",
        "x11_forwarding",
        "max_auth_tries",
        "grace_time",
        "weak_algorithms",
        "default_port",
        "port_migration",
    ],
    "firewall": ["active", "default_policy", "dangerous_rules", "conflict"],
    "fail2ban": ["running", "config_valid", "ssh_jail", "log_backend", "ban_settings"],
    "updates": ["index_fresh", "security_updates", "reboot", "auto_updates", "os_supported"],
    "services": ["public", "risky"],
    "accounts": ["admin_user", "empty_password", "extra_root"],
    "permissions": [name for name, _, _ in permissions.GROUPS.values()],
    "sysctl": [p.name for p in sysctl.PARAMS],
}


@pytest.mark.parametrize("lang", available_languages())
def test_all_check_texts_exist(lang):
    catalog = json.loads((_DIR / f"{lang}.json").read_text(encoding="utf-8"))
    missing = [
        f"{cat}.{name}.{part}"
        for cat, names in DYNAMIC.items()
        for name in names
        for part in ("title", "desc", "fix")
        if f"{cat}.{name}.{part}" not in catalog
    ]
    assert not missing, missing
    for category in DYNAMIC:
        assert f"{category}.module.title" in catalog


@pytest.mark.parametrize("lang", available_languages())
def test_all_fix_texts_exist(lang):
    import re
    from pathlib import Path

    catalog = json.loads((_DIR / f"{lang}.json").read_text(encoding="utf-8"))
    src = Path(__file__).parent.parent / "reviveguard"
    keys = set()
    for path in list((src / "fixes").glob("*.py")) + [src / "cli.py", src / "remediation.py"]:
        keys |= set(re.findall(r'"(fix\.[a-z0-9_.]+)"', path.read_text(encoding="utf-8")))
    keys = {k for k in keys if not k.endswith(".")}
    missing = sorted(k for k in keys if k not in catalog)
    assert not missing, missing
