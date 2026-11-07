"""Password quality policy: libpam-pwquality with a sane minimum length (new passwords only)."""

from __future__ import annotations

from reviveguard import packages
from reviveguard.checks.accounts import MIN_PASSWORD_LENGTH, PWQUALITY_DIR
from reviveguard.context import AuditContext
from reviveguard.models import CheckResult
from reviveguard.remediation import FixSpec, Manual, write_file_atomic

DROPIN = "90-reviveguard.conf"
TEXT = (
    "# Managed by ReviveGuard (USR-004). Remove this file to undo.\n"
    f"minlen = {MIN_PASSWORD_LENGTH}\nminclass = 3\n"
)


def plan_password_policy(ctx: AuditContext, result: CheckResult) -> FixSpec | Manual:
    installed = packages.is_installed(ctx, "libpam-pwquality")
    if not installed and not packages.apt_available(ctx):
        return Manual("fix.reason.no_apt")
    path = ctx.path(f"{PWQUALITY_DIR}/{DROPIN}")

    def apply() -> None:
        if not installed:
            error = packages.install(ctx, ["libpam-pwquality"])
            if error:
                raise RuntimeError(error)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_file_atomic(path, TEXT, 0o644)

    return FixSpec(
        fix_id="passwords.policy.set",
        check_id=result.check_id,
        description=f"Require passwords of at least {MIN_PASSWORD_LENGTH} characters (3 classes)",
        files=[path],
        apply=apply,
        validate=lambda: None,
        activate=None,
        change_key="fix.passwords.policy",
        change_args={"length": str(MIN_PASSWORD_LENGTH)},
        packages=[] if installed else ["libpam-pwquality"],
    )
