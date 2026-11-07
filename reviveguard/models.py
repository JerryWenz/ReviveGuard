"""Shared result structures used by every check."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Severity of a failed check. Higher value means more severe."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Status(enum.Enum):
    OK = "OK"  # the check passed
    FAIL = "FAIL"  # a weakness was found
    SKIPPED = "SKIPPED"  # not applicable here (tool or service absent)
    ERROR = "ERROR"  # the check itself could not be completed


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single check.

    Text fields hold i18n *keys*, not final text. Evidence is technical data
    and is never translated. It must never contain secrets.
    """

    check_id: str
    category: str
    severity: Severity
    status: Status
    title_key: str
    description_key: str
    remediation_key: str
    evidence: tuple[str, ...] = ()
    auto_fix_supported: bool = False
    restart_required: bool = False
    reboot_required: bool = False
    message_args: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["status"] = self.status.value
        data["evidence"] = list(self.evidence)
        return data
