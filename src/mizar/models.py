"""Result model shared by all modules and reporters."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class Status(str, Enum):
    OK = "OK"
    WARN = "WARN"
    CRIT = "CRIT"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class SkipReason(str, Enum):
    TOOL_MISSING = "tool_missing"
    NOT_APPLICABLE = "not_applicable"
    NO_PRIVILEGES = "no_privileges"
    TIMEOUT = "timeout"
    NOT_ENABLED = "not_enabled"


@dataclass
class Finding:
    id: str
    module: str
    status: Status
    title: str
    evidence: str = ""
    recommendation: str = ""
    skip_reason: Optional[SkipReason] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "id": self.id,
            "module": self.module,
            "status": self.status.value,
            "title": self.title,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "skip_reason": self.skip_reason.value if self.skip_reason else None,
        }


@dataclass
class Coverage:
    executed: int
    skipped: int
    errors: int

    @classmethod
    def from_findings(cls, findings: List[Finding]) -> Coverage:
        skipped = sum(f.status is Status.SKIPPED for f in findings)
        errors = sum(f.status is Status.ERROR for f in findings)
        return cls(len(findings) - skipped - errors, skipped, errors)
