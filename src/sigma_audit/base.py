"""Base class for audit modules."""

from __future__ import annotations

from typing import List, Optional, Tuple

from sigma_audit.context import Context
from sigma_audit.models import Finding, SkipReason, Status

PROFILES = ("quick", "standard", "full")


class Module:
    """One independent area of checks. Subclasses implement `run`."""

    name: str = ""
    profile: str = "standard"
    active: bool = False
    description: str = ""
    tools: Tuple[str, ...] = ()  # optional external tools, shown by `list` and `doctor`

    def run(self, ctx: Context) -> List[Finding]:
        raise NotImplementedError

    def finding(
        self,
        id: str,
        status: Status,
        title: str,
        evidence: str = "",
        recommendation: str = "",
        skip_reason: Optional[SkipReason] = None,
    ) -> Finding:
        return Finding(
            id, self.name, status, title, evidence, recommendation, skip_reason
        )

    def skip(
        self, id: str, title: str, reason: SkipReason, evidence: str = ""
    ) -> Finding:
        return self.finding(id, Status.SKIPPED, title, evidence, skip_reason=reason)
