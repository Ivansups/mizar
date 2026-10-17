from __future__ import annotations

from mizar.models import Coverage, Finding, SkipReason, Status


def test_finding_to_dict_uses_plain_values() -> None:
    finding = Finding(
        id="ssh.root",
        module="ssh",
        status=Status.SKIPPED,
        title="Root login",
        skip_reason=SkipReason.TOOL_MISSING,
    )
    data = finding.to_dict()
    assert data["status"] == "SKIPPED"
    assert data["skip_reason"] == "tool_missing"
    assert data["evidence"] == ""


def test_coverage_counts_each_status_class() -> None:
    findings = [
        Finding("a", "m", Status.OK, "t"),
        Finding("b", "m", Status.WARN, "t"),
        Finding("c", "m", Status.CRIT, "t"),
        Finding("d", "m", Status.SKIPPED, "t", skip_reason=SkipReason.NOT_ENABLED),
        Finding("e", "m", Status.ERROR, "t"),
    ]
    assert Coverage.from_findings(findings) == Coverage(executed=3, skipped=1, errors=1)
