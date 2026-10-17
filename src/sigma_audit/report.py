"""Report building, text rendering and exit codes."""

from __future__ import annotations

import datetime
from typing import Any, Dict, List

from sigma_audit import __version__
from sigma_audit.models import Coverage, Finding, Status

SCHEMA_VERSION = 1
Report = Dict[str, Any]

_SEVERITY_RANK = {"ok": 0, "warn": 1, "crit": 2}
_ALWAYS_SHOWN = {Status.SKIPPED.value, Status.ERROR.value}
_COLORS = {
    "OK": "32",
    "WARN": "33",
    "CRIT": "31;1",
    "SKIPPED": "36",
    "ERROR": "35;1",
}


def build_report(
    findings: List[Finding], host: str, distro: str, profile: str
) -> Report:
    coverage = Coverage.from_findings(findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "host": host,
        "distro": distro,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "profile": profile,
        "coverage": {
            "executed": coverage.executed,
            "skipped": coverage.skipped,
            "errors": coverage.errors,
        },
        "findings": [f.to_dict() for f in findings],
    }


def _count(report: Report, status: Status) -> int:
    return sum(f["status"] == status.value for f in report["findings"])


def exit_code(report: Report, strict: bool) -> int:
    if _count(report, Status.CRIT):
        return 2
    if _count(report, Status.ERROR):
        return 3
    if strict and _count(report, Status.SKIPPED):
        return 4
    if _count(report, Status.WARN):
        return 1
    return 0


def _paint(label: str, status: str, color: bool) -> str:
    if not color:
        return label
    return f"\x1b[{_COLORS[status]}m{label}\x1b[0m"


def _visible(finding: Dict[str, Any], min_severity: str) -> bool:
    status = finding["status"]
    if status in _ALWAYS_SHOWN:
        return True
    return _SEVERITY_RANK[status.lower()] >= _SEVERITY_RANK[min_severity]


def _indented(label: str, text: str) -> List[str]:
    return [
        f"{'':10}{label}: {line}" if i == 0 else f"{'':12}{line}"
        for i, line in enumerate(text.splitlines())
    ]


def render_summary(report: Report) -> str:
    cov = report["coverage"]
    return (
        f"Coverage: {cov['executed']} executed, {cov['skipped']} skipped, "
        f"{cov['errors']} errors\n"
        f"Result:   {_count(report, Status.CRIT)} CRIT, "
        f"{_count(report, Status.WARN)} WARN, {_count(report, Status.OK)} OK"
    )


def render_text(report: Report, min_severity: str, color: bool, verbose: bool) -> str:
    lines = [
        f"sigma-audit {report['tool_version']}  host={report['host']}  "
        f"distro={report['distro']}  profile={report['profile']}",
        "",
    ]
    for finding in report["findings"]:
        if not _visible(finding, min_severity):
            continue
        status = finding["status"]
        label = _paint(f"[{status}]".ljust(9), status, color)
        reason = f" ({finding['skip_reason']})" if finding["skip_reason"] else ""
        lines.append(f"{label} {finding['id']}  {finding['title']}{reason}")
        if status != "OK" or verbose:
            if finding["evidence"]:
                lines.extend(_indented("evidence", finding["evidence"]))
            if finding["recommendation"] and status != "OK":
                lines.extend(_indented("fix", finding["recommendation"]))
    lines.extend(["", render_summary(report)])
    return "\n".join(lines)
