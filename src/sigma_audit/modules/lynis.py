"""Wrapper around Lynis: run an audit and read its report file."""

from __future__ import annotations

from typing import Dict, List

from sigma_audit.base import Module
from sigma_audit.context import Context
from sigma_audit.models import Finding, SkipReason, Status

REPORT_PATH = "/var/log/lynis-report.dat"
LYNIS_TIMEOUT = 900
MIN_HARDENING_INDEX = 60
SAMPLE = 20


def parse_report(text: str) -> Dict[str, List[str]]:
    """Collect `key=value` and `key[]=value` lines into lists per key."""
    data: Dict[str, List[str]] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.startswith("#"):
            data.setdefault(key.rstrip("[]"), []).append(value)
    return data


class LynisModule(Module):
    name = "lynis"
    profile = "standard"
    tools = ("lynis",)
    description = "Lynis hardening index and warnings"

    def run(self, ctx: Context) -> List[Finding]:
        title = "Lynis system audit"
        if not ctx.has("lynis"):
            return [
                self.skip("lynis.audit", title, SkipReason.TOOL_MISSING, "lynis not found")
            ]
        if not ctx.is_root:
            return [
                self.skip("lynis.audit", title, SkipReason.NO_PRIVILEGES, "lynis needs root")
            ]
        result = ctx.run(
            ["lynis", "audit", "system", "--quick", "--no-colors"],
            timeout=LYNIS_TIMEOUT,
        )
        if result.timed_out:
            return [
                self.skip(
                    "lynis.audit", title, SkipReason.TIMEOUT, f"over {LYNIS_TIMEOUT}s"
                )
            ]
        report = ctx.read(REPORT_PATH)
        if report is None:
            return [
                self.finding(
                    "lynis.audit", Status.ERROR, title, f"{REPORT_PATH} was not created"
                )
            ]
        data = parse_report(report)
        return [self._index(data), self._warnings(data)]

    def _index(self, data: Dict[str, List[str]]) -> Finding:
        title = "Lynis hardening index"
        raw = data.get("hardening_index", [""])[0]
        if not raw.isdigit():
            return self.finding(
                "lynis.hardening_index", Status.ERROR, title, "no hardening_index"
            )
        suggestions = len(data.get("suggestion", []))
        evidence = f"hardening index {raw}/100, {suggestions} suggestions"
        if int(raw) >= MIN_HARDENING_INDEX:
            return self.finding("lynis.hardening_index", Status.OK, title, evidence)
        return self.finding(
            "lynis.hardening_index",
            Status.WARN,
            title,
            evidence,
            "Review /var/log/lynis-report.dat suggestions.",
        )

    def _warnings(self, data: Dict[str, List[str]]) -> Finding:
        title = "Lynis warnings"
        warnings = data.get("warning", [])
        if not warnings:
            return self.finding("lynis.warnings", Status.OK, title)
        lines = []
        for item in warnings[:SAMPLE]:
            parts = item.split("|")
            lines.append(f"{parts[0]}: {parts[1] if len(parts) > 1 else ''}")
        return self.finding(
            "lynis.warnings",
            Status.WARN,
            title,
            "\n".join(lines),
            "Look up each test ID at https://cisofy.com/lynis/controls/.",
        )
