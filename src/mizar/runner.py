"""Module selection and execution."""

from __future__ import annotations

from typing import List

from mizar.base import PROFILES, Module
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status


def select_modules(
    registry: List[Module], profile: str, only: List[str], skip: List[str]
) -> List[Module]:
    known = {m.name for m in registry}
    unknown = [n for n in only + skip if n not in known]
    if unknown:
        raise ValueError("unknown module: " + ", ".join(unknown))
    if only:
        chosen = [m for m in registry if m.name in only]
    else:
        level = PROFILES.index(profile)
        chosen = [m for m in registry if PROFILES.index(m.profile) <= level]
    return [m for m in chosen if m.name not in skip]


def run_modules(modules: List[Module], ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for module in modules:
        if module.active and not ctx.active:
            findings.append(
                module.skip(
                    module.name + ".active",
                    module.name + " (active scan)",
                    SkipReason.NOT_ENABLED,
                    "Run with --active to enable.",
                )
            )
            continue
        try:
            findings.extend(module.run(ctx))
        except Exception as exc:  # a broken check must not abort the audit
            findings.append(
                module.finding(
                    module.name + ".error",
                    Status.ERROR,
                    module.name + " crashed",
                    f"{type(exc).__name__}: {exc}",
                )
            )
    return findings
