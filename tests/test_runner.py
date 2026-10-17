from __future__ import annotations

from typing import List

import pytest

from sigma_audit.base import Module
from sigma_audit.context import Context
from sigma_audit.models import Finding, SkipReason, Status
from sigma_audit.runner import run_modules, select_modules
from tests.conftest import MakeCtx


class Quick(Module):
    name = "quick_mod"
    profile = "quick"

    def run(self, ctx: Context) -> List[Finding]:
        return [self.finding("quick_mod.a", Status.OK, "fine")]


class Full(Module):
    name = "full_mod"
    profile = "full"

    def run(self, ctx: Context) -> List[Finding]:
        return []


class Active(Module):
    name = "active_mod"
    profile = "standard"
    active = True

    def run(self, ctx: Context) -> List[Finding]:
        return [self.finding("active_mod.a", Status.OK, "scanned")]


class Boom(Module):
    name = "boom"
    profile = "quick"

    def run(self, ctx: Context) -> List[Finding]:
        raise RuntimeError("kaput")


REGISTRY: List[Module] = [Quick(), Full(), Active(), Boom()]


def names(mods: List[Module]) -> List[str]:
    return [m.name for m in mods]


def test_profile_includes_modules_up_to_its_level() -> None:
    assert names(select_modules(REGISTRY, "quick", [], [])) == ["quick_mod", "boom"]
    assert names(select_modules(REGISTRY, "standard", [], [])) == [
        "quick_mod",
        "active_mod",
        "boom",
    ]
    assert len(select_modules(REGISTRY, "full", [], [])) == 4


def test_explicit_modules_override_profile_and_skip_removes() -> None:
    assert names(select_modules(REGISTRY, "quick", ["full_mod"], [])) == ["full_mod"]
    assert names(select_modules(REGISTRY, "full", [], ["boom", "full_mod"])) == [
        "quick_mod",
        "active_mod",
    ]


def test_unknown_module_name_is_an_error() -> None:
    with pytest.raises(ValueError, match="nope"):
        select_modules(REGISTRY, "standard", ["nope"], [])


def test_active_module_is_skipped_without_flag(make_ctx: MakeCtx) -> None:
    findings = run_modules([Active()], make_ctx(active=False))
    assert [(f.status, f.skip_reason) for f in findings] == [
        (Status.SKIPPED, SkipReason.NOT_ENABLED)
    ]
    assert [f.status for f in run_modules([Active()], make_ctx(active=True))] == [
        Status.OK
    ]


def test_crashing_module_becomes_error_finding(make_ctx: MakeCtx) -> None:
    findings = run_modules([Boom(), Quick()], make_ctx())
    assert findings[0].status is Status.ERROR
    assert "kaput" in findings[0].evidence
    assert findings[1].status is Status.OK
