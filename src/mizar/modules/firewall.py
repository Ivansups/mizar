"""Inbound firewall checks (ufw, nftables, iptables)."""

from __future__ import annotations

import re
from typing import List, Optional

from mizar.base import Module, lacks_privileges
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

DENY = "deny"
OPEN = "open"
INACTIVE = "inactive"
DENIED = "no_privileges"

NFT_INPUT_DROP = re.compile(r"hook input[^;]*;\s*policy drop")
NFT_INPUT_CHAIN = re.compile(r"hook input")


class FirewallModule(Module):
    name = "firewall"
    profile = "quick"
    tools = ("ufw", "nft", "iptables")
    description = "default-deny inbound policy"

    def run(self, ctx: Context) -> List[Finding]:
        states = {}
        for tool, probe in (
            ("ufw", self._ufw),
            ("nft", self._nft),
            ("iptables", self._iptables),
        ):
            if ctx.has(tool):
                states[tool] = probe(ctx)
        title = "Inbound firewall policy"
        if not states:
            return [
                self.skip(
                    "firewall.policy",
                    title,
                    SkipReason.TOOL_MISSING,
                    "none of ufw, nft, iptables found",
                )
            ]
        values = list(states.values())
        if DENY in values:
            tool = next(t for t, s in states.items() if s == DENY)
            return [self.finding("firewall.policy", Status.OK, title, f"{tool}: deny")]
        if OPEN in values:
            tool = next(t for t, s in states.items() if s == OPEN)
            return [
                self.finding(
                    "firewall.policy",
                    Status.WARN,
                    title,
                    f"{tool}: inbound traffic is allowed by default",
                    "Set the default inbound policy to deny and allow needed ports.",
                )
            ]
        if set(values) == {DENIED}:
            return [
                self.skip(
                    "firewall.policy",
                    title,
                    SkipReason.NO_PRIVILEGES,
                    "firewall tools need root",
                )
            ]
        return [
            self.finding(
                "firewall.policy",
                Status.WARN,
                title,
                "no active firewall detected",
                "Enable ufw or nftables with a default-deny inbound policy.",
            )
        ]

    def _ufw(self, ctx: Context) -> str:
        result = ctx.run(["ufw", "status", "verbose"])
        if lacks_privileges(ctx, result):
            return DENIED
        if "Status: active" not in result.stdout:
            return INACTIVE
        incoming = re.search(r"Default:\s*(\w+) \(incoming\)", result.stdout)
        denies = incoming is not None and incoming.group(1) in ("deny", "reject")
        return DENY if denies else OPEN

    def _nft(self, ctx: Context) -> str:
        result = ctx.run(["nft", "list", "ruleset"])
        if lacks_privileges(ctx, result):
            return DENIED
        if NFT_INPUT_DROP.search(result.stdout):
            return DENY
        return OPEN if NFT_INPUT_CHAIN.search(result.stdout) else INACTIVE

    def _iptables(self, ctx: Context) -> str:
        result = ctx.run(["iptables", "-S"])
        if lacks_privileges(ctx, result):
            return DENIED
        policy: Optional[str] = None
        for line in result.stdout.splitlines():
            if line.startswith("-P INPUT"):
                policy = line.split()[-1]
        if policy in ("DROP", "REJECT"):
            return DENY
        return OPEN if policy == "ACCEPT" else INACTIVE
