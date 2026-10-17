"""Pending updates, automatic updates and services that need a restart."""

from __future__ import annotations

import re
from typing import List, Optional

from mizar.base import Module, lacks_privileges
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"
DNF_UPDATES_AVAILABLE = 100
SAMPLE = 10


class PackagesModule(Module):
    name = "packages"
    profile = "standard"
    tools = ("apt", "dnf", "needrestart")
    description = "pending updates, auto-updates, restarts needed"

    def run(self, ctx: Context) -> List[Finding]:
        return [
            self._updates(ctx),
            self._auto_updates(ctx),
            self._needrestart(ctx),
        ]

    def _updates(self, ctx: Context) -> Finding:
        title = "Pending package updates"
        if ctx.has("apt"):
            lines = [
                line
                for line in ctx.run(["apt", "list", "--upgradable"]).stdout.splitlines()
                if "[upgradable" in line
            ]
            security = sum("-security" in line for line in lines)
            return self._pending(
                title, [line.split("/")[0] for line in lines], security
            )
        if ctx.has("dnf"):
            result = ctx.run(["dnf", "check-update", "-q"])
            if result.returncode == 0:
                return self.finding("packages.updates", Status.OK, title)
            if result.returncode != DNF_UPDATES_AVAILABLE:
                return self.finding(
                    "packages.updates", Status.ERROR, title, result.stderr.strip()
                )
            names: List[str] = []
            for line in result.stdout.splitlines():
                if line.startswith("Obsoleting"):
                    break
                if len(line.split()) >= 3:
                    names.append(line.split()[0])
            return self._pending(title, names, None)
        return self.skip(
            "packages.updates",
            title,
            SkipReason.TOOL_MISSING,
            "neither apt nor dnf found",
        )

    def _pending(
        self, title: str, names: List[str], security: Optional[int]
    ) -> Finding:
        if not names:
            return self.finding("packages.updates", Status.OK, title)
        extra = f" ({security} security)" if security is not None else ""
        evidence = f"{len(names)} upgradable{extra}: {', '.join(names[:SAMPLE])}"
        return self.finding(
            "packages.updates",
            Status.WARN,
            title,
            evidence,
            "Apply updates, security ones first.",
        )

    def _auto_updates(self, ctx: Context) -> Finding:
        title = "Automatic security updates"
        advice = "Enable unattended-upgrades (apt) or dnf-automatic (dnf)."
        if ctx.has("apt"):
            enabled = re.search(
                r'Unattended-Upgrade\s+"1"', ctx.read(AUTO_UPGRADES) or ""
            )
            return self.finding(
                "packages.auto_updates",
                Status.OK if enabled else Status.WARN,
                title,
                "" if enabled else "unattended-upgrades is not enabled",
                "" if enabled else advice,
            )
        if ctx.has("dnf"):
            result = ctx.run(["systemctl", "is-enabled", "dnf-automatic.timer"])
            timer_on = result.stdout.strip() == "enabled"
            return self.finding(
                "packages.auto_updates",
                Status.OK if timer_on else Status.WARN,
                title,
                "" if timer_on else "dnf-automatic.timer is not enabled",
                "" if timer_on else advice,
            )
        return self.skip(
            "packages.auto_updates", title, SkipReason.NOT_APPLICABLE, "no apt or dnf"
        )

    def _needrestart(self, ctx: Context) -> Finding:
        title = "Services or kernel needing a restart"
        if not ctx.has("needrestart"):
            return self.skip(
                "packages.needrestart",
                title,
                SkipReason.TOOL_MISSING,
                "needrestart not found",
            )
        # -r l: list only, never restart anything.
        result = ctx.run(["needrestart", "-b", "-r", "l"])
        if lacks_privileges(ctx, result):
            return self.skip(
                "packages.needrestart",
                title,
                SkipReason.NO_PRIVILEGES,
                "needrestart needs root",
            )
        kernel = re.search(r"NEEDRESTART-KSTA:\s*(\d)", result.stdout)
        services = re.findall(r"NEEDRESTART-SVC:\s*(\S+)", result.stdout)
        notes = []
        if kernel and kernel.group(1) in ("2", "3"):
            notes.append("kernel update pending a reboot")
        if services:
            notes.append("services: " + ", ".join(services))
        if not notes:
            return self.finding("packages.needrestart", Status.OK, title)
        return self.finding(
            "packages.needrestart",
            Status.WARN,
            title,
            "; ".join(notes),
            "Reboot or restart the listed services in a maintenance window.",
        )
