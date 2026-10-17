"""Accounts and file permission checks."""

from __future__ import annotations

from typing import List

from mizar.base import Module
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

SUID_ARGS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/home",
    "-xdev",
    "-type",
    "f",
    "(",
    "-perm",
    "-4000",
    "-o",
    "-perm",
    "-2000",
    ")",
]
WORLD_WRITABLE_ARGS = [
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "-xdev",
    "-type",
    "f",
    "-perm",
    "-0002",
]
SAMPLE = 20


class FilesystemModule(Module):
    name = "filesystem"
    profile = "standard"
    tools = ("find",)
    description = "UID 0 accounts, empty passwords, risky file permissions"

    def run(self, ctx: Context) -> List[Finding]:
        return [
            self._uid0(ctx),
            self._empty_passwords(ctx),
            self._find(
                ctx,
                "filesystem.risky_suid",
                "SUID/SGID files in temp and home directories",
                SUID_ARGS,
                "Remove the setuid/setgid bit or delete the file.",
            ),
            self._find(
                ctx,
                "filesystem.world_writable",
                "World-writable files in system directories",
                WORLD_WRITABLE_ARGS,
                "Run chmod o-w on these files.",
            ),
        ]

    def _uid0(self, ctx: Context) -> Finding:
        title = "Accounts with UID 0 besides root"
        passwd = ctx.read("/etc/passwd")
        if passwd is None:
            return self.skip(
                "filesystem.uid0", title, SkipReason.NOT_APPLICABLE, "no /etc/passwd"
            )
        extra = []
        for line in passwd.splitlines():
            fields = line.split(":")
            if len(fields) >= 3 and fields[2] == "0" and fields[0] != "root":
                extra.append(fields[0])
        if not extra:
            return self.finding("filesystem.uid0", Status.OK, title)
        return self.finding(
            "filesystem.uid0",
            Status.CRIT,
            title,
            ", ".join(extra),
            "Remove these accounts or give them a non-zero UID.",
        )

    def _empty_passwords(self, ctx: Context) -> Finding:
        title = "Accounts with an empty password"
        shadow = ctx.read("/etc/shadow")
        if shadow is None:
            reason = (
                SkipReason.NOT_APPLICABLE if ctx.is_root else SkipReason.NO_PRIVILEGES
            )
            return self.skip(
                "filesystem.empty_passwords", title, reason, "cannot read /etc/shadow"
            )
        empty = []
        for line in shadow.splitlines():
            fields = line.split(":")
            if len(fields) >= 2 and fields[1] == "":
                empty.append(fields[0])
        if not empty:
            return self.finding("filesystem.empty_passwords", Status.OK, title)
        return self.finding(
            "filesystem.empty_passwords",
            Status.CRIT,
            title,
            ", ".join(empty),
            "Set a password or lock the account with passwd -l.",
        )

    def _find(
        self, ctx: Context, id: str, title: str, args: List[str], advice: str
    ) -> Finding:
        result = ctx.run(["find"] + args)
        if result.not_found:
            return self.skip(id, title, SkipReason.TOOL_MISSING, "find not found")
        if result.timed_out:
            return self.skip(id, title, SkipReason.TIMEOUT, "find took too long")
        # find exits non-zero when a listed directory is missing; stdout still counts.
        paths = [line for line in result.stdout.splitlines() if line.strip()]
        if not paths:
            return self.finding(id, Status.OK, title)
        more = f" (+{len(paths) - SAMPLE} more)" if len(paths) > SAMPLE else ""
        return self.finding(
            id, Status.WARN, title, "\n".join(paths[:SAMPLE]) + more, advice
        )
