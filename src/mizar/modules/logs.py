"""SSH login history: brute-force attempts and direct root logins."""

from __future__ import annotations

import re
from collections import Counter
from typing import List, Optional

from mizar.base import Module
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

LOG_FILES = ("/var/log/auth.log", "/var/log/secure")
JOURNAL_CMD = [
    "journalctl",
    "-u",
    "ssh",
    "-u",
    "sshd",
    "--no-pager",
    "-o",
    "cat",
    "--since",
    "7 days ago",
]
FAILED = re.compile(r"Failed password for (?:invalid user )?\S+ from (\S+)")
ROOT_LOGIN = re.compile(r"Accepted \w+ for root from (\S+)")
BRUTEFORCE_THRESHOLD = 100
TOP_SOURCES = 5


class LogsModule(Module):
    name = "logs"
    profile = "standard"
    tools = ("journalctl",)
    description = "failed and root SSH logins from auth logs"

    def run(self, ctx: Context) -> List[Finding]:
        text = self._load(ctx)
        if text is None:
            reason = SkipReason.NO_PRIVILEGES if not ctx.is_root else (
                SkipReason.NOT_APPLICABLE
            )
            return [
                self.skip(
                    "logs.source",
                    "SSH authentication logs",
                    reason,
                    "no readable auth log or journal",
                )
            ]
        return [self._failed_logins(text), self._root_logins(text)]

    def _load(self, ctx: Context) -> Optional[str]:
        for path in LOG_FILES:
            text = ctx.read(path)
            if text is not None:
                return text
        result = ctx.run(JOURNAL_CMD)
        if not result.not_found and result.returncode == 0 and result.stdout.strip():
            return result.stdout
        return None

    def _failed_logins(self, text: str) -> Finding:
        title = "Failed SSH password logins"
        counts = Counter(FAILED.findall(text))
        total = sum(counts.values())
        top = counts.most_common(TOP_SOURCES)
        if top and top[0][1] >= BRUTEFORCE_THRESHOLD:
            sources = ", ".join(f"{ip}: {n}" for ip, n in top)
            return self.finding(
                "logs.failed_logins",
                Status.WARN,
                title,
                f"{total} failed attempts; top sources {sources}",
                "Use key-only auth and consider fail2ban or a firewall rate limit.",
            )
        return self.finding(
            "logs.failed_logins", Status.OK, title, f"{total} failed attempts"
        )

    def _root_logins(self, text: str) -> Finding:
        title = "Direct root logins over SSH"
        sources = sorted(set(ROOT_LOGIN.findall(text)))
        if not sources:
            return self.finding("logs.root_logins", Status.OK, title)
        return self.finding(
            "logs.root_logins",
            Status.WARN,
            title,
            "root logged in from " + ", ".join(sources),
            "Log in as a normal user and use sudo; disable root SSH login.",
        )
