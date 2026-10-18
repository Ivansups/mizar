"""Wrapper around docker-bench-security (CIS Docker benchmark)."""

from __future__ import annotations

import os
import re
from typing import List

from mizar.base import Module
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

BENCH_SCRIPTS = ("docker-bench-security.sh", "docker-bench-security")
BENCH_TIMEOUT = 600
SAMPLE = 20
ANSI = re.compile(r"\x1b\[[0-9;]*m")
RESULT_MARKS = ("[PASS]", "[WARN]", "[INFO]", "[NOTE]")
# The script sources ./functions/*.sh, so it only works from its own directory.
RUN_IN_DIR = 'cd "$1" && exec "./$2" -l /dev/null'


class DockerModule(Module):
    name = "docker"
    profile = "full"
    tools = ("docker", "docker-bench-security.sh")
    description = "CIS Docker benchmark, only when Docker is installed"

    def run(self, ctx: Context) -> List[Finding]:
        id, title = "docker.bench", "CIS Docker benchmark"
        if not ctx.has("docker"):
            return [
                self.skip(
                    id, title, SkipReason.NOT_APPLICABLE, "Docker is not installed"
                )
            ]
        found = next((p for p in map(ctx.locate, BENCH_SCRIPTS) if p), None)
        if found is None:
            return [
                self.skip(
                    id,
                    title,
                    SkipReason.TOOL_MISSING,
                    "docker-bench-security not found",
                )
            ]
        if not ctx.is_root:
            return [
                self.skip(
                    id, title, SkipReason.NO_PRIVILEGES, "the benchmark needs root"
                )
            ]
        real = os.path.realpath(found)
        # -l /dev/null: the script writes a log file into the current directory.
        result = ctx.run(
            [
                "sh",
                "-c",
                RUN_IN_DIR,
                "sh",
                os.path.dirname(real),
                os.path.basename(real),
            ],
            timeout=BENCH_TIMEOUT,
        )
        if result.timed_out:
            return [self.skip(id, title, SkipReason.TIMEOUT, f"over {BENCH_TIMEOUT}s")]
        lines = [ANSI.sub("", line).strip() for line in result.stdout.splitlines()]
        if not any(line.startswith(RESULT_MARKS) for line in lines):
            detail = (result.stderr or result.stdout).strip().splitlines()
            return [
                self.finding(
                    id,
                    Status.ERROR,
                    title,
                    "docker-bench-security printed no results: "
                    + (detail[0] if detail else f"exit {result.returncode}"),
                )
            ]
        warnings = [line for line in lines if line.startswith("[WARN]")]
        if not warnings:
            return [self.finding(id, Status.OK, title)]
        more = f"\n(+{len(warnings) - SAMPLE} more)" if len(warnings) > SAMPLE else ""
        return [
            self.finding(
                id,
                Status.WARN,
                title,
                f"{len(warnings)} failed checks\n"
                + "\n".join(warnings[:SAMPLE])
                + more,
                "Review the CIS Docker benchmark items listed above.",
            )
        ]
