"""Wrapper around docker-bench-security (CIS Docker benchmark)."""

from __future__ import annotations

from typing import List

from mizar.base import Module
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

BENCH_SCRIPTS = ("docker-bench-security.sh", "docker-bench-security")
BENCH_TIMEOUT = 600
SAMPLE = 20


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
        script = next((s for s in BENCH_SCRIPTS if ctx.has(s)), None)
        if script is None:
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
        # -l /dev/null: the script writes a log file into the current directory.
        result = ctx.run([script, "-l", "/dev/null"], timeout=BENCH_TIMEOUT)
        if result.timed_out:
            return [self.skip(id, title, SkipReason.TIMEOUT, f"over {BENCH_TIMEOUT}s")]
        warnings = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().startswith("[WARN]")
        ]
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
