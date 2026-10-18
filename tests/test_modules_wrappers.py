from __future__ import annotations

from typing import Dict, List

from mizar.context import CommandResult, Context
from mizar.models import Finding, SkipReason, Status
from mizar.modules.docker import DockerModule
from mizar.modules.lynis import REPORT_PATH, LynisModule
from mizar.modules.malware import MalwareModule
from tests.conftest import MakeCtx

LYNIS_CMD = ("lynis", "audit", "system", "--quick", "--no-colors")
REPORT = (
    "# lynis report\n"
    "hardening_index=48\n"
    "warning[]=SSH-7440|Weak SSH config|-|-|\n"
    "suggestion[]=AUTH-9286|Set password aging|-|-|\n"
    "suggestion[]=KRNL-6000|Harden sysctl|-|-|\n"
)


def by_id(findings: List[Finding]) -> Dict[str, Finding]:
    return {f.id: f for f in findings}


def test_lynis_reads_report_after_audit(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {LYNIS_CMD: CommandResult()}, files={REPORT_PATH: REPORT}, is_root=True
    )
    found = by_id(LynisModule().run(ctx))
    assert found["lynis.hardening_index"].status is Status.WARN
    assert "48/100, 2 suggestions" in found["lynis.hardening_index"].evidence
    assert "SSH-7440: Weak SSH config" in found["lynis.warnings"].evidence


def test_lynis_skip_reasons(make_ctx: MakeCtx) -> None:
    missing = LynisModule().run(make_ctx())[0]
    assert missing.skip_reason is SkipReason.TOOL_MISSING
    nonroot = LynisModule().run(make_ctx({LYNIS_CMD: CommandResult()}))[0]
    assert nonroot.skip_reason is SkipReason.NO_PRIVILEGES


def test_rkhunter_warnings_and_chkrootkit_infection(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {
            ("rkhunter", "--check", "--sk", "--nocolors", "--rwo"): CommandResult(
                "Warning: Hidden file found: /dev/.udev\n", returncode=1
            ),
            ("chkrootkit", "-q"): CommandResult(
                "Checking `bindshell'... INFECTED (PORTS: 31337)\n"
            ),
        },
        is_root=True,
    )
    found = by_id(MalwareModule().run(ctx))
    assert found["malware.rkhunter"].status is Status.WARN
    assert found["malware.chkrootkit"].status is Status.CRIT


def test_rkhunter_repeated_warnings_are_counted_once(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {
            ("rkhunter", "--check", "--sk", "--nocolors", "--rwo"): CommandResult(
                "Warning: The file properties have changed:\n" * 3
                + "Warning: Hidden file found: /dev/.udev\n",
                returncode=1,
            ),
        },
        is_root=True,
    )
    evidence = by_id(MalwareModule().run(ctx))["malware.rkhunter"].evidence
    assert evidence.splitlines() == [
        "Warning: The file properties have changed: (x3)",
        "Warning: Hidden file found: /dev/.udev",
    ]


def test_malware_tools_missing_or_without_root(make_ctx: MakeCtx) -> None:
    for finding in MalwareModule().run(make_ctx()):
        assert finding.skip_reason is SkipReason.TOOL_MISSING
    ctx = make_ctx({("rkhunter", "--check"): CommandResult()}, is_root=False)
    rk = by_id(MalwareModule().run(ctx))["malware.rkhunter"]
    assert rk.skip_reason is SkipReason.NO_PRIVILEGES


def test_docker_bench_not_applicable_without_docker(make_ctx: MakeCtx) -> None:
    assert DockerModule().run(make_ctx())[0].skip_reason is SkipReason.NOT_APPLICABLE


BENCH_CMD = (
    "sh",
    "-c",
    'cd "$1" && exec "./$2" -l /dev/null',
    "sh",
    "/usr/bin",
    "docker-bench-security.sh",
)


def bench_ctx(make_ctx: MakeCtx, result: CommandResult) -> Context:
    return make_ctx(
        {("docker", "ps"): CommandResult(), BENCH_CMD: result},
        tools={"docker", "docker-bench-security.sh"},
        is_root=True,
    )


def test_docker_bench_collects_warnings_and_runs_from_its_own_directory(
    make_ctx: MakeCtx,
) -> None:
    out = "[PASS] 1.1 - ok\n[WARN] 2.1 - Ensure network traffic is restricted\n"
    finding = DockerModule().run(bench_ctx(make_ctx, CommandResult(out)))[0]
    assert finding.status is Status.WARN
    assert "1 failed checks" in finding.evidence


def test_docker_bench_counts_colored_warnings(make_ctx: MakeCtx) -> None:
    out = "\x1b[1;32m[PASS]\x1b[0m 1.1 - ok\n\x1b[1;31m[WARN]\x1b[0m 2.1 - bad\n"
    finding = DockerModule().run(bench_ctx(make_ctx, CommandResult(out)))[0]
    assert finding.status is Status.WARN
    assert "\x1b" not in finding.evidence


def test_docker_bench_that_prints_no_results_is_an_error(make_ctx: MakeCtx) -> None:
    broken = CommandResult("./functions/helper_lib.sh: No such file", returncode=127)
    finding = DockerModule().run(bench_ctx(make_ctx, broken))[0]
    assert finding.status is Status.ERROR
    assert "No such file" in finding.evidence
