from __future__ import annotations

from typing import Dict, List

from mizar.context import CommandResult
from mizar.models import Finding, SkipReason, Status
from mizar.modules.firewall import FirewallModule
from mizar.modules.network import NetworkModule, NmapModule
from mizar.modules.ssh import SshModule
from tests.conftest import MakeCtx, fixture_text


def by_id(findings: List[Finding]) -> Dict[str, Finding]:
    return {f.id: f for f in findings}


# --- ssh ---------------------------------------------------------------


def test_ssh_flags_bad_config(make_ctx: MakeCtx) -> None:
    ctx = make_ctx({("sshd", "-T"): CommandResult(fixture_text("sshd_T_bad.txt"))})
    found = by_id(SshModule().run(ctx))
    assert found["ssh.permit_root_login"].status is Status.CRIT
    assert found["ssh.password_auth"].status is Status.WARN
    assert found["ssh.max_auth_tries"].status is Status.WARN
    assert found["ssh.empty_passwords"].status is Status.OK


def test_ssh_good_config_is_all_ok(make_ctx: MakeCtx) -> None:
    ctx = make_ctx({("sshd", "-T"): CommandResult(fixture_text("sshd_T_good.txt"))})
    statuses = {f.id: f.status for f in SshModule().run(ctx) if f.id != "ssh.audit"}
    assert set(statuses.values()) == {Status.OK}


def test_ssh_without_sshd_is_not_applicable(make_ctx: MakeCtx) -> None:
    findings = SshModule().run(make_ctx())
    config = by_id(findings)["ssh.config"]
    assert config.status is Status.SKIPPED
    assert config.skip_reason is SkipReason.NOT_APPLICABLE


def test_ssh_without_root_reports_no_privileges(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {("sshd", "-T"): CommandResult(stderr="no hostkeys available", returncode=1)},
        is_root=False,
    )
    config = by_id(SshModule().run(ctx))["ssh.config"]
    assert config.skip_reason is SkipReason.NO_PRIVILEGES


def test_ssh_audit_missing_is_skipped_and_present_is_parsed(
    make_ctx: MakeCtx,
) -> None:
    sshd = {("sshd", "-T"): CommandResult(fixture_text("sshd_T_good.txt"))}
    missing = by_id(SshModule().run(make_ctx(sshd)))["ssh.audit"]
    assert missing.skip_reason is SkipReason.TOOL_MISSING

    audit_cmd = ("ssh-audit", "-j", "-p", "22", "127.0.0.1")
    weak = '{"recommendations": {"critical": {"del": {"kex": ["x"]}}, "warning": {}}}'
    ctx = make_ctx({**sshd, audit_cmd: CommandResult(weak, returncode=3)})
    assert by_id(SshModule().run(ctx))["ssh.audit"].status is Status.CRIT

    ctx = make_ctx({**sshd, audit_cmd: CommandResult("not json")})
    assert by_id(SshModule().run(ctx))["ssh.audit"].status is Status.ERROR


# --- firewall ----------------------------------------------------------


def test_firewall_ufw_default_deny_is_ok(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {("ufw", "status", "verbose"): CommandResult(fixture_text("ufw_active.txt"))}
    )
    assert FirewallModule().run(ctx)[0].status is Status.OK


def test_firewall_nft_policy_drop_is_ok(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {("nft", "list", "ruleset"): CommandResult(fixture_text("nft_drop.txt"))}
    )
    assert FirewallModule().run(ctx)[0].status is Status.OK


def test_firewall_iptables_accept_policy_warns(make_ctx: MakeCtx) -> None:
    ctx = make_ctx({("iptables", "-S"): CommandResult("-P INPUT ACCEPT\n")})
    assert FirewallModule().run(ctx)[0].status is Status.WARN


def test_firewall_inactive_ufw_and_no_rules_warns(make_ctx: MakeCtx) -> None:
    ctx = make_ctx({("ufw", "status", "verbose"): CommandResult("Status: inactive\n")})
    assert FirewallModule().run(ctx)[0].status is Status.WARN


def test_firewall_no_tools_is_skipped(make_ctx: MakeCtx) -> None:
    finding = FirewallModule().run(make_ctx())[0]
    assert finding.skip_reason is SkipReason.TOOL_MISSING


def test_firewall_denied_without_root_is_no_privileges(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {
            ("nft", "list", "ruleset"): CommandResult(
                stderr="Operation not permitted", returncode=1
            )
        },
        is_root=False,
    )
    assert FirewallModule().run(ctx)[0].skip_reason is SkipReason.NO_PRIVILEGES


# --- network -----------------------------------------------------------


def test_network_flags_risky_and_unexpected_public_listeners(
    make_ctx: MakeCtx,
) -> None:
    ctx = make_ctx({("ss", "-tulpn"): CommandResult(fixture_text("ss_tulpn.txt"))})
    found = by_id(NetworkModule().run(ctx))
    assert found["network.risky_listeners"].status is Status.CRIT
    assert "6379" in found["network.risky_listeners"].evidence
    assert found["network.public_listeners"].status is Status.WARN
    assert "8080" in found["network.public_listeners"].evidence
    assert "5432" not in found["network.public_listeners"].evidence
    assert "68" not in found["network.public_listeners"].evidence


def test_network_clean_host_is_ok(make_ctx: MakeCtx) -> None:
    ctx = make_ctx({("ss", "-tulpn"): CommandResult(fixture_text("ss_clean.txt"))})
    assert {f.status for f in NetworkModule().run(ctx)} == {Status.OK}


def test_network_without_ss_is_skipped(make_ctx: MakeCtx) -> None:
    assert NetworkModule().run(make_ctx())[0].skip_reason is SkipReason.TOOL_MISSING


def test_nmap_is_active_and_parses_open_ports(make_ctx: MakeCtx) -> None:
    assert NmapModule().active is True
    cmd = ("nmap", "-Pn", "-sV", "-oG", "-", "127.0.0.1")
    ctx = make_ctx({cmd: CommandResult(fixture_text("nmap_grepable.txt"))}, active=True)
    found = by_id(NmapModule().run(ctx))
    assert found["nmap.risky_ports"].status is Status.CRIT
    assert "6379" in found["nmap.risky_ports"].evidence
    assert "631" not in found["nmap.open_ports"].evidence


def test_nmap_missing_is_skipped(make_ctx: MakeCtx) -> None:
    finding = NmapModule().run(make_ctx(active=True))[0]
    assert finding.skip_reason is SkipReason.TOOL_MISSING
