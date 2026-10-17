from __future__ import annotations

from typing import Dict, List

from sigma_audit.context import CommandResult
from sigma_audit.models import Finding, SkipReason, Status
from sigma_audit.modules.filesystem import FilesystemModule
from sigma_audit.modules.logs import LogsModule
from sigma_audit.modules.packages import PackagesModule
from tests.conftest import MakeCtx


def by_id(findings: List[Finding]) -> Dict[str, Finding]:
    return {f.id: f for f in findings}


APT_LIST = (
    "Listing...\n"
    "openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.15 amd64 "
    "[upgradable from: 3.0.2-0ubuntu1.14]\n"
    "curl/jammy-updates 7.81.0-1ubuntu1.18 amd64 [upgradable from: 7.81.0-1]\n"
)
APT_CMD = ("apt", "list", "--upgradable")
AUTO_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"


# --- packages ----------------------------------------------------------


def test_apt_pending_updates_warn_with_security_count(make_ctx: MakeCtx) -> None:
    found = by_id(PackagesModule().run(make_ctx({APT_CMD: CommandResult(APT_LIST)})))
    updates = found["packages.updates"]
    assert updates.status is Status.WARN
    assert "2 upgradable" in updates.evidence and "1 security" in updates.evidence


def test_apt_up_to_date_is_ok(make_ctx: MakeCtx) -> None:
    ctx = make_ctx({APT_CMD: CommandResult("Listing...\n")})
    assert by_id(PackagesModule().run(ctx))["packages.updates"].status is Status.OK


def test_dnf_exit_100_means_updates(make_ctx: MakeCtx) -> None:
    out = "kernel.x86_64   5.14.0-2   baseos\nopenssl.x86_64   3.0.7-1   baseos\n"
    ctx = make_ctx({("dnf", "check-update", "-q"): CommandResult(out, returncode=100)})
    updates = by_id(PackagesModule().run(ctx))["packages.updates"]
    assert updates.status is Status.WARN and "2 upgradable" in updates.evidence


def test_no_package_manager_is_skipped(make_ctx: MakeCtx) -> None:
    found = by_id(PackagesModule().run(make_ctx()))
    assert found["packages.updates"].skip_reason is SkipReason.TOOL_MISSING


def test_unattended_upgrades_enabled_or_not(make_ctx: MakeCtx) -> None:
    on = make_ctx(
        {APT_CMD: CommandResult("Listing...\n")},
        files={AUTO_UPGRADES: 'APT::Periodic::Unattended-Upgrade "1";\n'},
    )
    off = make_ctx({APT_CMD: CommandResult("Listing...\n")})
    assert by_id(PackagesModule().run(on))["packages.auto_updates"].status is Status.OK
    assert (
        by_id(PackagesModule().run(off))["packages.auto_updates"].status is Status.WARN
    )


def test_needrestart_runs_in_list_only_mode(make_ctx: MakeCtx) -> None:
    pending = "NEEDRESTART-VER: 3.5\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service\n"
    ctx = make_ctx(
        {
            APT_CMD: CommandResult("Listing...\n"),
            ("needrestart", "-b", "-r", "l"): CommandResult(pending),
        }
    )
    found = by_id(PackagesModule().run(ctx))["packages.needrestart"]
    assert found.status is Status.WARN and "ssh.service" in found.evidence


def test_needrestart_missing_is_skipped(make_ctx: MakeCtx) -> None:
    ctx = make_ctx({APT_CMD: CommandResult("Listing...\n")})
    found = by_id(PackagesModule().run(ctx))["packages.needrestart"]
    assert found.skip_reason is SkipReason.TOOL_MISSING


# --- logs --------------------------------------------------------------


def failed(n: int, ip: str) -> str:
    line = "Oct 1 sshd[1]: Failed password for invalid user admin from {} port 22 ssh2\n"
    return line.format(ip) * n


def test_many_failures_from_one_ip_warn(make_ctx: MakeCtx) -> None:
    log = failed(150, "203.0.113.9") + failed(3, "198.51.100.1")
    found = by_id(LogsModule().run(make_ctx(files={"/var/log/auth.log": log})))
    assert found["logs.failed_logins"].status is Status.WARN
    assert "203.0.113.9: 150" in found["logs.failed_logins"].evidence
    assert found["logs.root_logins"].status is Status.OK


def test_few_failures_are_ok(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(files={"/var/log/secure": failed(5, "198.51.100.1")})
    assert by_id(LogsModule().run(ctx))["logs.failed_logins"].status is Status.OK


def test_accepted_root_login_warns(make_ctx: MakeCtx) -> None:
    log = "sshd[2]: Accepted publickey for root from 192.0.2.7 port 5000 ssh2\n"
    ctx = make_ctx(files={"/var/log/auth.log": log})
    found = by_id(LogsModule().run(ctx))["logs.root_logins"]
    assert found.status is Status.WARN and "192.0.2.7" in found.evidence


def test_journalctl_is_the_fallback(make_ctx: MakeCtx) -> None:
    cmd = ("journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-o", "cat")
    ctx = make_ctx({cmd + ("--since", "7 days ago"): CommandResult(failed(2, "1.2.3.4"))})
    assert by_id(LogsModule().run(ctx))["logs.failed_logins"].status is Status.OK


def test_no_log_source_without_root_is_no_privileges(make_ctx: MakeCtx) -> None:
    found = LogsModule().run(make_ctx(is_root=False))
    assert found[0].skip_reason is SkipReason.NO_PRIVILEGES


# --- filesystem --------------------------------------------------------


def test_extra_uid0_account_is_critical(make_ctx: MakeCtx) -> None:
    passwd = "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\nbob:x:1000:1000::/h:/bin/sh\n"
    found = by_id(FilesystemModule().run(make_ctx(files={"/etc/passwd": passwd})))
    assert found["filesystem.uid0"].status is Status.CRIT
    assert "toor" in found["filesystem.uid0"].evidence


def test_empty_password_is_critical_and_needs_root(make_ctx: MakeCtx) -> None:
    shadow = "root:!:19000:::::\nguest::19000:0:99999:7:::\n"
    root = make_ctx(files={"/etc/shadow": shadow}, is_root=True)
    found = by_id(FilesystemModule().run(root))["filesystem.empty_passwords"]
    assert found.status is Status.CRIT and "guest" in found.evidence
    nonroot = make_ctx(is_root=False)
    skipped = by_id(FilesystemModule().run(nonroot))["filesystem.empty_passwords"]
    assert skipped.skip_reason is SkipReason.NO_PRIVILEGES


SUID_CMD = (
    "find /tmp /var/tmp /dev/shm /home -xdev -type f "
    "( -perm -4000 -o -perm -2000 )"
).split()
WW_CMD = "find /etc /usr /bin /sbin /lib -xdev -type f -perm -0002".split()


def test_suid_in_tmp_and_world_writable_system_files_warn(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {
            tuple(SUID_CMD): CommandResult("/tmp/.x/rootshell\n", returncode=1),
            tuple(WW_CMD): CommandResult("/etc/cron.d/job\n"),
        }
    )
    found = by_id(FilesystemModule().run(ctx))
    assert found["filesystem.risky_suid"].status is Status.WARN
    assert "/tmp/.x/rootshell" in found["filesystem.risky_suid"].evidence
    assert found["filesystem.world_writable"].status is Status.WARN


def test_clean_find_results_are_ok(make_ctx: MakeCtx) -> None:
    ctx = make_ctx(
        {tuple(SUID_CMD): CommandResult(returncode=1), tuple(WW_CMD): CommandResult()}
    )
    found = by_id(FilesystemModule().run(ctx))
    assert found["filesystem.risky_suid"].status is Status.OK
    assert found["filesystem.world_writable"].status is Status.OK
