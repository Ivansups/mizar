"""Runs the real CLI against the real system. Only meant for the test image.

Enable with MIZAR_INTEGRATION=1 (docker/Dockerfile.test sets it).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MIZAR_INTEGRATION") != "1",
    reason="integration tests only run inside the test image",
)

TIMEOUT = 1800


def run_mizar(
    args: List[str], user: Optional[str] = None
) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "mizar"] + args
    if user:
        cmd = ["runuser", "-u", user, "--"] + cmd
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False
    )


def audit(args: List[str], user: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    proc = run_mizar(["run", "--no-save", "--format", "json"] + args, user)
    assert proc.returncode in (0, 1, 2, 3, 4), proc.stderr
    report = json.loads(proc.stdout)
    assert report["schema_version"] == 1
    return {f["id"]: f for f in report["findings"]}


def errors(found: Dict[str, Dict[str, Any]]) -> List[str]:
    return [
        f"{f['id']}: {f['evidence']}" for f in found.values() if f["status"] == "ERROR"
    ]


def test_standard_run_as_root_checks_the_real_system() -> None:
    found = audit([])
    assert errors(found) == []
    assert found["ssh.permit_root_login"]["status"] != "SKIPPED"
    assert found["filesystem.empty_passwords"]["status"] != "SKIPPED"
    assert found["network.risky_listeners"]["status"] == "OK"
    assert "lynis.hardening_index" in found
    assert "packages.updates" in found and "firewall.policy" in found


def test_non_root_run_reports_no_privileges_instead_of_failing() -> None:
    found = audit([], user="tester")
    assert errors(found) == []
    for id in ("ssh.config", "filesystem.empty_passwords", "lynis.audit"):
        assert found[id]["status"] == "SKIPPED", id
        assert found[id]["skip_reason"] == "no_privileges", id


def test_full_profile_runs_rootkit_scanners() -> None:
    found = audit(["--profile", "full", "--modules", "malware,docker"])
    assert errors(found) == []
    assert found["malware.rkhunter"]["status"] in ("OK", "WARN")
    assert found["malware.chkrootkit"]["status"] in ("OK", "CRIT")
    assert found["docker.bench"]["skip_reason"] == "not_applicable"


def test_active_scan_finds_the_local_sshd() -> None:
    found = audit(["--active", "--modules", "nmap"])
    assert errors(found) == []
    assert "22/" in found["nmap.open_ports"]["evidence"]


def test_active_module_is_skipped_by_default() -> None:
    found = audit(["--modules", "nmap"])
    assert found["nmap.active"]["skip_reason"] == "not_enabled"


def test_strict_turns_skips_into_exit_code_4_or_crit() -> None:
    proc = run_mizar(["run", "--no-save", "--strict", "-q"], user="tester")
    assert proc.returncode in (2, 4), proc.stdout + proc.stderr


def test_saved_report_is_private_and_can_be_rendered_again(tmp_path: Path) -> None:
    out = tmp_path / "out"
    proc = run_mizar(["run", "--modules", "ssh,firewall", "--output", str(out)])
    assert proc.returncode in (0, 1, 2), proc.stderr
    assert (out / "report.json").stat().st_mode & 0o777 == 0o600
    again = run_mizar(["report", str(out / "report.json")])
    assert again.returncode == proc.returncode
    assert "Coverage:" in again.stdout
