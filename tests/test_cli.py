from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from sigma_audit import cli
from sigma_audit.base import Module
from sigma_audit.context import Context
from sigma_audit.models import Finding, Status
from tests.conftest import MakeCtx


class Warns(Module):
    name = "warns"
    profile = "quick"
    tools = ("sometool",)

    def run(self, ctx: Context) -> List[Finding]:
        return [self.finding("warns.a", Status.WARN, "Something is off")]


@pytest.fixture(autouse=True)
def fake_system(monkeypatch: pytest.MonkeyPatch, make_ctx: MakeCtx) -> None:
    monkeypatch.setattr(cli, "all_modules", lambda: [Warns()])
    monkeypatch.setattr(cli, "build_context", lambda args: make_ctx())


def test_no_args_runs_and_returns_warn_code(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code = cli.main(["--output", str(tmp_path)])
    assert code == 1
    assert "Something is off" in capsys.readouterr().out
    saved = json.loads((tmp_path / "report.json").read_text())
    assert saved["findings"][0]["id"] == "warns.a"
    assert (tmp_path / "report.txt").exists()


def test_no_save_writes_nothing(tmp_path: Path) -> None:
    cli.main(["run", "--no-save", "--output", str(tmp_path)])
    assert list(tmp_path.iterdir()) == []


def test_json_format_prints_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["run", "--no-save", "--format", "json"])
    assert json.loads(capsys.readouterr().out)["schema_version"] == 1


def test_unknown_module_returns_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["run", "--no-save", "--modules", "nope"]) == 3
    assert "nope" in capsys.readouterr().err


def test_bad_flag_returns_3() -> None:
    assert cli.main(["run", "--bogus"]) == 3


def test_list_shows_modules(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "warns" in out and "quick" in out


def test_doctor_reports_missing_tool(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["doctor"]) == 0
    assert "sometool" in capsys.readouterr().out


def test_report_command_rerenders_saved_json(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cli.main(["run", "--output", str(tmp_path)])
    capsys.readouterr()
    code = cli.main(["report", str(tmp_path / "report.json")])
    assert code == 1
    assert "Something is off" in capsys.readouterr().out
