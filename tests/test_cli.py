from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from mizar import cli
from mizar.base import Module
from mizar.context import Context
from mizar.models import Finding, Status
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


def test_doctor_works_with_the_real_context(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.undo()
    assert cli.main(["doctor"]) == 0
    assert "distro:" in capsys.readouterr().out


def test_report_command_rerenders_saved_json(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cli.main(["run", "--output", str(tmp_path)])
    capsys.readouterr()
    code = cli.main(["report", str(tmp_path / "report.json")])
    assert code == 1
    assert "Something is off" in capsys.readouterr().out


def test_report_command_rejects_tampered_json(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    cli.main(["run", "--output", str(tmp_path)])
    path = tmp_path / "report.json"
    data = json.loads(path.read_text())
    data["findings"][0]["status"] = "FINE"
    path.write_text(json.dumps(data))
    assert cli.main(["report", str(path)]) == 3


def test_saved_reports_are_private(tmp_path: Path) -> None:
    cli.main(["run", "--output", str(tmp_path / "out")])
    mode = (tmp_path / "out" / "report.json").stat().st_mode & 0o777
    assert mode == 0o600


def test_existing_report_is_never_overwritten_or_followed(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    (out / "report.json").symlink_to(victim)
    assert cli.main(["run", "--output", str(out)]) == 3
    assert victim.read_text() == "keep me"


def test_default_dir_refuses_symlinked_reports_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    (work / "mizar-reports").symlink_to(elsewhere)
    monkeypatch.chdir(work)
    assert cli.main(["run"]) == 3
    assert list(elsewhere.iterdir()) == []
