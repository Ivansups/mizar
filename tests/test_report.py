from __future__ import annotations

from typing import List

from sigma_audit.models import Finding, SkipReason, Status
from sigma_audit.report import build_report, exit_code, render_text


def f(status: Status, reason: SkipReason | None = None) -> Finding:
    return Finding("m.x", "m", status, "Title", "some evidence", "fix it", reason)


def report_for(findings: List[Finding]) -> dict:  # type: ignore[type-arg]
    return build_report(findings, host="h", distro="debian", profile="standard")


def test_report_has_schema_and_coverage() -> None:
    report = report_for([f(Status.OK), f(Status.SKIPPED, SkipReason.TOOL_MISSING)])
    assert report["schema_version"] == 1
    assert report["host"] == "h"
    assert report["coverage"] == {"executed": 1, "skipped": 1, "errors": 0}
    assert report["findings"][1]["skip_reason"] == "tool_missing"


def test_exit_code_precedence() -> None:
    def code(statuses: List[Status], strict: bool = False) -> int:
        return exit_code(report_for([f(s) for s in statuses]), strict)

    assert code([Status.OK]) == 0
    assert code([Status.OK, Status.WARN]) == 1
    assert code([Status.WARN, Status.CRIT]) == 2
    assert code([Status.CRIT, Status.ERROR]) == 2
    assert code([Status.WARN, Status.ERROR]) == 3
    assert code([Status.WARN, Status.SKIPPED]) == 1
    assert code([Status.WARN, Status.SKIPPED], strict=True) == 4
    assert code([Status.OK, Status.SKIPPED], strict=True) == 4


def test_text_shows_coverage_and_skip_reason() -> None:
    report = report_for([f(Status.WARN), f(Status.SKIPPED, SkipReason.NO_PRIVILEGES)])
    text = render_text(report, min_severity="ok", color=False, verbose=False)
    assert "[WARN]" in text
    assert "[SKIPPED]" in text and "no_privileges" in text
    assert "1 executed, 1 skipped, 0 errors" in text
    assert "\x1b[" not in text


def test_min_severity_hides_ok_but_never_skips() -> None:
    report = report_for([f(Status.OK), f(Status.WARN), f(Status.SKIPPED)])
    text = render_text(report, min_severity="warn", color=False, verbose=False)
    assert "[OK]" not in text
    assert "[WARN]" in text and "[SKIPPED]" in text


def test_color_adds_ansi_and_verbose_shows_ok_evidence() -> None:
    report = report_for([f(Status.OK)])
    plain = render_text(report, min_severity="ok", color=False, verbose=False)
    verbose = render_text(report, min_severity="ok", color=False, verbose=True)
    colored = render_text(report, min_severity="ok", color=True, verbose=False)
    assert "some evidence" not in plain
    assert "some evidence" in verbose
    assert "\x1b[" in colored


def test_validate_report_accepts_valid_and_recomputes_coverage() -> None:
    from sigma_audit.report import validate_report

    report = report_for([f(Status.CRIT), f(Status.OK)])
    report["coverage"] = {"executed": 0, "skipped": 99, "errors": 0}
    clean = validate_report(report)
    assert clean["coverage"] == {"executed": 2, "skipped": 0, "errors": 0}


def test_validate_report_rejects_tampered_documents() -> None:
    import copy

    import pytest

    from sigma_audit.report import validate_report

    good = report_for([f(Status.OK)])
    bad_status = copy.deepcopy(good)
    bad_status["findings"][0]["status"] = "FINE"
    bad_version = {**good, "schema_version": 2}
    missing = {k: v for k, v in good.items() if k != "host"}
    docs: List[object] = [bad_status, bad_version, missing, [], {"findings": "x"}]
    for doc in docs:
        with pytest.raises(ValueError):
            validate_report(doc)


def test_validate_report_rejects_escape_codes_in_header_fields() -> None:
    import pytest

    from sigma_audit.report import validate_report

    for key in ("tool_version", "host", "distro", "profile"):
        for bad in ("\x1b[31mred", "a\nb", 5):
            doc = report_for([f(Status.OK)])
            doc[key] = bad
            with pytest.raises(ValueError):
                validate_report(doc)


def test_render_text_neutralizes_escape_codes_in_header() -> None:
    report = report_for([f(Status.OK)])
    report["profile"] = "\x1b]0;pwned\x07"
    assert "\x1b" not in render_text(report, "ok", color=False, verbose=False)
