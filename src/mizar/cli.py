"""Command line interface."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import List, NoReturn, Optional

from mizar import __version__
from mizar.base import PROFILES
from mizar.context import Context
from mizar.modules import all_modules
from mizar.report import (
    Report,
    build_report,
    exit_code,
    render_summary,
    render_text,
    validate_report,
)
from mizar.runner import run_modules, select_modules

USAGE_ERROR = 3
CRIT_EXIT = 2
SCAN_OPTIONS = {"active", "target", "timeout"}
PACKAGED_TOOLS = {"lynis", "nmap", "needrestart", "rkhunter", "chkrootkit"}
DEB_FAMILY = {"debian", "ubuntu", "raspbian", "linuxmint"}
RPM_FAMILY = {"rhel", "rocky", "almalinux", "centos", "fedora", "ol"}


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(USAGE_ERROR)


def _csv(value: str) -> List[str]:
    return [item for item in value.split(",") if item]


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="mizar", description="Read-only Linux audit.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)

    run = sub.add_parser("run", help="run the audit (default)")
    run.add_argument("--profile", choices=PROFILES, default="standard")
    run.add_argument("--modules", type=_csv, default=[], help="only these modules")
    run.add_argument("--skip", type=_csv, default=[], help="skip these modules")
    run.add_argument("--format", choices=("text", "json"), default="text")
    run.add_argument("--output", help="directory for report.json and report.txt")
    run.add_argument("--no-save", action="store_true", help="do not write files")
    run.add_argument("--min-severity", choices=("ok", "warn", "crit"), default="ok")
    run.add_argument("--active", action="store_true", help="enable active scans")
    run.add_argument("--target", default="127.0.0.1", help="host for active scans")
    run.add_argument("--timeout", type=int, default=60, help="seconds per command")
    run.add_argument("--strict", action="store_true", help="skipped checks fail")
    run.add_argument("--no-color", action="store_true")
    run.add_argument("-q", "--quiet", action="store_true", help="summary only")
    run.add_argument("-v", "--verbose", action="store_true", help="show OK details")

    sub.add_parser("list", help="list modules")
    sub.add_parser("doctor", help="show which optional tools are installed")
    rep = sub.add_parser("report", help="render a saved report.json")
    rep.add_argument("file")
    return parser


def build_context(args: argparse.Namespace) -> Context:
    # `doctor` has no scan flags, so fall back to Context's defaults.
    options = {k: v for k, v in vars(args).items() if k in SCAN_OPTIONS}
    return Context.system(**options)


def _use_color(args: argparse.Namespace) -> bool:
    return not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _write_private(path: Path, text: str) -> None:
    """Create a new owner-only file; never overwrite or follow a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w") as handle:
        handle.write(text)


def _save(report: Report, text: str, directory: Optional[str]) -> Path:
    if directory:
        target = Path(directory)
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
    else:
        root = Path("mizar-reports")
        if root.is_symlink():
            raise OSError("mizar-reports is a symlink, refusing to write into it")
        root.mkdir(mode=0o700, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        host = re.sub(r"[^A-Za-z0-9._-]", "_", report["host"])
        target = root / f"{host}-{stamp}"
        target.mkdir(mode=0o700)
    _write_private(target / "report.json", json.dumps(report, indent=2) + "\n")
    _write_private(target / "report.txt", text + "\n")
    return target


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        modules = select_modules(all_modules(), args.profile, args.modules, args.skip)
    except ValueError as exc:
        print(f"mizar: {exc}", file=sys.stderr)
        return USAGE_ERROR
    ctx = build_context(args)
    findings = run_modules(modules, ctx)
    report = build_report(findings, socket.gethostname(), ctx.distro, args.profile)

    plain = render_text(report, args.min_severity, color=False, verbose=args.verbose)
    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.quiet:
        print(render_summary(report))
    else:
        shown = render_text(report, args.min_severity, _use_color(args), args.verbose)
        print(shown)
    code = exit_code(report, args.strict)
    if not args.no_save:
        try:
            where = _save(report, plain, args.output)
        except OSError as exc:
            print(f"mizar: cannot save report: {exc}", file=sys.stderr)
            return code if code == CRIT_EXIT else USAGE_ERROR
        print(f"Report saved to {where}", file=sys.stderr)
    return code


def _cmd_list(_: argparse.Namespace) -> int:
    for module in all_modules():
        flags = "active" if module.active else "passive"
        tools = ",".join(module.tools) or "-"
        print(
            f"{module.name:<12} {module.profile:<9} {flags:<8} "
            f"tools: {tools:<30} {module.description}"
        )
    return 0


def _install_hint(tool: str, distro: str) -> str:
    if tool in PACKAGED_TOOLS and distro in DEB_FAMILY:
        return f"apt install {tool}"
    if tool in PACKAGED_TOOLS and distro in RPM_FAMILY:
        return f"dnf install {tool}"
    return "see README"


def _cmd_doctor(args: argparse.Namespace) -> int:
    ctx = build_context(args)
    print(f"distro: {ctx.distro}   root: {'yes' if ctx.is_root else 'no'}")
    seen = set()
    for module in all_modules():
        for tool in module.tools:
            if tool in seen:
                continue
            seen.add(tool)
            if ctx.has(tool):
                print(f"  found    {tool}")
            else:
                print(f"  missing  {tool:<26} {_install_hint(tool, ctx.distro)}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        report = validate_report(json.loads(Path(args.file).read_text()))
    except (OSError, ValueError) as exc:
        print(f"mizar: cannot read {args.file}: {exc}", file=sys.stderr)
        return USAGE_ERROR
    print(render_text(report, "ok", color=False, verbose=False))
    return exit_code(report, strict=False)


def main(argv: Optional[List[str]] = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    if not args_in or (args_in[0].startswith("-") and args_in[0] != "--version"):
        if not args_in or args_in[0] not in ("-h", "--help"):
            args_in.insert(0, "run")
    try:
        args = build_parser().parse_args(args_in)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    handlers = {
        "run": _cmd_run,
        "list": _cmd_list,
        "doctor": _cmd_doctor,
        "report": _cmd_report,
    }
    return handlers[args.command](args)


def entry() -> None:
    sys.exit(main())
