"""Everything modules need from the outside world, behind one injectable seam."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional, Sequence


@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False

    @property
    def not_found(self) -> bool:
        return self.returncode == 127


RunFn = Callable[[Sequence[str], int], CommandResult]
ReadFn = Callable[[str], Optional[str]]
WhichFn = Callable[[str], Optional[str]]


def run_subprocess(cmd: Sequence[str], timeout: int) -> CommandResult:
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError:
        return CommandResult(returncode=127)
    except subprocess.TimeoutExpired:
        return CommandResult(returncode=124, timed_out=True)
    return CommandResult(proc.stdout, proc.stderr, proc.returncode)


def read_file(path: str) -> Optional[str]:
    try:
        with open(path, errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def detect_distro() -> str:
    for line in (read_file("/etc/os-release") or "").splitlines():
        if line.startswith("ID="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


@dataclass
class Context:
    run_fn: RunFn
    read_fn: ReadFn
    which_fn: WhichFn
    is_root: bool = False
    distro: str = "unknown"
    active: bool = False
    target: str = "127.0.0.1"
    timeout: int = 60
    tmp_dir: str = "/tmp"

    def run(self, cmd: Sequence[str], timeout: Optional[int] = None) -> CommandResult:
        return self.run_fn(cmd, timeout or self.timeout)

    def read(self, path: str) -> Optional[str]:
        return self.read_fn(path)

    def has(self, tool: str) -> bool:
        return self.which_fn(tool) is not None

    @classmethod
    def system(
        cls, active: bool = False, target: str = "127.0.0.1", timeout: int = 60
    ) -> Context:
        return cls(
            run_fn=run_subprocess,
            read_fn=read_file,
            which_fn=shutil.which,
            is_root=os.geteuid() == 0,
            distro=detect_distro(),
            active=active,
            target=target,
            timeout=timeout,
            tmp_dir=tempfile.gettempdir(),
        )
