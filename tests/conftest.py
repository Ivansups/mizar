from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, Optional, Sequence, Set, Tuple

import pytest

from sigma_audit.context import CommandResult, Context

FIXTURES = Path(__file__).parent / "fixtures"

MakeCtx = Callable[..., Context]


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture
def make_ctx() -> MakeCtx:
    """Build a Context backed by dicts instead of the real system."""

    def build(
        commands: Optional[Dict[Tuple[str, ...], CommandResult]] = None,
        files: Optional[Dict[str, str]] = None,
        tools: Optional[Set[str]] = None,
        **kwargs: object,
    ) -> Context:
        cmds = commands or {}
        fs = files or {}
        available = tools if tools is not None else {c[0] for c in cmds}

        def run(cmd: Sequence[str], timeout: int) -> CommandResult:
            return cmds.get(tuple(cmd), CommandResult(returncode=127))

        def read(path: str) -> Optional[str]:
            return fs.get(path)

        def which(tool: str) -> Optional[str]:
            return "/usr/bin/" + tool if tool in available else None

        return Context(run_fn=run, read_fn=read, which_fn=which, **kwargs)  # type: ignore[arg-type]

    return build
