"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Golden outputs of a stub run (`miccmac assess test-device`, no facts and no
input files) in text, markdown and JSON. tests/golden/ holds what commit
9f1d101 printed for these runs, captured before any later change to the
tool, so the files show the original scaffold output byte for byte.

The comparison ignores only the difference between LF and CRLF line ends,
so a checkout that converts line ends (git's core.autocrlf on Windows)
still compares equal."""
from __future__ import annotations

from pathlib import Path

import pytest

from miccmac.cli import main

GOLDEN = Path(__file__).resolve().parent / "golden"
FORMATS = {"stub-text.txt": [], "stub-markdown.txt": ["--format", "markdown"],
           "stub-json.txt": ["--format", "json"]}


def _golden(name: str) -> str:
    return (GOLDEN / name).read_bytes().decode("utf-8").replace("\r\n", "\n")


@pytest.mark.parametrize("name", sorted(FORMATS))
def test_a_stub_run_prints_the_golden_output(name, capsys):
    assert main(["assess", "test-device", *FORMATS[name]]) == 0
    assert capsys.readouterr().out.replace("\r\n", "\n") == _golden(name)
