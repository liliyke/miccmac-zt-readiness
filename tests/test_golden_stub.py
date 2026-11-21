"""Golden outputs of a stub run (`miccmac assess test-device`, no facts and no
input files) in text, markdown and JSON. tests/golden/ holds what commit
4644c33, the last before CMMI became the default lens, printed for these
runs, captured before any later change to the tool. That is not the original
Alpha scaffold's output byte for byte: the scorecard legend in it was added on
2026-08-28 (commit 89904f9).

Since CMMI became the default lens, `--methodology none` reproduces that
output exactly; the default run differs from it only by the CMMI lens (every
CMMI value Unassessed in a stub run, plus the CMMI legend).

The comparison ignores only the difference between LF and CRLF line ends,
so a checkout that converts line ends (git's core.autocrlf on Windows)
still compares equal."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from miccmac.cli import main

GOLDEN = Path(__file__).resolve().parent / "golden"
FORMATS = {"stub-text.txt": [], "stub-markdown.txt": ["--format", "markdown"],
           "stub-json.txt": ["--format", "json"]}


def _golden(name: str) -> str:
    return (GOLDEN / name).read_bytes().decode("utf-8").replace("\r\n", "\n")


@pytest.mark.parametrize("name", sorted(FORMATS))
def test_methodology_none_prints_the_golden_output(name, capsys):
    assert main(["assess", "test-device", "--methodology", "none", *FORMATS[name]]) == 0
    assert capsys.readouterr().out.replace("\r\n", "\n") == _golden(name)


@pytest.mark.parametrize("name", sorted(FORMATS))
def test_the_default_run_differs_only_by_the_cmmi_lens(name, capsys):
    assert main(["assess", "test-device", *FORMATS[name]]) == 0
    default = capsys.readouterr().out.replace("\r\n", "\n")
    golden = _golden(name)
    assert default != golden and "CMMI" not in golden
    if name == "stub-json.txt":
        data = json.loads(default)
        methodology = data.pop("methodology")
        assert methodology["name"] == "cmmi"
        assert methodology["overall"]["level_label"] == "Unassessed"
        assert {v["level_label"] for v in methodology["properties"].values()} == {"Unassessed"}
        assert data == json.loads(golden)
        return
    if name == "stub-text.txt":
        cleaned = default.replace("  [CMMI: Unassessed]", "")
        lens = [line for line in cleaned.split("\n")
                if line in ("  CMMI            : Unassessed", "  alongside the readiness tier above, not instead of it:")
                or line.startswith("  CMMI (Capability Maturity Model Integration) maturity levels")
                or re.fullmatch(r"    \d+-\d+ +Level \d [A-Za-z ]+", line)]
        assert len(lens) == 1 + 2 + 5
    else:
        cleaned = default.replace(" &mdash; CMMI: Unassessed", "")
        lens = [line for line in cleaned.split("\n")
                if line == "- **CMMI:** Unassessed" or line.startswith("- **CMMI** (Capability Maturity Model")]
        assert len(lens) == 2
    assert "\n".join(line for line in cleaned.split("\n") if line not in lens) == golden
