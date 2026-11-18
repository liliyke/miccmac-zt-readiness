"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Entry point: ``python -m miccmac_study <command> [options]``.

Each command lives in its own module exposing ``configure(parser)`` and
``run(args) -> int``. Only the module for the requested command is
imported, so one command's problem never blocks the others. A
formats.StudyError (a problem the user must fix) prints ``error: ...`` and
exits 2.

The instruments are not installed with the package: run them from the
repository root, or set PYTHONPATH to it (the guide's Setup line does).
"""
from __future__ import annotations

import argparse
import importlib
import sys
from typing import List, Optional

from miccmac_study.formats import StudyError

COMMANDS = {
    "worksheet": ("miccmac_study.worksheet",
                  "Generate blank per-host manual worksheets (no tool results in them)."),
    "ledger": ("miccmac_study.ledger",
               "Record (lint, hash and archive), verify, list or withdraw: the SHA-256 ledger of study files."),
    "health": ("miccmac_study.health",
               "Check tool outputs, facts files or input files without revealing any result."),
    "register-sheet": ("miccmac_study.register_sheet",
                       "Generate risk-register review sheets, only after every worksheet of the study is hashed."),
    "agreement": ("miccmac_study.agreement",
                  "Compute the protocol's agreement statistics, only after every worksheet of the study is hashed."),
    "synthetic": ("miccmac_study.synthetic",
                  "Build a synthetic study folder for pipeline tests (never study data)."),
}


def _print_usage(stream=None) -> None:
    # The stream is looked up when called (a default of sys.stdout would be fixed at
    # import time and miss contextlib.redirect_stdout).
    stream = stream if stream is not None else sys.stdout
    print("usage: python -m miccmac_study <command> [options]", file=stream)
    print("", file=stream)
    print("commands:", file=stream)
    width = max(len(name) for name in COMMANDS)
    for name, (_, help_text) in COMMANDS.items():
        print(f"  {name:<{width}}  {help_text}", file=stream)
    print("", file=stream)
    print("Run 'python -m miccmac_study <command> --help' for a command's options.", file=stream)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        _print_usage()
        return 0
    name = argv[0]
    if name not in COMMANDS:
        print(f"error: unknown command {name!r}", file=sys.stderr)
        _print_usage(sys.stderr)
        return 2
    module_name, help_text = COMMANDS[name]
    module = importlib.import_module(module_name)
    parser = argparse.ArgumentParser(prog=f"python -m miccmac_study {name}", description=help_text)
    module.configure(parser)
    args = parser.parse_args(argv[1:])
    try:
        return int(module.run(args) or 0)
    except StudyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
