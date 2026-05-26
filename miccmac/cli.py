"""Command-line interface for the MICCMAC readiness toolkit."""
from __future__ import annotations

import argparse
import sys

from miccmac import __version__
from miccmac.engine import run_assessment
from miccmac.report import render


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miccmac",
        description="Assess device readiness for Zero Trust Architecture "
                    "using the MICCMAC defensible-system properties.",
    )
    parser.add_argument("--version", action="version",
                        version=f"miccmac {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_assess = sub.add_parser("assess", help="Run a MICCMAC readiness assessment.")
    p_assess.add_argument("target", nargs="?", default="localhost",
                          help="Hostname, IP, or identifier of the device to assess.")
    p_assess.add_argument("--format", "-f", default="text",
                          choices=["text", "markdown", "md", "json"],
                          help="Output format (default: text).")
    p_assess.add_argument("--output", "-o", default=None,
                          help="Write the report to a file instead of stdout.")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "assess":
        parser.print_help()
        return 0

    assessment = run_assessment(args.target)
    output = render(assessment, args.format)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"Report written to {args.output}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
