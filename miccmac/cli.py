"""Command-line interface for the MICCMAC readiness toolkit."""
from __future__ import annotations

import argparse
import json
import sys

from miccmac import __version__
from miccmac.config import Config, ConfigError
from miccmac.connectors.base import ConnectorError
from miccmac.engine import enabled_check_ids, run_assessment
from miccmac.metadata import MappingsError
from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY
from miccmac.report import render as render_assessment
from miccmac.risk_register import build_risk_register
from miccmac.risk_register import render as render_risk_register

CONNECTORS = ("ssh-osquery", "ssh-osquery-windows")


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
    p_assess.add_argument("--methodology", "-m", default=None,
                          choices=sorted(METHODOLOGY_REGISTRY),
                          help="Additionally score using a maturity-model methodology.")
    p_assess.add_argument("--config", "-c", default=None,
                          help="Path to a YAML config file (excluded_checks, custom_checks_dir).")
    p_assess.add_argument("--risk-register", action="store_true",
                          help="Append the CIS IG / FAIR-inspired risk register to the output.")
    p_assess.add_argument("--connector", default=None, choices=CONNECTORS,
                          help="Collect real facts from the target instead of the NOT_IMPLEMENTED "
                               "stub. ssh-osquery targets Linux; ssh-osquery-windows targets Windows "
                               "(OpenSSH Server + osqueryi.exe on the target).")
    p_assess.add_argument("--ssh-user", default=None,
                          help="SSH username (required with --connector ssh-osquery[-windows]).")
    p_assess.add_argument("--ssh-key", default=None,
                          help="Path to the SSH private key (required with --connector ssh-osquery[-windows]).")
    p_assess.add_argument("--ssh-port", type=int, default=22,
                          help="SSH port (default: 22).")
    p_assess.add_argument("--inventory-record", default=None,
                          help="Path to a JSON file with an external inventory-system record "
                               "for this device (feeds INV-01/INV-04).")
    p_assess.add_argument("--attestation", default=None,
                          help="Path to a JSON file attesting organizational facts that "
                               "aren't observable from the device itself, e.g. "
                               "identity-aware access policy (feeds CTL-03 and similar).")

    p_checks = sub.add_parser(
        "list-checks",
        help="List the enabled check IDs for a configuration (the fairness control).",
    )
    p_checks.add_argument("--config", "-c", default=None,
                          help="Path to a YAML config file (excluded_checks, custom_checks_dir).")
    p_checks.add_argument("--format", "-f", default="text", choices=["text", "json"],
                          help="Output format (default: text).")

    return parser


def _load_config(config_path: str | None) -> Config:
    if config_path is None:
        return Config()
    return Config.from_file(config_path)


def _render_output(assessment, entries, fmt: str) -> str:
    fmt = (fmt or "text").lower()
    if fmt == "json":
        if entries is None:
            return json.dumps(assessment.to_dict(), indent=2)
        return json.dumps(
            {"assessment": assessment.to_dict(), "risk_register": [e.to_dict() for e in entries]},
            indent=2,
        )

    output = render_assessment(assessment, fmt)
    if entries is not None:
        output = output + "\n\n" + render_risk_register(entries, fmt)
    return output


def _load_json_file(path: str, flag_name: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        raise ConfigError(f"cannot read {flag_name} file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{flag_name} file is not valid JSON: {exc}") from exc


def _build_context(args) -> dict:
    context = {}

    if args.connector in ("ssh-osquery", "ssh-osquery-windows"):
        if not args.ssh_user or not args.ssh_key:
            raise ConfigError(f"--connector {args.connector} requires --ssh-user and --ssh-key")
        if args.connector == "ssh-osquery":
            from miccmac.connectors.ssh_osquery import SSHOsqueryConnector as _Connector
        else:
            from miccmac.connectors.ssh_osquery_windows import SSHOsqueryWindowsConnector as _Connector
        connector = _Connector(
            ssh_user=args.ssh_user, ssh_key_path=args.ssh_key, port=args.ssh_port,
        )
        context["facts"] = connector.collect_facts(args.target)

    if args.inventory_record:
        context["inventory_record"] = _load_json_file(args.inventory_record, "--inventory-record")

    if args.attestation:
        context["attestation"] = _load_json_file(args.attestation, "--attestation")

    return context


def _custom_check_risk_metadata(config: Config) -> dict:
    """Flatten every loaded custom-check plugin's RISK_METADATA into a single
    check_id -> CheckMetadata lookup, so custom checks plug into the risk
    register the same way built-in checks do."""
    merged = {}
    for plugins in config.load_custom_checks().values():
        for plugin in plugins:
            merged.update(plugin.risk_metadata)
    return merged


def _run_assess(args) -> str:
    config = _load_config(args.config)
    context = _build_context(args)
    assessment = run_assessment(
        args.target, context=context, config=config, methodology_name=args.methodology,
    )
    entries = None
    if args.risk_register:
        entries = build_risk_register(assessment, extra_metadata=_custom_check_risk_metadata(config))
    return _render_output(assessment, entries, args.format)


def _run_list_checks(args) -> str:
    config = _load_config(args.config)
    ids = enabled_check_ids(config)
    if (args.format or "text").lower() == "json":
        return json.dumps(ids, indent=2)
    return "\n".join(ids)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command not in ("assess", "list-checks"):
        parser.print_help()
        return 0

    try:
        if args.command == "assess":
            output = _run_assess(args)
        else:
            output = _run_list_checks(args)
    except (ConfigError, MappingsError, ConnectorError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output_path = getattr(args, "output", None)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
        print(f"Report written to {output_path}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
