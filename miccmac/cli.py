"""Command-line interface for the MICCMAC readiness toolkit.

It includes the reproducible-run options (--as-of, --save-facts, --facts and
the provenance block) and the --output safeguards (--overwrite, --stdout and
the report-destination rule, the blank file-name checks, the checks in
_check_output_option including the saved-facts guard, the atomic write);
CMMI as the default maturity lens and --methodology none; the risk-register
run's early check of the mappings file and custom-check metadata (before any
connection); and the error after a live run with --save-facts that stops
once the facts are saved, which names the saved facts file and how to build
the report from it.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import stat
import sys
from dataclasses import dataclass, field
from typing import Optional, Tuple

from miccmac import __version__
from miccmac import clock
from miccmac import facts_file as facts_file_mod
from miccmac import provenance as provenance_mod
from miccmac.config import Config, ConfigError
from miccmac.connectors.base import ConnectorError
from miccmac.engine import enabled_check_ids, run_assessment
from miccmac.metadata import MappingsError, load_register_metadata
from miccmac.methodology import DEFAULT_METHODOLOGY, NO_METHODOLOGY
from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY
from miccmac.report import render as render_assessment
from miccmac.risk_register import build_risk_register, not_evaluated_count
from miccmac.risk_register import render as render_risk_register

CONNECTORS = ("ssh-osquery", "ssh-osquery-windows")
# Target used by live and stub runs when none is given.
DEFAULT_TARGET = "localhost"
# Options whose value must name a file, as (option, args attribute). A blank
# value (an unset shell variable passes "") would otherwise be ignored or
# misread: --facts would turn into a stub run, --save-facts would drop the
# save, --output would send the whole report to stdout, --attestation and
# --inventory-record would be dropped, so the input-driven checks would run
# without them, and --config and --ssh-key would fail later with a puzzling
# message (or not at all, without --connector).
_FILE_NAME_OPTIONS = (("--output", "output"), ("--facts", "facts"), ("--save-facts", "save_facts"),
                      ("--attestation", "attestation"), ("--inventory-record", "inventory_record"),
                      ("--config", "config"), ("--ssh-key", "ssh_key"))
# Input files that --output may never replace, as (option, args attribute).
_INPUT_FILE_OPTIONS = (("--facts", "facts"), ("--attestation", "attestation"),
                       ("--inventory-record", "inventory_record"), ("--config", "config"))
# A saved facts file (miccmac/facts_file.py) holds both of these near its
# start. --output never replaces an existing file whose first 64 KiB contain
# both, not even with --overwrite or in a plain run.
_FACTS_FILE_MARKS = (b'"facts_format"', facts_file_mod.FACTS_FORMAT.encode("ascii"))
_FACTS_FILE_SNIFF_BYTES = 64 * 1024
_NO_REPORT_DESTINATION = ("this run's report holds results, so it goes to a file: give -o FILE, "
                          "or --stdout to print it here")


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
    p_assess.add_argument("target", nargs="?", default=None,
                          help="Hostname, IP, or identifier of the device to assess "
                               f"(default: {DEFAULT_TARGET}; with --facts, the target "
                               "recorded in the facts file).")
    p_assess.add_argument("--format", "-f", default="text",
                          choices=["text", "markdown", "md", "json"],
                          help="Output format (default: text).")
    p_assess.add_argument("--output", "-o", default=None,
                          help="Write the report to a file instead of stdout. The file is "
                               "written whole or not at all, its folder must already exist, "
                               "and it can never be one of this command's input files or a "
                               "saved facts file. A study run (--connector, --facts, "
                               "--save-facts or --as-of) refuses an existing file unless "
                               "--overwrite is given; a plain run replaces it, as before. A run "
                               "with --connector, --facts or --save-facts needs --output or "
                               "--stdout.")
    p_assess.add_argument("--stdout", action="store_true",
                          help="Print the report on stdout. A run with --connector, --facts or "
                               "--save-facts holds a host's results, so it prints its report only "
                               "with --stdout and otherwise needs --output; every other run "
                               "prints without it. Not allowed with --output.")
    p_assess.add_argument("--overwrite", action="store_true",
                          help="Let a study run replace an existing --output file. A plain run "
                               "does not need it. It never lets --output replace one of the "
                               "run's input files or a saved facts file, and --save-facts never "
                               "overwrites a file, with or without it.")
    p_assess.add_argument("--methodology", "-m", default=DEFAULT_METHODOLOGY,
                          choices=sorted(METHODOLOGY_REGISTRY) + [NO_METHODOLOGY],
                          help="Maturity-model lens for the property and overall levels and for the risk "
                               "register's next-level hints (default: cmmi). cisa-ztmm uses CISA's Zero Trust "
                               "Maturity Model; none turns the lens off (flat score and readiness tier only, "
                               "as before cmmi became the default). The flat score is always computed.")
    p_assess.add_argument("--config", "-c", default=None,
                          help="Path to a YAML config file (excluded_checks, custom_checks_dir).")
    p_assess.add_argument("--risk-register", action="store_true",
                          help="Append the risk register: one entry per FAIL or PARTIAL check (a finding) and "
                               "per check that could not be evaluated for missing data (ERROR, or an "
                               "organizational input not supplied), with the CIS IG / FAIR-inspired rating, "
                               "NIST SP 800-30 Rev. 1 risk factors and recommended response and, with a "
                               "maturity lens, a next-level hint.")
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
    p_assess.add_argument("--as-of", default=None, metavar="YYYY-MM-DD",
                          help="Reference date for the date-dependent checks (INV-04, ASM-01, "
                               "ASM-02, CUR-01) instead of today. Ages are counted in whole UTC "
                               "calendar days up to the end of this date, so the same facts give "
                               "the same verdicts whenever the run happens. CUR-04 is not "
                               "affected: its expired-certificate list is computed on the device "
                               "when the facts are collected.")
    p_assess.add_argument("--save-facts", default=None, metavar="FILE",
                          help="With --connector: save the collected facts, plus extended facts "
                               "for later re-tests, to FILE before the checks run. Refuses to "
                               "overwrite an existing FILE.")
    p_assess.add_argument("--facts", default=None, metavar="FILE",
                          help="Score facts saved earlier with --save-facts instead of collecting "
                               "them; no connection is made. Not allowed with --connector or "
                               "--save-facts. --attestation, --inventory-record and --config "
                               "still come from this command line.")

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
        methodology = assessment.methodology.name if assessment.methodology is not None else None
        output = output + "\n\n" + render_risk_register(
            entries, fmt, not_evaluated=not_evaluated_count(assessment), methodology=methodology)
    return output


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _note(message: str) -> None:
    print(f"note: {message}", file=sys.stderr)


def _read_input_bytes(path: str, flag_name: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise ConfigError(f"cannot read {flag_name} file: {exc}") from exc


def _load_json_file(path: str, flag_name: str) -> Tuple[object, dict]:
    """Parse a JSON input file and describe it for provenance, from the same
    bytes, so the recorded SHA-256 is that of exactly what was read.

    json.loads on the raw bytes detects the encoding: UTF-8 with or without
    a byte-order mark (what Windows PowerShell 5.1's Out-File -Encoding utf8
    writes), UTF-16 (what its '>' writes) and UTF-32. Anything else, for
    example ANSI text with accented letters, is an error."""
    data = _read_input_bytes(path, flag_name)
    try:
        value = json.loads(data)
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{flag_name} file is not valid UTF-8, UTF-16 or UTF-32 text "
                          f"(save it as UTF-8): {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{flag_name} file is not valid JSON: {exc}") from exc
    return value, provenance_mod.file_record(path, data)


@dataclass
class _Inputs:
    """The organizational input files given on the command line."""
    # "inventory_record" / "attestation" entries for the check context.
    context: dict = field(default_factory=dict)
    # Provenance "inputs": attestation / inventory_record / config -> {path, sha256}.
    records: dict = field(default_factory=dict)


def _load_inputs(args) -> _Inputs:
    inputs = _Inputs()
    if args.config is not None:
        inputs.records["config"] = provenance_mod.file_record(
            args.config, _read_input_bytes(args.config, "--config"))
    if args.inventory_record:
        value, record = _load_json_file(args.inventory_record, "--inventory-record")
        inputs.context["inventory_record"] = value
        inputs.records["inventory_record"] = record
    if args.attestation:
        value, record = _load_json_file(args.attestation, "--attestation")
        inputs.context["attestation"] = value
        inputs.records["attestation"] = record
    return inputs


def _parse_as_of_option(raw: Optional[str]) -> Optional[datetime.date]:
    if raw is None:
        return None
    try:
        return clock.parse_as_of(raw)
    except ValueError as exc:
        raise ConfigError(f"--as-of must be a date in the form YYYY-MM-DD: {exc}") from None


def _reject_blank_file_names(args) -> None:
    """A blank or whitespace value for an option that names a file is an
    error, in every run and for list-checks' --config too. So is a value
    holding a line break or any other control character: a command wrapped
    inside a quoted file name when pasted carries one, and no real file name
    does, so the run stops before anything is read or collected."""
    for flag, attr in _FILE_NAME_OPTIONS:
        value = getattr(args, attr, None)
        if value is None:
            continue
        if not value.strip():
            raise ConfigError(f"{flag} needs a file name")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ConfigError(f"{flag} holds a line break or another control character, as a command "
                              f"wrapped when pasted does; type the command again on one line "
                              f"(nothing was read or collected)")


def _check_fact_options(args) -> None:
    """Reject blank file names, conflicting fact-source options, a report
    with no destination and an unsafe --output before anything is read or
    collected, so a run that would be refused neither connects nor saves
    facts."""
    _reject_blank_file_names(args)
    if args.facts and args.connector:
        raise ConfigError("--facts cannot be combined with --connector: facts are either "
                          "replayed from a file or collected live, not both")
    if args.facts and args.save_facts:
        raise ConfigError("--facts cannot be combined with --save-facts: the replayed facts "
                          "are already saved")
    if args.save_facts and not args.connector:
        raise ConfigError("--save-facts requires --connector (it saves facts collected "
                          "from a live target)")
    if args.connector in CONNECTORS and (not args.ssh_user or not args.ssh_key):
        raise ConfigError(f"--connector {args.connector} requires --ssh-user and --ssh-key")
    if args.connector and args.target is None and (args.save_facts or args.as_of is not None):
        # A study run never falls back to localhost: an empty shell variable for
        # the address must not collect (and save) another machine's facts.
        raise ConfigError(f"a live run with --save-facts or --as-of needs the target's address "
                          f"(for example: assess 192.0.2.10 ...); it never defaults to {DEFAULT_TARGET}")
    if args.connector and args.target is not None and (
            not args.target.strip() or any(ord(char) < 32 or ord(char) == 127 for char in args.target)):
        # A blank target (bash "$IP" unset, PowerShell 7.3+) resolves to this
        # machine's own addresses; one with a line break comes from a wrapped paste.
        raise ConfigError("the target is blank or holds a line break or another control character (an "
                          "unset variable, or a line wrapped when pasted); nothing was collected")
    _check_report_destination(args)
    _check_output_option(args)
    if args.save_facts:
        facts_file_mod.check_can_save(args.save_facts)


def _report_holds_study_results(args) -> bool:
    """A replay of saved facts (--facts) and every live run (--connector,
    with or without --save-facts or --as-of): each reports a host's results.
    Such a report goes to --output, or to stdout only on request (--stdout),
    because printed by accident it would show a host's results before the
    later hosts' blind passes. A plain run (no --connector, no --facts)
    collects nothing and prints as before."""
    return bool(args.facts or args.save_facts or args.connector)


def _check_report_destination(args) -> None:
    """--stdout and --output exclude each other, and a report that holds a
    host's results needs one of them. Every other run prints as before."""
    to_stdout = getattr(args, "stdout", False)
    if to_stdout and args.output is not None:
        raise ConfigError("--stdout cannot be combined with --output: the report goes either "
                          "to a file or to the terminal, not both")
    if args.output is None and not to_stdout and _report_holds_study_results(args):
        raise ConfigError(_NO_REPORT_DESTINATION)


def _check_output_option(args) -> None:
    """The --output checks, all made before the run: --output never names
    the facts file or an input file (whatever the spelling, and through a
    hard or symbolic link), names a file in a folder that exists, never
    names a saved facts file (in any run, even with --overwrite), and in a
    study run never names an existing file unless --overwrite is given."""
    output = args.output
    if output is None:
        return
    # Spelling-insensitive, for paths that need not exist yet (--save-facts).
    for flag, facts_path in (("--save-facts", args.save_facts), ("--facts", args.facts)):
        if facts_path and _same_path(facts_path, output):
            raise ConfigError(f"--output and {flag} name the same file ({output}); the report "
                              f"would overwrite the saved facts")
    for flag, attr in _INPUT_FILE_OPTIONS:
        path = getattr(args, attr)
        if path and _same_existing_file(path, output):
            what = "the saved facts" if flag == "--facts" else "that input file"
            raise ConfigError(f"--output and {flag} name the same file ({output}); the report "
                              f"would overwrite {what}")
    if os.path.isdir(output):
        raise ConfigError(f"--output names a folder, not a file: {output}")
    folder = os.path.dirname(output)
    if folder and not os.path.isdir(folder):
        raise ConfigError(f"--output folder does not exist: {folder}")
    facts_refusal = _saved_facts_refusal(output, output)
    if facts_refusal is not None:
        raise ConfigError(facts_refusal)
    if _refuses_existing_output(args) and os.path.lexists(output):
        raise ConfigError(_refusal_message(output))


def _same_path(a: str, b: str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def _same_existing_file(a: str, b: str) -> bool:
    """True when both paths exist and are one file (os.path.samefile, which
    also sees through hard links, symbolic links and other spellings)."""
    try:
        return os.path.samefile(a, b)
    except (OSError, ValueError):
        return False


def _refuses_existing_output(args) -> bool:
    """A study run never replaces an existing --output file unless
    --overwrite is given; a plain run replaces it, as it always did."""
    return _wants_provenance(args) and not getattr(args, "overwrite", False)


def _refusal_message(path: str) -> str:
    return (f"refusing to replace {path}: study runs never overwrite a file; choose a new "
            f"file name or pass --overwrite")


def _saved_facts_refusal(path: str, shown: str) -> Optional[str]:
    """The refusal when the existing file at path is a saved facts file, else
    None. ``shown`` is the --output value as typed, for the message.

    A saved facts file is an existing regular file (through a symbolic link,
    its target) whose first 64 KiB contain both '"facts_format"' and
    'miccmac-facts/1'. A missing path, a folder, a device and a pipe are
    never opened (reading a pipe could block). A regular file that cannot be
    read cannot be cleared, so it is refused too: a report must never
    replace raw study data, and a rename can replace a file its owner
    cannot read."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as fh:
            head = fh.read(_FACTS_FILE_SNIFF_BYTES)
    except (OSError, ValueError) as exc:
        reason = getattr(exc, "strerror", None) or exc
        return (f"refusing to replace {shown}: it cannot be read to check that it is not a saved "
                f"facts file ({reason})")
    if all(mark in head for mark in _FACTS_FILE_MARKS):
        return (f"refusing to replace {shown}: it is a saved facts file "
                f"({facts_file_mod.FACTS_FORMAT}), which a report must never replace")
    return None


@dataclass
class _FactsSource:
    """Where a run's facts came from: the context's facts plus what
    provenance records about them."""
    facts: Optional[dict] = None
    kind: str = "none"                     # "connector", "facts-file" or "none"
    collected_at_utc: Optional[str] = None
    file: Optional[dict] = None            # {"path", "sha256", "role"} or None
    loaded: Optional[facts_file_mod.LoadedFacts] = None   # set for a --facts replay


def _make_connector(args):
    if args.connector == "ssh-osquery":
        from miccmac.connectors.ssh_osquery import SSHOsqueryConnector as _Connector
    else:
        from miccmac.connectors.ssh_osquery_windows import SSHOsqueryWindowsConnector as _Connector
    return _Connector(ssh_user=args.ssh_user, ssh_key_path=args.ssh_key, port=args.ssh_port)


def _collect_live(args, target: str, as_of: Optional[datetime.date]) -> _FactsSource:
    """Collect facts through the connector. With --save-facts, collect the
    extended facts too and write the facts file before any check runs, so
    the raw facts survive a later failure; the checks then read the facts
    back exactly as a later --facts replay will."""
    connector = _make_connector(args)
    if not args.save_facts:
        facts = connector.collect_facts(target)
        return _FactsSource(facts=facts, kind="connector",
                            collected_at_utc=clock.format_utc(clock.now_utc()))

    facts = connector.collect_facts(target, extended=True)
    collected_at = clock.format_utc(clock.now_utc())
    envelope = facts_file_mod.build_envelope(
        facts, tool_version=__version__, tool_commit=provenance_mod.tool_commit(),
        connector=args.connector, target=target, collected_at_utc=collected_at, as_of=as_of,
    )
    try:
        saved = facts_file_mod.save_envelope(args.save_facts, envelope)
    except facts_file_mod.FactsFileError as exc:
        raise facts_file_mod.FactsFileError(
            f"{exc}; the facts were collected from {target} but not saved, so running the command "
            f"again collects again") from None
    return _FactsSource(
        facts=saved.facts, kind="connector", collected_at_utc=collected_at,
        file={"path": args.save_facts, "sha256": saved.sha256, "role": "saved"},
    )


def _load_replay(path: str) -> _FactsSource:
    loaded = facts_file_mod.load_envelope(path)
    return _FactsSource(
        facts=loaded.facts, kind="facts-file", collected_at_utc=loaded.collected_at_utc,
        file={"path": path, "sha256": loaded.sha256, "role": "replayed"}, loaded=loaded,
    )


def _replay_target(cli_target: Optional[str], loaded: facts_file_mod.LoadedFacts) -> str:
    """No target on the command line: the facts file's. A different one is
    allowed (it only labels the report) but warned about."""
    if cli_target is None:
        return loaded.target
    if cli_target != loaded.target:
        _warn(f"target {cli_target!r} differs from the target recorded in the facts file "
              f"({loaded.target!r}); the report is labelled {cli_target!r}")
    return cli_target


def _replay_as_of(cli_as_of: Optional[datetime.date],
                  loaded: facts_file_mod.LoadedFacts) -> Tuple[datetime.date, str]:
    """The reference date for a replay and where it came from: --as-of when
    given (warning if it differs from the file's as_of or predates the
    collection), else the file's as_of, else the UTC date of collection.

    --as-of equal to the file's own as_of is never "earlier than the
    collection": after 19:00 EST (00:00 UTC) the session's local date is one
    day before the UTC collection date, and replaying with the live run's
    own date is exactly the protocol's step-6 replay."""
    collected_date = loaded.collected_date
    if cli_as_of is not None:
        if loaded.as_of is not None and cli_as_of != loaded.as_of:
            _warn(f"--as-of {cli_as_of.isoformat()} differs from the as_of date recorded in "
                  f"the facts file ({loaded.as_of.isoformat()})")
        if cli_as_of < collected_date and cli_as_of != loaded.as_of:
            _warn(f"--as-of {cli_as_of.isoformat()} is earlier than the date the facts were "
                  f"collected ({collected_date.isoformat()} UTC)")
        return cli_as_of, "cli"
    if loaded.as_of is not None:
        _note(f"--as-of not given; using {loaded.as_of.isoformat()}, the as_of date recorded "
              f"in the facts file")
        return loaded.as_of, "facts-file"
    _note(f"--as-of not given; using {collected_date.isoformat()}, the UTC date the facts "
          f"were collected; they were saved without --as-of, so the live run used the real "
          f"clock and its date-dependent verdicts may differ from this replay's")
    return collected_date, "facts-collected-date"


def _build_context(source: _FactsSource, inputs: _Inputs,
                   as_of: Optional[datetime.date]) -> dict:
    context = {}
    if source.facts is not None:
        context["facts"] = source.facts
    context.update(inputs.context)
    # Only a context that already has facts or input files gets the
    # reference date: with nothing else supplied there is no date-dependent
    # check to feed, and an "as_of"-only context would make Claimed and
    # Assessed (which keep their placeholders only for an empty context)
    # report NOT_APPLICABLE instead of NOT_IMPLEMENTED. Provenance records
    # as_of either way.
    if as_of is not None and context:
        context[clock.AS_OF_KEY] = as_of
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


class _StoppedAfterSaveError(ConfigError):
    """A live run with --save-facts stopped after the facts were saved; the
    message says how to build the report from them."""


def _stopped_after_save_message(args, exc: BaseException) -> str:
    """The error for a --save-facts run that stopped after the facts were
    saved. It names files only: the tool's own errors (ConfigError,
    MappingsError) keep their text, which names files and check ids; any
    other exception is named by its type alone, since its text could hold a
    check's detail or status."""
    own = isinstance(exc, (ConfigError, MappingsError))
    reason = str(exc) if own else f"an internal error ({type(exc).__name__}) while scoring the collected facts"
    return (f"{reason}; no report was written. The facts were saved to {args.save_facts}, so the report can be "
            f"built from them with --facts {args.save_facts} (no new collection needed)")


def _wants_provenance(args) -> bool:
    """Provenance is added for the reproducible-run options only, so a plain
    run's output stays exactly as it was."""
    return bool(args.connector or args.facts or args.save_facts or args.as_of is not None)


def _run_assess(args) -> str:
    run_at_utc = clock.format_utc(clock.now_utc())
    cli_as_of = _parse_as_of_option(args.as_of)
    _check_fact_options(args)
    config = _load_config(args.config)
    inputs = _load_inputs(args)
    # Resolving the enabled checks also validates exclusions and custom
    # checks, so a bad config fails here, before any connection is made.
    check_ids = enabled_check_ids(config) if _wants_provenance(args) else None
    methodology = None if args.methodology == NO_METHODOLOGY else args.methodology
    extra_metadata = None
    if args.risk_register:
        # The register reads the mappings file's checks: and threats: sections
        # and every custom check's RISK_METADATA: a problem in either stops the
        # run here, before anything is collected.
        load_register_metadata()
        extra_metadata = _custom_check_risk_metadata(config)

    if args.facts:
        source = _load_replay(args.facts)
        target = _replay_target(args.target, source.loaded)
        as_of, as_of_source = _replay_as_of(cli_as_of, source.loaded)
    else:
        target = args.target if args.target is not None else DEFAULT_TARGET
        as_of, as_of_source = cli_as_of, ("cli" if cli_as_of is not None else None)
        source = _collect_live(args, target, as_of) if args.connector else _FactsSource()

    try:
        context = _build_context(source, inputs, as_of)
        assessment = run_assessment(
            target, context=context, config=config, methodology_name=methodology,
        )
        if check_ids is not None:
            assessment.provenance = provenance_mod.build_provenance(
                run_at_utc=run_at_utc, as_of=as_of, as_of_source=as_of_source,
                methodology=methodology, risk_register=args.risk_register, target=target,
                facts_source=source.kind, connector=args.connector,
                facts_collected_at_utc=source.collected_at_utc, facts_file=source.file,
                inputs=inputs.records, enabled_check_ids=check_ids, facts=source.facts,
            )
        entries = None
        if args.risk_register:
            entries = build_risk_register(assessment, extra_metadata=extra_metadata)
        return _render_output(assessment, entries, args.format)
    except Exception as exc:
        if (source.file or {}).get("role") == "saved":
            # The facts are on disk: say so, and how to build the report from
            # them, instead of an error (or a traceback) that hides it.
            raise _StoppedAfterSaveError(_stopped_after_save_message(args, exc)) from None
        raise


def _run_list_checks(args) -> str:
    _reject_blank_file_names(args)
    config = _load_config(args.config)
    ids = enabled_check_ids(config)
    if (args.format or "text").lower() == "json":
        return json.dumps(ids, indent=2)
    return "\n".join(ids)


class _OutputRefusedError(Exception):
    """The --output file may not be replaced, as found just before the
    write; the exception's text is the refusal message."""


def _write_report(path: str, text: str, *, replace: bool) -> None:
    """Write the report to path whole or not at all: a temporary file in the
    same folder, written in text mode exactly as before (UTF-8, the
    platform's newlines), flushed and fsynced, then moved over path with
    os.replace. The temporary file is removed on any failure, so a failed
    write leaves path as it was. Just before the move, a saved facts file
    at path is refused in every run, and with replace=False so is any
    file that exists by then (_OutputRefusedError): _check_output_option
    refused both before the run, so this only catches a file created or
    changed in the meantime. Raises OSError when the file cannot be written.

    Two kinds of path are written as the old direct write did: a symbolic
    link has its target written (atomically), and an existing device or
    pipe, such as /dev/null or NUL, is written to directly; it cannot, and
    must never, be replaced by a regular file."""
    target = os.path.realpath(path) if os.path.islink(path) else path
    if _is_device_or_pipe(target):
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)
        return
    folder = os.path.dirname(target) or os.curdir
    fh, tmp_path = _create_temporary_file(folder, os.path.basename(target))
    try:
        with fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        facts_refusal = _saved_facts_refusal(target, path)
        if facts_refusal is not None:
            raise _OutputRefusedError(facts_refusal)
        if not replace and os.path.lexists(path):
            raise _OutputRefusedError(_refusal_message(path))
        os.replace(tmp_path, target)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _is_device_or_pipe(path: str) -> bool:
    """True for an existing path that is neither a regular file nor a folder."""
    try:
        mode = os.stat(path).st_mode
    except (OSError, ValueError):
        return False
    return not stat.S_ISREG(mode) and not stat.S_ISDIR(mode)


def _create_temporary_file(folder: str, name: str):
    """(open text file, its path): a new, empty file next to the report. It
    gets the permissions any newly created file gets, as the report file
    always did (unlike tempfile.mkstemp, which makes it private to the user)."""
    for _ in range(100):
        candidate = os.path.join(folder, f".{name}.{os.urandom(6).hex()}.tmp")
        try:
            return open(candidate, "x", encoding="utf-8"), candidate
        except FileExistsError:
            continue
    raise FileExistsError(f"no free name for a temporary file next to {name}")


def _write_failure_message(args, path: str, exc: BaseException) -> str:
    """The error for a report that could not be written. It never contains
    any part of the report. After a live run with --save-facts it says how
    to rebuild the report from the facts that were saved."""
    if isinstance(exc, _OutputRefusedError):
        message = str(exc)
    else:
        message = f"cannot write --output {path}: {getattr(exc, 'strerror', None) or exc}"
    saved_facts = getattr(args, "save_facts", None)
    if saved_facts:
        message += (f"; the facts were saved to {saved_facts}, so the report can be rebuilt "
                    f"from them with --facts {saved_facts} (no new collection needed)")
    return message


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
    if output_path is None:
        print(output)
        return 0
    try:
        _write_report(output_path, output + "\n", replace=not _refuses_existing_output(args))
    except (_OutputRefusedError, OSError) as exc:
        print(f"error: {_write_failure_message(args, output_path, exc)}", file=sys.stderr)
        return 2
    print(f"Report written to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
