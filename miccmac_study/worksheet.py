"""Blank per-host manual worksheets (protocol sections 5 and 6).

    python -m miccmac_study worksheet --list-checks FILE --hosts H1,H2,... --out DIR
        [--miccmac-config FILE] [--study-config FILE]
        [--methodology cmmi [--methodology cisa-ztmm]]
        [--session-date YYYY-MM-DD] [--synthetic] [--overwrite]

Each sheet (formats.WORKSHEET_COLUMNS) has meta rows, one row per enabled
check in list-checks order, and one level row per methodology and scope. A
check row shows only what the assessor may see before the blind manual pass:
the check id, its property, its intent (the check's name) and its control
references. The sheet never carries a tool status, score, detail or evidence
string, query, policy threshold, level cutoff, CIS IG or FAIR value,
remediation text, or any other risk-register field (missing-data texts,
next-level hints, the SP 800-30 threat-source types and threat events). Its own instructions (the worksheet_format meta row) name
the protocol's verdict values, PASS, PARTIAL, FAIL, N/A and UNASSESSED, and
say how to fill each column.

Each level row states the levels the assessor may enter: the methodology's
full range, or, with --study-config, 1 up to the study's manual_max_level for
that methodology (study.yaml), so a level the analysis would reject cannot be
offered. With --study-config, --methodology defaults to the study's
methodologies, every one of them must get level rows, and every host must be
one of the study's hosts. When that configuration does not yet declare the
manual level rule the pre-hash lint checks levels against (level_rule.manual,
and level_rule.overall under the approved rule; decision 4), the command
says so in one note on stderr after writing the sheets (level_rule_note).

Check names and control references come from a stub-mode engine run: with no
facts every check returns its NOT_IMPLEMENTED placeholder, so no verdict
logic runs. If any check returns anything else, nothing is generated.

The generator leaves every judgment cell blank (verdicts, levels, pass
criteria, evidence, reasons, assessor, level rule) and never replaces a sheet
in which any of them has been filled in.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union

from miccmac.config import Config, ConfigError
from miccmac.engine import enabled_check_ids, run_assessment
from miccmac.metadata import MappingsError, load_raw_mappings
from miccmac.methodology import LEVEL_WORDS as METHODOLOGY_LEVEL_WORDS
from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY
from miccmac.model import PROPERTY_KEYS, Status

from miccmac_study.formats import (
    CONFIG_FILE,
    DEFAULT_INPUT_DRIVEN_PROPERTIES,
    LEVEL_RULE_APPROVED,
    LEVEL_SCOPES,
    META_FIELDS,
    OVERALL,
    OVERALL_EXCL,
    ROW_CHECK,
    ROW_LEVEL,
    ROW_META,
    WORKSHEET_COLUMNS,
    WORKSHEET_FORMAT,
    StudyConfig,
    StudyError,
    check_ids_fingerprint,
    parse_date,
    read_csv,
    utc_now_iso,
    validate_host_code,
    worksheet_name,
    write_csv,
)
from miccmac_study.ledger import load_config, parse_host_list

PathLike = Union[str, Path]

DEFAULT_METHODOLOGY = "cmmi"
# Target label for the stub-mode run; it never reaches a real host.
STUB_TARGET = "worksheet"

# One-line instruction shown in the description cell of each meta row. The
# worksheet_format row carries the instructions for the whole sheet; it
# names the protocol's verdict values (section 6), never a tool result.
META_HELP = {
    "worksheet_format": "Sheet format, set by the generator. How to fill each check row: in value, your "
                        "verdict: PASS, PARTIAL, FAIL, N/A (not applicable), or UNASSESSED with the reason "
                        "in unassessed_reason. In pass_criterion, what had to be true for a pass; in "
                        "evidence_procedure, the steps you followed; in procedure_source, the external "
                        "source of those steps (for example a CIS Benchmark audit step or vendor "
                        "documentation), or NONE when no external procedure exists; in evidence_notes, "
                        "what you observed. Each level row states the levels you may enter.",
    "host_code": "Opaque host code, set by the generator; do not change.",
    "session_date": "Session date, YYYY-MM-DD. The tool's --as-of uses the same date.",
    "assessor": "Who filled in this sheet.",
    "level_rule": "The manual level rule you applied (protocol section 6).",
    "methodologies": "Methodologies with level rows below, set by the generator; do not change.",
    "enabled_checks_fingerprint": "Fingerprint of the enabled check list, set by the generator; do not change.",
    "generated_at_utc": "When this blank sheet was generated (UTC), set by the generator.",
    "synthetic": "yes only for pipeline-test data, never for study data; set by the generator.",
}

# Meta values the generator fills in; the assessor has no reason to change them.
GENERATED_META = frozenset({
    "worksheet_format", "host_code", "methodologies", "enabled_checks_fingerprint",
    "generated_at_utc", "synthetic",
})
# Cells only the assessor fills in. A sheet with any of them filled is never replaced.
ENTRY_COLUMNS = ("value", "pass_criterion", "evidence_procedure", "procedure_source",
                 "evidence_notes", "unassessed_reason")

# How each methodology's ordinal positions are named in the level-row text.
_METHODOLOGY_WORDS = METHODOLOGY_LEVEL_WORDS   # shared with the risk register's next-level hints
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class StubModeError(StudyError):
    """With no facts a check returned something other than its NOT_IMPLEMENTED
    stub, so its verdict logic ran; its output must not reach a worksheet."""


@dataclass(frozen=True)
class CheckInfo:
    """What a worksheet may show about one check."""
    check_id: str
    property_key: str
    name: str
    control_refs: Tuple[str, ...]


# ------------------------------------------------------------------ inputs
def read_list_checks(path: PathLike) -> List[str]:
    """The enabled check ids from a `miccmac list-checks --format json` file:
    a non-empty JSON list of unique, non-empty strings, kept in file order.
    UTF-8 (with or without a BOM) and UTF-16 files are accepted, since a
    PowerShell redirect may save either."""
    path = Path(path)
    try:
        data = json.loads(path.read_bytes())
    except OSError as exc:
        raise StudyError(f"cannot read list-checks file {path}: {exc}") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise StudyError(f"list-checks file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise StudyError(f"list-checks file {path} must be a non-empty JSON list of check ids")
    if not all(isinstance(item, str) and item.strip() == item and item for item in data):
        raise StudyError(f"list-checks file {path} must contain only non-empty check-id strings")
    duplicates = sorted({item for item in data if data.count(item) > 1})
    if duplicates:
        raise StudyError(f"list-checks file {path} repeats check id(s): {', '.join(duplicates)}")
    return list(data)


def load_miccmac_config(path: Optional[PathLike]) -> Config:
    """A miccmac Config from a YAML file, or the default Config when no path is given."""
    if path is None:
        return Config()
    try:
        return Config.from_file(path)
    except ConfigError as exc:
        raise StudyError(f"cannot load miccmac config: {exc}") from exc


def _session_date(raw: Optional[str]) -> Optional[str]:
    if raw is None or not str(raw).strip():
        return None
    text = str(raw).strip()
    try:
        if not _DATE_RE.fullmatch(text):
            raise ValueError
        return dt.date.fromisoformat(text).isoformat()
    except ValueError:
        raise StudyError(f"session date {raw!r} must be a YYYY-MM-DD date") from None


def _methodology_list(names: Optional[Sequence[str]]) -> List[str]:
    """The methodologies for level rows, in the order given, without repeats."""
    chosen: List[str] = []
    for name in names or [DEFAULT_METHODOLOGY]:
        if name not in METHODOLOGY_REGISTRY:
            raise StudyError(f"unknown methodology {name!r}; use one of {', '.join(sorted(METHODOLOGY_REGISTRY))}")
        if name not in chosen:
            chosen.append(name)
    return chosen


# ------------------------------------------------------------------ check metadata (stub mode)
def stub_check_info(config: Optional[Config] = None) -> Dict[str, CheckInfo]:
    """Id, property, name and control references of every check, built-in and
    custom, in report order, read from an engine run with no facts.

    The run uses the config's custom checks but none of its exclusions, so
    every check (including excluded ones) must come back as its
    NOT_IMPLEMENTED stub; anything else raises StubModeError."""
    stub_config = Config(custom_checks_dir=config.custom_checks_dir if config else None)
    try:
        assessment = run_assessment(STUB_TARGET, context={}, config=stub_config)
    except (ConfigError, MappingsError) as exc:
        raise StudyError(f"cannot load the miccmac checks: {exc}") from exc
    except Exception as exc:  # a custom check that cannot run without facts
        raise StubModeError(
            f"the stub-mode run (no facts) raised {type(exc).__name__}: {exc}; no worksheet was written"
        ) from exc

    info: Dict[str, CheckInfo] = {}
    not_stub: List[str] = []
    for prop in assessment.properties:
        for check in prop.checks:
            if check.status != Status.NOT_IMPLEMENTED:
                not_stub.append(check.check_id)
            if check.check_id in info:
                raise StubModeError(f"check id {check.check_id} appears twice in the stub-mode run")
            info[check.check_id] = CheckInfo(
                check_id=check.check_id,
                property_key=prop.key,
                name=check.name,
                control_refs=tuple(check.control_refs or ()),
            )
    if not_stub:
        raise StubModeError(
            "with no facts every check must return its NOT_IMPLEMENTED stub, but "
            f"{', '.join(sorted(not_stub))} returned something else; no worksheet was written, "
            "because a check that runs its verdict logic without facts could leak into the sheet"
        )
    return info


def validate_check_ids(ids: Sequence[str], known: Dict[str, CheckInfo], list_path: PathLike,
                       config: Optional[Config] = None, config_path: Optional[PathLike] = None) -> None:
    """Every id must be a known check. With a miccmac config, the list must
    also be exactly that config's enabled checks, in miccmac's order, so the
    assessor and the tool get the same check set."""
    unknown = [check_id for check_id in ids if check_id not in known]
    if unknown:
        hint = "" if config_path else " (custom checks need --miccmac-config)"
        raise StudyError(f"{list_path} names unknown check id(s): {', '.join(unknown)}{hint}")
    if config is None:
        return
    try:
        expected = enabled_check_ids(config)
    except (ConfigError, MappingsError) as exc:
        raise StudyError(f"cannot list the enabled checks of {config_path}: {exc}") from exc
    if list(ids) == expected:
        return
    parts = []
    missing = [check_id for check_id in expected if check_id not in ids]
    extra = [check_id for check_id in ids if check_id not in expected]
    if missing:
        parts.append(f"missing {', '.join(missing)}")
    if extra:
        parts.append(f"not enabled by the config: {', '.join(extra)}")
    if not parts:
        parts.append("same ids in a different order")
    raise StudyError(
        f"{list_path} does not match the enabled checks of {config_path} ({'; '.join(parts)}); "
        f"regenerate it with 'python -m miccmac list-checks --config {config_path} --format json'"
    )


def property_titles() -> Dict[str, str]:
    """Property key -> title from the control mappings (falls back to the key)."""
    titles = {key: key.capitalize() for key in PROPERTY_KEYS}
    try:
        mappings = load_raw_mappings()
    except MappingsError:
        return titles
    for prop in mappings.get("properties") or []:
        if isinstance(prop, dict) and prop.get("key") in titles and isinstance(prop.get("title"), str):
            titles[prop["key"]] = prop["title"]
    return titles


# ------------------------------------------------------------------ rows
def level_description(methodology: str, scope: str, titles: Dict[str, str],
                      max_level: Optional[int] = None) -> str:
    """Instruction for one level row: the levels the assessor may enter
    (1 to `max_level`, default the methodology's highest) and their names."""
    label, unit = _METHODOLOGY_WORDS.get(methodology, (methodology.upper(), "level"))
    names = METHODOLOGY_REGISTRY[methodology].levels
    top = len(names) if max_level is None else max(1, min(int(max_level), len(names)))
    allowed = f"whole number 1-{top}, or UNASSESSED with a reason in unassessed_reason"
    if top < len(names):
        allowed += f"; the study configuration allows {unit}s up to {top}"
    scale = (f"{unit.capitalize()}s: "
             + ", ".join(f"{i} {name}" for i, name in enumerate(names[:top], start=1)) + ".")
    if scope == OVERALL:
        what = f"Manual {label} {unit} overall ({allowed})."
    elif scope == OVERALL_EXCL:
        left_out = " and ".join(titles.get(key, key) for key in DEFAULT_INPUT_DRIVEN_PROPERTIES)
        what = f"Optional: manual {label} {unit} overall excluding {left_out} ({allowed}; may stay blank)."
    else:
        what = f"Manual {label} {unit} for {titles.get(scope, scope)} ({allowed})."
    return f"{what} {scale}"


def worksheet_rows(host: str, checks: Sequence[CheckInfo], methodologies: Sequence[str],
                   session_date: Optional[str], synthetic: bool, generated_at: str,
                   titles: Dict[str, str],
                   max_levels: Optional[Dict[str, int]] = None) -> List[Dict[str, str]]:
    """All rows of one blank sheet: meta rows, check rows, level rows.
    `max_levels` (methodology -> highest level the study allows) narrows the
    range each level row states."""
    max_levels = max_levels or {}
    meta_values = {
        "worksheet_format": WORKSHEET_FORMAT,
        "host_code": validate_host_code(host),
        "session_date": session_date or "",
        "assessor": "",
        "level_rule": "",
        "methodologies": ";".join(methodologies),
        "enabled_checks_fingerprint": check_ids_fingerprint([c.check_id for c in checks]),
        "generated_at_utc": generated_at,
        "synthetic": "yes" if synthetic else "no",
    }
    rows = [
        {"row_type": ROW_META, "item": name, "value": meta_values.get(name, ""),
         "description": META_HELP.get(name, "")}
        for name in META_FIELDS
    ]
    rows.extend(
        {"row_type": ROW_CHECK, "item": check.check_id, "property": check.property_key,
         "description": check.name, "control_refs": "; ".join(check.control_refs)}
        for check in checks
    )
    rows.extend(
        {"row_type": ROW_LEVEL, "item": methodology, "property": scope,
         "description": level_description(methodology, scope, titles, max_levels.get(methodology))}
        for methodology in methodologies
        for scope in LEVEL_SCOPES
    )
    return rows


# ------------------------------------------------------------------ overwrite protection
def _same_date(raw: str, session_date: Optional[str]) -> bool:
    if session_date is None:
        return False
    try:
        return parse_date(raw) == dt.date.fromisoformat(session_date)
    except StudyError:
        return False


def worksheet_entry(path: PathLike, session_date: Optional[str] = None) -> Optional[str]:
    """Why the existing sheet at `path` counts as filled in, or None while it
    is still blank. Blank means: no value or judgment cell filled in any
    check or level row, no assessor or level rule, no content in a column
    the generator does not write, and a session date that is blank or equal
    to `session_date` (the date this run would write)."""
    path = Path(path)
    if path.stat().st_size == 0:
        return None
    try:
        rows = read_csv(path, WORKSHEET_COLUMNS)
    except StudyError:
        return "it is not a worksheet this generator can read"
    for row in rows:
        extra = [name for name, value in row.items() if value and name not in WORKSHEET_COLUMNS]
        if extra:
            return f"column {extra[0]} has content"
        row_type = row["row_type"].lower()
        item = row["item"] or "?"
        if row_type == ROW_META:
            filled = [name for name in ENTRY_COLUMNS[1:] if row[name]]
            if filled:
                return f"meta {item}: {filled[0]} is filled in"
            if item in GENERATED_META or not row["value"]:
                continue
            if item == "session_date":
                if _same_date(row["value"], session_date):
                    continue
                return "meta session_date is filled in and differs from --session-date"
            return f"meta {item} is filled in"
        filled = [name for name in ENTRY_COLUMNS if row[name]]
        if filled:
            return f"{row_type or 'row'} {item}: {filled[0]} is filled in"
    return None


def _guard_existing(path: Path, overwrite: bool, session_date: Optional[str]) -> None:
    if not path.exists():
        return
    if not path.is_file():
        raise StudyError(f"{path} exists and is not a file")
    if not overwrite:
        raise StudyError(f"{path} already exists; refusing to overwrite it "
                         f"(--overwrite replaces a sheet only while it is still blank)")
    reason = worksheet_entry(path, session_date)
    if reason:
        raise StudyError(f"{path} has entries ({reason}); refusing to overwrite it. "
                         f"If it is really blank, delete it yourself and run again")


def _study_settings(study_config: Optional[PathLike], hosts: Sequence[str],
                    methodologies: Optional[Sequence[str]]) -> Tuple[List[str], Dict[str, int]]:
    """The methodologies for level rows and the highest level each may
    take. Without a study configuration: the methodologies given (default
    CMMI) at their full range. With one: the study's methodologies unless
    others are given (they must include every one of the study's), its
    manual_max_level for each, and every host must be one of its hosts."""
    if study_config is None:
        return _methodology_list(methodologies), {}
    study: StudyConfig = load_config(study_config)
    unknown = [host for host in hosts if host not in study.hosts]
    if unknown:
        raise StudyError(f"{', '.join(unknown)} not in the hosts of {study_config} "
                         f"({', '.join(study.hosts)}); no worksheet was written")
    chosen = _methodology_list(methodologies if methodologies else study.methodologies)
    missing = [name for name in study.methodologies if name not in chosen]
    if missing:
        raise StudyError(f"the study analyses {', '.join(study.methodologies)}, so the sheet needs level rows "
                         f"for {', '.join(missing)} too (add --methodology, or leave it out to use the study's)")
    return chosen, {name: study.manual_max(name) for name in chosen}


def level_rule_note(study: StudyConfig, name: str = CONFIG_FILE) -> Optional[str]:
    """The note `worksheet --study-config` prints (stderr) when the study
    configuration (file name `name`) does not yet declare the manual level
    rule the pre-hash lint checks typed levels against (decision 4), or
    None when it does: no level_rule.manual, or manual approved without a
    level_rule.overall for the overall levels."""
    if study.manual_level_rule is None:
        return (f"note: {name} declares no level_rule.manual yet (decision 4); ledger record will refuse to hash a "
                "filled worksheet until it does")
    if study.manual_level_rule == LEVEL_RULE_APPROVED and study.overall_rule is None:
        return (f"note: {name} declares no level_rule.overall, which the approved manual rule needs for the overall "
                "levels (decision 4); ledger record will refuse to hash a filled worksheet until it does")
    return None


# ------------------------------------------------------------------ library entry point
def generate_worksheets(list_checks: PathLike, hosts: Sequence[str], out_dir: PathLike,
                        miccmac_config: Optional[PathLike] = None,
                        methodologies: Optional[Sequence[str]] = None,
                        session_date: Optional[str] = None, synthetic: bool = False,
                        overwrite: bool = False, study_config: Optional[PathLike] = None) -> List[Path]:
    """Write <out_dir>/<H>-worksheet.csv for each host and return the paths.
    Every sheet is checked before any is written, so a refusal changes
    nothing. With `study_config` (study.yaml), the level rows state the
    study's allowed level range (see _study_settings)."""
    hosts = [validate_host_code(host) for host in hosts]
    if not hosts:
        raise StudyError("no host codes given")
    duplicates = sorted({host for host in hosts if hosts.count(host) > 1})
    if duplicates:
        raise StudyError(f"duplicate host code(s): {', '.join(duplicates)}")
    chosen, max_levels = _study_settings(study_config, hosts, methodologies)
    session = _session_date(session_date)

    config = load_miccmac_config(miccmac_config)
    known = stub_check_info(config)
    ids = read_list_checks(list_checks)
    validate_check_ids(ids, known, list_checks,
                       config=config if miccmac_config is not None else None,
                       config_path=miccmac_config)
    checks = [known[check_id] for check_id in ids]
    titles = property_titles()

    out_dir = Path(out_dir)
    targets = [(host, out_dir / worksheet_name(host)) for host in hosts]
    for _, path in targets:
        _guard_existing(path, overwrite, session)

    generated_at = utc_now_iso()
    written = []
    for host, path in targets:
        rows = worksheet_rows(host, checks, chosen, session, synthetic, generated_at, titles, max_levels)
        try:
            written.append(write_csv(path, WORKSHEET_COLUMNS, rows, overwrite=path.exists()))
        except OSError as exc:
            raise StudyError(f"cannot write {path}: {exc}") from exc
    return written


# ------------------------------------------------------------------ command line
def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--list-checks", required=True, metavar="FILE",
                        help="JSON list from 'python -m miccmac list-checks [--config <miccmac config>] --format json'.")
    parser.add_argument("--hosts", required=True, metavar="H1,H2,...",
                        help="Comma-separated opaque host codes.")
    parser.add_argument("--out", required=True, metavar="DIR",
                        help="Folder for the <H>-worksheet.csv files (created if missing).")
    parser.add_argument("--miccmac-config", default=None, metavar="FILE",
                        help="The miccmac Config YAML used for list-checks (needed for custom checks; "
                             "the list must then match its enabled checks exactly).")
    parser.add_argument("--study-config", default=None, metavar="FILE",
                        help="The study.yaml: each level row then states the study's allowed range "
                             "(manual_max_level), --methodology defaults to the study's methodologies, and "
                             "every host must be one of the study's hosts. A note on stderr says when it "
                             "declares no manual level rule yet.")
    parser.add_argument("--methodology", action="append", default=None,
                        choices=sorted(METHODOLOGY_REGISTRY),
                        help=f"Add level rows for a methodology (repeatable; default {DEFAULT_METHODOLOGY}, "
                             "or the study's methodologies with --study-config).")
    parser.add_argument("--session-date", default=None, metavar="YYYY-MM-DD",
                        help="Pre-fill the session date (otherwise the assessor writes it in).")
    parser.add_argument("--synthetic", action="store_true",
                        help="Mark the sheets as synthetic pipeline-test data.")
    parser.add_argument("--overwrite", action="store_true",
                        help="Replace existing sheets, but only ones that are still blank.")


def run(args: argparse.Namespace) -> int:
    paths = generate_worksheets(
        list_checks=args.list_checks,
        hosts=parse_host_list(args.hosts),
        out_dir=args.out,
        miccmac_config=args.miccmac_config,
        methodologies=args.methodology,
        session_date=args.session_date,
        synthetic=args.synthetic,
        overwrite=args.overwrite,
        study_config=args.study_config,
    )
    for path in paths:
        print(path)
    if args.study_config is not None:
        note = level_rule_note(load_config(args.study_config), Path(args.study_config).name)
        if note:
            print(note, file=sys.stderr)
    return 0
