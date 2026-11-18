"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Risk-register review sheets (protocol section 7), generated only after
every manual worksheet is hashed.

    python -m miccmac_study register-sheet --study-dir DIR [--config FILE]
        [--force-before-unseal --reason TEXT] [--overwrite]

The register shows the tool's findings, so it stays sealed until the blind
manual passes are over. The only gate is ledger.seal_status: it waits for
every host of the study (in the configuration, in DIR/study.yaml or a
version of it in force at or after the first tool run, in a ledger row, or
named by a worksheet or tool-output file) until that host's
worksheets/<H>-worksheet.csv has a worksheet row in DIR/ledger.csv and still
matches the first one, and while DIR/study.yaml differs from its latest
ledger row. A host leaves the study only through 'ledger withdraw'; a
--config listing fewer hosts never opens the seal. No
tool output is opened before that check passes. Each run that writes sheets
first appends a seal-opening row to the ledger (ledger.record_seal_opened:
"seal opened by register-sheet: hosts ...; withdrawn: ..."), after every
check that can still refuse, so the ledger shows when the tool's findings
became visible. --force-before-unseal (with --reason) overrides a closed
gate and appends only its own row saying so.

For each host of the configuration that is not withdrawn it reads
DIR/outputs/<H>-<primary methodology>.json and writes

    DIR/register/<H>-register-review.csv  one row per register entry, in the
                                          tool's order, with accurate,
                                          actionable, prioritized and reason
                                          left blank for the researcher
    DIR/register/<H>-missed-gaps.csv      gap rows 1-5, blank apart from the
                                          host code and gap number

It prints only the paths written, and never replaces a sheet in which any
judgment cell has been filled in.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Union

from miccmac_study.formats import (
    CONFIG_FILE,
    LEDGER_FILE,
    MISSED_GAPS_COLUMNS,
    OUTPUTS_DIR,
    REGISTER_DIR,
    REGISTER_REVIEW_COLUMNS,
    StudyError,
    load_tool_output,
    missed_gaps_name,
    read_csv,
    register_review_name,
    tool_output_name,
    write_csv,
)
from miccmac_study.ledger import (  # FORCE_NOTE_PREFIX is re-exported for existing imports
    FORCE_NOTE_PREFIX,
    NO_WORKSHEET_YET,
    STUDY_HOST_CODE,
    WORKSHEET_NOT_HASHED,
    SealStatus,
    load_config,
    record_forced_unseal,
    record_seal_opened,
    seal_status,
    worksheet_problems,
)

PathLike = Union[str, Path]

MISSED_GAP_ROWS = 5
# Cells only the researcher fills in.
REVIEW_JUDGMENT_COLUMNS = ("accurate", "actionable", "prioritized", "reason")
MISSED_GAP_ENTRY_COLUMNS = ("check_id", "description", "evidence")


class SealedError(StudyError):
    """The register sheets are still sealed: not every worksheet is hashed and unchanged."""


@dataclass(frozen=True)
class HostSheets:
    """The two sheets for one host, ready to write."""
    host: str
    review_path: Path
    review_rows: List[Dict[str, object]]
    gaps_path: Path
    gaps_rows: List[Dict[str, object]]


# ------------------------------------------------------------------ rows
def review_row(host: str, entry_no: int, entry: dict) -> Dict[str, object]:
    """One review-sheet row: the register entry as the tool wrote it, with the
    judgment columns blank."""
    return {
        "host_code": host,
        "entry_no": entry_no,
        "check_id": entry.get("check_id"),
        "property": entry.get("property_key"),
        "name": entry.get("name"),
        "tool_status": entry.get("status"),
        "cis_ig": entry.get("cis_ig"),
        "fair_frequency": entry.get("fair_frequency"),
        "fair_magnitude": entry.get("fair_magnitude"),
        "risk_rating": entry.get("risk_rating"),
        "detail": entry.get("detail"),
        "recommended_fix": entry.get("remediation"),
        "accurate": "",
        "actionable": "",
        "prioritized": "",
        "reason": "",
    }


def missed_gap_rows(host: str, count: int = MISSED_GAP_ROWS) -> List[Dict[str, object]]:
    """Numbered blank rows for gaps found manually that have no register entry."""
    return [{"host_code": host, "gap_no": number} for number in range(1, count + 1)]


def host_sheets(study_dir: Path, host: str, methodology: str) -> HostSheets:
    """Read one host's tool output and build both sheets (nothing is written)."""
    path = study_dir / OUTPUTS_DIR / tool_output_name(host, methodology)
    output = load_tool_output(path)
    if output.risk_register is None:
        raise StudyError(f"{host}: {path} has no risk_register (run the tool with --risk-register)")
    rows = []
    for number, entry in enumerate(output.risk_register, start=1):
        if not isinstance(entry, dict) or not entry.get("check_id"):
            raise StudyError(f"{host}: risk register entry {number} in {path} is malformed")
        rows.append(review_row(host, number, entry))
    register_dir = study_dir / REGISTER_DIR
    return HostSheets(
        host=host,
        review_path=register_dir / register_review_name(host),
        review_rows=rows,
        gaps_path=register_dir / missed_gaps_name(host),
        gaps_rows=missed_gap_rows(host),
    )


# ------------------------------------------------------------------ overwrite protection
def _first_entry(path: Path, columns: Sequence[str], entry_columns: Sequence[str],
                 number_column: str) -> Optional[str]:
    """Why the sheet at `path` counts as filled in, or None while every entry
    cell (and every column this command does not write) is blank."""
    if path.stat().st_size == 0:
        return None
    try:
        rows = read_csv(path, entry_columns)
    except StudyError:
        return "it is not a sheet this command can read"
    for row in rows:
        for name, value in row.items():
            if value and (name in entry_columns or name not in columns):
                return f"row {row.get(number_column) or '?'}: {name} is filled in"
    return None


def review_sheet_entry(path: PathLike) -> Optional[str]:
    """Why a register-review sheet counts as filled in, or None while blank."""
    return _first_entry(Path(path), REGISTER_REVIEW_COLUMNS, REVIEW_JUDGMENT_COLUMNS, "entry_no")


def missed_gaps_entry(path: PathLike) -> Optional[str]:
    """Why a missed-gaps sheet counts as filled in, or None while blank."""
    return _first_entry(Path(path), MISSED_GAPS_COLUMNS, MISSED_GAP_ENTRY_COLUMNS, "gap_no")


def _guard_existing(path: Path, overwrite: bool, entry: Callable[[PathLike], Optional[str]]) -> None:
    if not path.exists():
        return
    if not path.is_file():
        raise StudyError(f"{path} exists and is not a file")
    if not overwrite:
        raise StudyError(f"{path} already exists; refusing to overwrite it "
                         f"(--overwrite replaces a sheet only while its judgment cells are blank)")
    reason = entry(path)
    if reason:
        raise StudyError(f"{path} has entries ({reason}); refusing to overwrite it")


# ------------------------------------------------------------------ library entry point
def sealed_hosts(study_dir: PathLike, hosts: Sequence[str]) -> Dict[str, str]:
    """host -> why its worksheet does not yet count as hashed and unchanged,
    for the given hosts only (empty when none). The gate itself is
    ledger.seal_status, which also covers hosts outside `hosts`."""
    ledger = Path(study_dir) / LEDGER_FILE
    return {host: why for host, why in worksheet_problems(ledger, hosts).items() if why}


def sealed_message(status: SealStatus, ledger: PathLike) -> str:
    """The refusal: every problem with its own advice, then the commands
    that fit those cases, then the override. It names hosts, files and
    hashes only, never a tool result."""
    details = "; ".join(f"{host} ({why})" for host, why in status.problems)
    reasons = [why for host, why in status.problems if host != STUDY_HOST_CODE]
    commands = []
    if any(why.startswith(WORKSHEET_NOT_HASHED) for why in reasons):
        commands.append(f"python -m miccmac_study ledger record --ledger {ledger} --host H --kind worksheet "
                        "worksheets/H-worksheet.csv")
    if any(why.startswith((NO_WORKSHEET_YET, WORKSHEET_NOT_HASHED)) for why in reasons):
        commands.append(f"python -m miccmac_study ledger withdraw --ledger {ledger} --host H --reason TEXT")
    listed = f" Commands: {'; '.join(commands)}." if commands else ""
    return (f"register sheets stay sealed until every worksheet is hashed and unchanged; not yet: {details}."
            f"{listed} To issue the sheets anyway, use --force-before-unseal --reason TEXT, which the ledger "
            "records.")


def generate_register_sheets(study_dir: PathLike, config_path: Optional[PathLike] = None,
                             force_reason: Optional[str] = None,
                             overwrite: bool = False) -> List[Path]:
    """Write both sheets for every host of the study configuration that is
    not withdrawn, and return the paths written. Everything is checked
    before anything is written. Just before the first sheet is written, a
    ledger row records the opening: the seal-opening row
    (ledger.record_seal_opened) when the seal is open, or, with
    `force_reason` and the seal still closed, the row that records the
    override and why (FORCE_NOTE_PREFIX) instead."""
    study_dir = Path(study_dir)
    config_path = Path(config_path) if config_path is not None else study_dir / CONFIG_FILE
    config = load_config(config_path)
    if force_reason is not None:
        force_reason = " ".join(force_reason.split())
        if not force_reason:
            raise StudyError("--force-before-unseal needs a non-empty --reason")

    ledger = study_dir / LEDGER_FILE
    status = seal_status(study_dir, config, ledger_path=ledger)
    if not status.ok and force_reason is None:
        raise SealedError(sealed_message(status, ledger))

    hosts = [host for host in config.hosts if host not in status.withdrawn]
    if not hosts:
        raise StudyError(f"every host in {config_path} is withdrawn in the ledger; there are no sheets to generate")
    sheets: List[HostSheets] = []
    problems: List[str] = []
    for host in hosts:
        try:
            sheets.append(host_sheets(study_dir, host, config.primary_methodology))
        except StudyError as exc:
            problems.append(str(exc))
    if problems:
        raise StudyError("; ".join(problems))
    for sheet in sheets:
        _guard_existing(sheet.review_path, overwrite, review_sheet_entry)
        _guard_existing(sheet.gaps_path, overwrite, missed_gaps_entry)

    if not status.ok:
        record_forced_unseal(ledger, config_path, force_reason)
    else:
        record_seal_opened(ledger, "register-sheet", config_path, status)

    written = []
    for sheet in sheets:
        for path, columns, rows in ((sheet.review_path, REGISTER_REVIEW_COLUMNS, sheet.review_rows),
                                    (sheet.gaps_path, MISSED_GAPS_COLUMNS, sheet.gaps_rows)):
            try:
                written.append(write_csv(path, columns, rows, overwrite=True))
            except OSError as exc:
                raise StudyError(f"cannot write {path}: {exc}") from exc
    return written


# ------------------------------------------------------------------ command line
def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--study-dir", required=True, metavar="DIR",
                        help="The study folder (study.yaml, ledger.csv, outputs/, register/).")
    parser.add_argument("--config", default=None, metavar="FILE",
                        help="Study configuration to use instead of DIR/study.yaml (the primary methodology "
                             "and the hosts to write sheets for; the seal still waits for every host of the "
                             "study).")
    parser.add_argument("--force-before-unseal", action="store_true",
                        help="Generate the sheets even though not every worksheet is hashed "
                             "(needs --reason; recorded in the ledger).")
    parser.add_argument("--reason", default=None, metavar="TEXT",
                        help="Why the sheets are forced before unsealing.")
    parser.add_argument("--overwrite", action="store_true",
                        help="Replace existing sheets, but only ones whose judgment cells are blank.")


def run(args: argparse.Namespace) -> int:
    if args.reason is not None and not args.force_before_unseal:
        raise StudyError("--reason is only used with --force-before-unseal")
    if args.force_before_unseal and not (args.reason or "").strip():
        raise StudyError("--force-before-unseal requires --reason TEXT")
    paths = generate_register_sheets(
        args.study_dir,
        config_path=args.config,
        force_reason=args.reason if args.force_before_unseal else None,
        overwrite=args.overwrite,
    )
    for path in paths:
        print(path)
    return 0
