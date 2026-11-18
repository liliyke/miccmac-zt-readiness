"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

SHA-256 ledger of study files (protocol section 5), and the seal that keeps
tool results hidden until every host's worksheet is hashed.

    python -m miccmac_study ledger record --ledger FILE --host H --kind KIND [--note TEXT]
        [--config FILE] [--force] PATH [PATH ...]
    python -m miccmac_study ledger verify --ledger FILE
    python -m miccmac_study ledger status --ledger FILE [--hosts H1,H2,...]
    python -m miccmac_study ledger withdraw --ledger FILE --host H --reason TEXT [--config FILE]

The ledger (formats.LEDGER_COLUMNS) only grows: each `record` call appends
one row per file with the time, host code, kind, path, SHA-256, size and an
optional note. A file inside the ledger's folder is recorded relative to that
folder, so the study folder can be moved or copied as a whole. `record` also
keeps a copy of each file in <ledger folder>/ledger-archive/<sha256><suffix>
(never replaced, and checked against the hash), so a hashed file that is
changed by accident can be restored byte for byte.

`record --kind worksheet` first lints each worksheet against the study
configuration (--config, default study.yaml next to the ledger) with
agreement.lint_worksheet: blank or unreadable verdicts and levels, levels
outside the study's range or not following the declared manual level rule,
the host code, the synthetic flag, and a file that is not
worksheets/<H>-worksheet.csv. It prints each finding and records nothing
while there is one, unless --force is given; the note then starts
"recorded despite lint findings: " and lists them. The lint reads only the
worksheet and the configuration. The library function record_files never
lints.

`verify` re-hashes every recorded file and prints one line per row:

    OK          the file still has its recorded hash
    CHANGED     the file differs from its recorded hash
    MISSING     the file is gone or cannot be read
    SUPERSEDED  a CHANGED row that a later, still-matching row for the same
                file and kind replaced in time (see row_states)

and adds OUT OF ORDER to a row dated strictly earlier than a row above it
(rows in the same second are in order). It exits 0 only when every row is
OK or SUPERSEDED and none is OUT OF ORDER. Rows of the kinds in FROZEN_KINDS
(worksheets, tool outputs, facts, register sheets) are never SUPERSEDED: once
hashed they never change, and re-recording an edited file does not hide the
edit, because the earlier row keeps reporting CHANGED.

`withdraw` records, with a dated row, that a host will not be assessed. It is
the only way a host leaves the seal (seal_status): the seal waits for every
host named in the study configuration, in DIR/study.yaml, in a ledger row, or
in a worksheet or tool-output file name, until its worksheet is hashed and
unchanged. Editing study.yaml or passing another configuration never opens it.

Nothing here prints file contents or any tool result.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY

from miccmac_study.formats import (
    CONFIG_FILE,
    LEDGER_COLUMNS,
    LEDGER_FILE,
    LEDGER_KINDS,
    OUTPUTS_DIR,
    WORKSHEETS_DIR,
    LedgerRow,
    StudyConfig,
    StudyError,
    ledger_relpath,
    load_study_config,
    parse_utc_timestamp,
    read_ledger,
    resolve_ledger_path,
    sha256_file,
    utc_now_iso,
    validate_host_code,
    worksheet_name,
)

# States reported by verify for each row.
OK = "OK"
CHANGED = "CHANGED"
MISSING = "MISSING"
SUPERSEDED = "SUPERSEDED"

# Host code for rows about the whole study rather than one host: the
# protocol, study.yaml, the list-checks file, register sheets forced before
# unsealing.
STUDY_HOST_CODE = "STUDY"

WORKSHEET_KIND = "worksheet"
INPUT_KIND = "input"
FACTS_KIND = "facts"
TOOL_OUTPUT_KIND = "tool-output"
PROTOCOL_KIND = "protocol"
# Kinds whose files never change once hashed: a CHANGED row of these kinds
# stays CHANGED whatever is recorded later.
FROZEN_KINDS = ("worksheet", "tool-output", "facts", "register-review", "missed-gaps")

# Note of the ledger row register-sheet appends when it is forced before
# every worksheet is hashed (register_sheet imports it from here).
FORCE_NOTE_PREFIX = "register sheets generated before every worksheet was hashed: "
# Note of a withdrawal row (kind protocol): "withdrawn: <reason>".
WITHDRAWN_NOTE_PREFIX = "withdrawn: "

# Folder next to the ledger holding a copy of every recorded file.
ARCHIVE_DIR = "ledger-archive"

# How seal_status starts each problem text, so callers can give advice per case.
NO_WORKSHEET_YET = "no worksheet yet"
WORKSHEET_NOT_HASHED = "worksheet not hashed"
HASHED_WORKSHEET_MISSING = "hashed worksheet is missing"
WORKSHEET_CHANGED = "worksheet changed after it was hashed"
RESTORE_ADVICE = "restore the original bytes from your commit, e-mail or ledger-archive copy"
NO_REHASH = "a changed worksheet cannot be re-hashed"
WITHDRAW_ADVICE = "if this host will not be assessed, record that with 'ledger withdraw'"

PathLike = Union[str, Path]

_WORKSHEET_SUFFIX = "-worksheet.csv"
_FACTS_SUFFIX = "-facts.json"


# ------------------------------------------------------------------ small helpers
def parse_host_list(raw: Optional[str]) -> List[str]:
    """Host codes from a comma-separated option value such as 'H1,H2,H3'.
    Spaces and empty items are ignored; duplicates are refused."""
    hosts = [part.strip() for part in (raw or "").split(",") if part.strip()]
    if not hosts:
        raise StudyError("no host codes given; use for example --hosts H1,H2,H3")
    for host in hosts:
        validate_host_code(host)
    duplicates = sorted({host for host in hosts if hosts.count(host) > 1})
    if duplicates:
        raise StudyError(f"duplicate host code(s): {', '.join(duplicates)}")
    return hosts


def is_study_code(code: Optional[str]) -> bool:
    """True for the study-wide host code (STUDY, in any letter case)."""
    return (code or "").strip().upper() == STUDY_HOST_CODE


def row_kind(row: LedgerRow) -> str:
    """A row's kind as compared everywhere: trimmed, lower case."""
    return (row.kind or "").strip().lower()


def file_key(path: PathLike) -> str:
    """How two paths are compared: resolved, and case-folded where the file
    system ignores case (os.path.normcase), as agreement matches them."""
    return os.path.normcase(str(Path(path).resolve()))


def path_key(ledger: PathLike, recorded: str) -> str:
    """file_key of the file a ledger row refers to ('' for a blank path)."""
    if not (recorded or "").strip():
        return ""
    return os.path.normcase(str(resolve_ledger_path(ledger, recorded)))


def worksheet_path(study_dir: PathLike, host: str) -> Path:
    """DIR/worksheets/<H>-worksheet.csv, the only file that counts as H's worksheet."""
    return Path(study_dir) / WORKSHEETS_DIR / worksheet_name(host)


def worksheet_rows(ledger: PathLike, rows: Sequence[LedgerRow], study_dir: PathLike,
                   host: str) -> List[LedgerRow]:
    """Rows of kind worksheet whose path resolves to DIR/worksheets/<H>-worksheet.csv
    (whatever host code they were recorded under), in ledger order."""
    target = file_key(worksheet_path(study_dir, host))
    return [row for row in rows if row_kind(row) == WORKSHEET_KIND and path_key(ledger, row.path) == target]


def is_withdrawal(row: LedgerRow) -> bool:
    """A withdrawal row: kind protocol with a note starting 'withdrawn: '."""
    return row_kind(row) == PROTOCOL_KIND and (row.note or "").startswith(WITHDRAWN_NOTE_PREFIX)


def withdrawn_hosts(rows: Sequence[LedgerRow]) -> Dict[str, Tuple[str, str]]:
    """host -> (recorded_at_utc, reason) of its first withdrawal row."""
    found: Dict[str, Tuple[str, str]] = {}
    for row in rows:
        code = (row.host_code or "").strip()
        if not is_withdrawal(row) or not code or is_study_code(code) or code in found:
            continue
        found[code] = (row.recorded_at_utc, row.note[len(WITHDRAWN_NOTE_PREFIX):].strip())
    return found


def load_config(path: PathLike) -> StudyConfig:
    """load_study_config, with a file that is not UTF-8 reported as a StudyError."""
    try:
        return load_study_config(path)
    except UnicodeDecodeError as exc:
        raise StudyError(f"cannot read study configuration {path}: save it as UTF-8 ({exc})") from None


def _time(raw: object) -> Optional[dt.datetime]:
    """A recorded UTC timestamp, or None when it is missing or unreadable."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return parse_utc_timestamp(raw)
    except StudyError:
        return None


def _valid_host(code: str) -> bool:
    try:
        validate_host_code(code)
    except StudyError:
        return False
    return True


def _hash_file(path: Path) -> str:
    try:
        return sha256_file(path)
    except OSError as exc:
        raise StudyError(f"cannot read {path}: {exc}") from exc


def _cells(row: LedgerRow, header: Sequence[str]) -> List[str]:
    """A ledger row as CSV cells in the order of `header` (extra columns blank)."""
    values = {
        "recorded_at_utc": row.recorded_at_utc,
        "host_code": row.host_code,
        "kind": row.kind,
        "path": row.path,
        "sha256": row.sha256,
        "bytes": str(row.bytes),
        "note": row.note,
    }
    return [values.get(name, "") for name in header]


def _existing_header(ledger: Path) -> Optional[List[str]]:
    """The header of an existing ledger, or None when there is no ledger yet
    (no file, or an empty one). Refuses a file that cannot safely be
    appended to: not UTF-8, or without the ledger columns."""
    if not ledger.exists():
        return None
    if not ledger.is_file():
        raise StudyError(f"ledger {ledger} is not a file")
    try:
        data = ledger.read_bytes()
    except OSError as exc:
        raise StudyError(f"cannot read ledger {ledger}: {exc}") from exc
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise StudyError(
            f"ledger {ledger} is not UTF-8 text; save it as 'CSV UTF-8' before recording more files"
        ) from None
    if not text.strip():
        return None
    first_row = next(csv.reader(io.StringIO(text, newline="")), [])
    header = [cell.strip() for cell in first_row]
    missing = [name for name in LEDGER_COLUMNS if name not in header]
    if missing:
        raise StudyError(f"ledger {ledger} is missing column(s): {', '.join(missing)}")
    return header


def _append_rows(ledger: Path, rows: Sequence[LedgerRow]) -> None:
    """Append rows to the ledger, creating it (UTF-8 with a BOM, like every
    other study CSV) when it does not exist yet. Appends never add a second
    BOM, follow the existing header's column order, and start on a new line
    even if the file was saved without a final line break."""
    header = _existing_header(ledger)
    try:
        if header is None:
            ledger.parent.mkdir(parents=True, exist_ok=True)
            with open(ledger, "w", encoding="utf-8-sig", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow(LEDGER_COLUMNS)
                writer.writerows(_cells(row, LEDGER_COLUMNS) for row in rows)
            return
        ends_with_newline = ledger.read_bytes().endswith((b"\n", b"\r"))
        with open(ledger, "a", encoding="utf-8", newline="") as fh:
            if not ends_with_newline:
                fh.write("\r\n")
            csv.writer(fh).writerows(_cells(row, header) for row in rows)
    except OSError as exc:
        raise StudyError(f"cannot write ledger {ledger}: {exc}") from exc


# ------------------------------------------------------------------ archive copies
def archive_path(ledger: PathLike, row: LedgerRow) -> Path:
    """Where `record` keeps the copy of a row's file:
    <ledger folder>/ledger-archive/<sha256><suffix of the recorded file>."""
    return Path(ledger).resolve().parent / ARCHIVE_DIR / f"{row.sha256}{PurePath(row.path).suffix}"


def _remove_quietly(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _check_existing_copy(target: Path, digest: str) -> None:
    try:
        existing = sha256_file(target) if target.is_file() else None
    except OSError:
        existing = None
    if existing != digest:
        raise StudyError(
            f"{target} already exists but does not hold the bytes its name stands for; it was left as it "
            f"is and nothing was recorded. Move it out of {ARCHIVE_DIR} (keep it: it may be evidence) and "
            "record again"
        )


def _archive_copy(ledger: Path, source: Path, row: LedgerRow) -> Path:
    """Copy `source` to archive_path(ledger, row) unless that copy exists
    already, and make sure the copy has the row's hash. Never replaces a file."""
    target = archive_path(ledger, row)
    if target.exists():
        _check_existing_copy(target, row.sha256)
        return target
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StudyError(f"cannot create {target.parent}: {exc}; nothing was recorded") from exc
    created = False
    try:
        with open(source, "rb") as src:
            with open(target, "xb") as dst:
                created = True
                shutil.copyfileobj(src, dst)
    except FileExistsError:
        _check_existing_copy(target, row.sha256)
        return target
    except OSError as exc:
        if created:
            _remove_quietly(target)
        raise StudyError(f"cannot copy {source} to {target}: {exc}; nothing was recorded") from exc
    try:
        copied = sha256_file(target)
    except OSError:
        copied = None
    if copied != row.sha256:
        _remove_quietly(target)
        raise StudyError(
            f"{source} changed while it was being recorded (its archive copy does not match the hash just "
            "taken); nothing was recorded. Close any program that is saving it and record it again"
        )
    try:
        shutil.copystat(str(source), str(target))  # keep the original's modification time
    except OSError:
        pass
    return target


# ------------------------------------------------------------------ library functions
def record_files(ledger: PathLike, host: str, kind: str, paths: Sequence[PathLike],
                 note: str = "", archive: bool = True) -> List[LedgerRow]:
    """Hash each file and append one ledger row per file, in the order given.
    With `archive` (the default), each file is first copied to
    archive_path(); a copy that cannot be made or does not match its hash
    stops the call. Nothing is appended unless every file exists (and was
    archived). Returns the new rows."""
    ledger = Path(ledger)
    host = validate_host_code(host)
    if kind not in LEDGER_KINDS:
        raise StudyError(f"unknown kind {kind!r}; use one of {', '.join(LEDGER_KINDS)}")
    files = [Path(p) for p in paths]
    if not files:
        raise StudyError("no files given to record")
    missing = [str(p) for p in files if not p.is_file()]
    if missing:
        raise StudyError(f"cannot record missing file(s): {', '.join(missing)}")
    ledger_resolved = ledger.resolve()
    if any(p.resolve() == ledger_resolved for p in files):
        raise StudyError("the ledger cannot record itself (its hash changes with every new row)")

    note = " ".join(str(note or "").split())
    recorded_at = utc_now_iso()
    rows = [
        LedgerRow(
            recorded_at_utc=recorded_at,
            host_code=host,
            kind=kind,
            path=ledger_relpath(ledger, path),
            sha256=_hash_file(path),
            bytes=path.stat().st_size,
            note=note,
        )
        for path in files
    ]
    if archive:
        _existing_header(ledger)  # a ledger that cannot take new rows stops the call before any copy is made
        for path, row in zip(files, rows):
            _archive_copy(ledger, path, row)
    _append_rows(ledger, rows)
    return rows


def file_state(ledger: PathLike, row: LedgerRow) -> str:
    """OK if the recorded file still has its recorded hash, CHANGED if it
    differs, MISSING if it is gone or cannot be read."""
    if not row.path:
        return MISSING
    path = resolve_ledger_path(ledger, row.path)
    if not path.is_file():
        return MISSING
    try:
        digest = sha256_file(path)
    except OSError:
        return MISSING
    return OK if digest == row.sha256 else CHANGED


def verify_rows(ledger: PathLike) -> List[Tuple[LedgerRow, str]]:
    """Every ledger row in file order with its hash state (OK, CHANGED or
    MISSING; see row_states for SUPERSEDED and the order check). A ledger
    that does not exist is an error, not an empty list, so a mistyped path
    never verifies as clean."""
    ledger = Path(ledger)
    if not ledger.is_file():
        raise StudyError(f"ledger {ledger} not found")
    return [(row, file_state(ledger, row)) for row in read_ledger(ledger)]


@dataclass
class RowState:
    """One ledger row as `ledger verify` reports it."""
    index: int          # 0-based position among the ledger's rows
    row: LedgerRow
    state: str          # OK, CHANGED, MISSING or SUPERSEDED
    out_of_order: bool  # dated strictly earlier than a row above it, or not a timestamp


def _out_of_order(times: Sequence[Optional[dt.datetime]]) -> List[bool]:
    """Per row: True when its time is unreadable or strictly earlier than the
    latest readable time above it (equal seconds are in order)."""
    flags: List[bool] = []
    latest: Optional[dt.datetime] = None
    for moment in times:
        if moment is None:
            flags.append(True)
            continue
        flags.append(latest is not None and moment < latest)
        if latest is None or moment > latest:
            latest = moment
    return flags


def _supersede_deadline(ledger: Path, rows: Sequence[LedgerRow], kinds: Sequence[str],
                        keys: Sequence[str], times: Sequence[Optional[dt.datetime]],
                        host_code: str) -> Tuple[bool, Optional[dt.datetime]]:
    """(known, deadline): a replacing row must be recorded strictly before
    `deadline` (None: no deadline yet). For a STUDY row the deadline is the
    first tool-output or facts row of any host. For a host row it is that
    host's first worksheet row (by host code or by its worksheet path) or
    first tool-output or facts row, whichever is earlier. known is False
    when one of those rows has no readable time, so nothing is superseded."""
    if is_study_code(host_code):
        relevant = [i for i, kind in enumerate(kinds) if kind in (TOOL_OUTPUT_KIND, FACTS_KIND)]
    else:
        sheet_key = file_key(worksheet_path(ledger.resolve().parent, host_code)) if _valid_host(host_code) else None
        relevant = [
            i for i, row in enumerate(rows)
            if (kinds[i] == WORKSHEET_KIND and (row.host_code == host_code or (sheet_key and keys[i] == sheet_key)))
            or (kinds[i] in (TOOL_OUTPUT_KIND, FACTS_KIND) and row.host_code == host_code)
        ]
    if any(times[i] is None for i in relevant):
        return False, None
    moments = [times[i] for i in relevant if times[i] is not None]
    return True, (min(moments) if moments else None)


def row_states(ledger_path: PathLike) -> List[RowState]:
    """Every ledger row in file order with its state and order flag.

    state is the hash state (file_state), except that a CHANGED row becomes
    SUPERSEDED when all of these hold:
    - its kind is a known kind not in FROZEN_KINDS (input, list-checks,
      protocol, other);
    - a later row (further down) has the same kind, a path that resolves
      to the same file, the state OK, a readable time and no order problem;
    - that later row was recorded strictly before the deadline: for a STUDY
      row, the first tool-output or facts row of any host; for a host row,
      that host's first worksheet row (or first tool-output or facts row, if
      earlier).
    So a correction of study.yaml or of an input file made, and re-recorded,
    before it could matter stops failing verify, while any change after that
    point, and any change to a worksheet, tool output, facts file or
    register sheet, stays CHANGED.

    out_of_order is True for a row whose recorded_at_utc is not a readable
    timestamp or is strictly earlier than a row above it. A ledger that does
    not exist is an error."""
    ledger = Path(ledger_path)
    if not ledger.is_file():
        raise StudyError(f"ledger {ledger} not found")
    rows = read_ledger(ledger)
    base = [file_state(ledger, row) for row in rows]
    times = [_time(row.recorded_at_utc) for row in rows]
    late = _out_of_order(times)
    kinds = [row_kind(row) for row in rows]
    keys = [path_key(ledger, row.path) for row in rows]
    states = list(base)
    for i, row in enumerate(rows):
        if base[i] != CHANGED or kinds[i] in FROZEN_KINDS or kinds[i] not in LEDGER_KINDS or not keys[i]:
            continue
        known, deadline = _supersede_deadline(ledger, rows, kinds, keys, times, row.host_code)
        if not known:
            continue
        for j in range(i + 1, len(rows)):
            moment = times[j]
            if (kinds[j] == kinds[i] and keys[j] == keys[i] and base[j] == OK and not late[j]
                    and moment is not None and (deadline is None or moment < deadline)):
                states[i] = SUPERSEDED
                break
    return [RowState(index=i, row=row, state=states[i], out_of_order=late[i]) for i, row in enumerate(rows)]


# ------------------------------------------------------------------ the seal
@dataclass
class SealStatus:
    """Whether the seal on tool results may open (seal_status)."""
    hosts: List[str]                         # sorted: every host that must be hashed (withdrawn ones left out)
    withdrawn: Dict[str, Tuple[str, str]]    # host -> (recorded_at_utc, reason)
    problems: List[Tuple[str, str]] = field(default_factory=list)  # (host or STUDY, reason with advice)

    @property
    def ok(self) -> bool:
        return not self.problems


def _hosts_from_files(study_dir: Path) -> Tuple[Set[str], List[str]]:
    """Host codes named by DIR/worksheets/<H>-worksheet.csv, DIR/outputs/<H>-facts.json
    and DIR/outputs/<H>-<methodology>.json (names that do not give a valid host
    code, such as Excel's ~$ lock files, are ignored), and any folder that
    could not be listed."""
    found: Set[str] = set()
    unreadable: List[str] = []
    output_suffixes = [_FACTS_SUFFIX] + [f"-{methodology.lower()}.json" for methodology in METHODOLOGY_REGISTRY]
    for folder, suffixes in ((WORKSHEETS_DIR, [_WORKSHEET_SUFFIX]), (OUTPUTS_DIR, output_suffixes)):
        directory = study_dir / folder
        if not directory.is_dir():
            continue
        try:
            entries = sorted(directory.iterdir())
        except OSError as exc:
            unreadable.append(f"cannot list {folder}/ ({exc}), so the hosts it names are unknown")
            continue
        for entry in entries:
            name = entry.name.lower()
            matches = [suffix for suffix in suffixes if name.endswith(suffix) and len(name) > len(suffix)]
            if not matches or not entry.is_file():
                continue
            host = entry.name[:-len(max(matches, key=len))]
            if _valid_host(host) and not is_study_code(host):
                found.add(host)
    return found, unreadable


def _archived_hint(ledger: Path, row: LedgerRow) -> str:
    copy = archive_path(ledger, row)
    return f" (archived copy: {ledger_relpath(ledger, copy)})" if copy.is_file() else ""


def _worksheet_problem(ledger: Path, rows: Sequence[LedgerRow], study_dir: Path, host: str) -> Optional[str]:
    """Why host H's worksheet does not count as hashed and unchanged (with
    advice), or None when it does."""
    sheet = worksheet_path(study_dir, host)
    rel = f"{WORKSHEETS_DIR}/{worksheet_name(host)}"
    matching = worksheet_rows(ledger, rows, study_dir, host)
    if not matching:
        if not sheet.is_file():
            return f"{NO_WORKSHEET_YET}: {rel} not found; {WITHDRAW_ADVICE}"
        return (f"{WORKSHEET_NOT_HASHED}: no ledger row of kind worksheet for {rel}; hash it with "
                f"'ledger record --kind worksheet' once it is finished, or, {WITHDRAW_ADVICE}")
    first = matching[0]
    if not sheet.is_file():
        return f"{HASHED_WORKSHEET_MISSING}: {rel}; {RESTORE_ADVICE}{_archived_hint(ledger, first)}"
    try:
        current = sha256_file(sheet)
    except OSError as exc:
        return f"hashed worksheet cannot be read: {rel} ({exc}); close any program that holds it and try again"
    if all(row.sha256 == current for row in matching):
        return None
    distinct = sorted({row.sha256 for row in matching})
    extra = f" (the ledger holds {len(distinct)} different hashes for it)" if len(distinct) > 1 else ""
    return f"{WORKSHEET_CHANGED}: {rel}{extra}; {RESTORE_ADVICE}; {NO_REHASH}{_archived_hint(ledger, first)}"


def seal_status(study_dir: PathLike, config: Union[StudyConfig, PathLike],
                ledger_path: Optional[PathLike] = None) -> SealStatus:
    """Whether tool results may be shown for the study in `study_dir`.

    Every host in the study must have its worksheet hashed and unchanged.
    The study's hosts are the union of: config.hosts; the hosts of
    DIR/study.yaml (when it exists); every host code other than STUDY in a
    ledger row; and every host named by a file DIR/worksheets/<H>-worksheet.csv,
    DIR/outputs/<H>-facts.json or DIR/outputs/<H>-<methodology>.json. A host
    leaves only through a withdrawal row (ledger withdraw). A remaining host
    has a problem unless at least one ledger row of kind worksheet resolves
    to DIR/worksheets/<H>-worksheet.csv, that file exists, and every such
    row's sha256 equals the file's current hash.

    `config` is a StudyConfig or the path of one; `ledger_path` defaults to
    DIR/ledger.csv. Problems about the study as a whole (no ledger, an
    unreadable study.yaml, an invalid host code in the ledger) are reported
    under the host code STUDY. Only file names and hashes are read: no tool
    output is opened. An unreadable ledger raises StudyError."""
    study_dir = Path(study_dir)
    ledger = Path(ledger_path) if ledger_path is not None else study_dir / LEDGER_FILE
    if not isinstance(config, StudyConfig):
        config = load_config(config)
    study_problems: List[str] = []
    if not ledger.is_file():
        study_problems.append(f"no ledger found at {ledger}")
    rows = read_ledger(ledger) if ledger.is_file() else []

    universe: Set[str] = set(config.hosts)
    default_config = study_dir / CONFIG_FILE
    if default_config.is_file():
        try:
            universe.update(load_config(default_config).hosts)
        except StudyError as exc:
            study_problems.append(f"{CONFIG_FILE} in the study folder cannot be read, so its hosts are "
                                  f"unknown: {exc}")
    for number, row in enumerate(rows):
        code = (row.host_code or "").strip()
        if is_study_code(code):
            continue
        if not _valid_host(code):
            study_problems.append(f"line {number + 2} of the ledger has an invalid host code {code!r}")
            continue
        universe.add(code)
    named, unreadable = _hosts_from_files(study_dir)
    universe.update(named)
    study_problems.extend(unreadable)

    withdrawn = withdrawn_hosts(rows)
    hosts = sorted(host for host in universe if host not in withdrawn)
    problems = [(STUDY_HOST_CODE, text) for text in study_problems]
    for host in hosts:
        reason = _worksheet_problem(ledger, rows, study_dir, host)
        if reason:
            problems.append((host, reason))
    return SealStatus(hosts=hosts, withdrawn=withdrawn, problems=problems)


def worksheet_problems(ledger: PathLike, hosts: Sequence[str]) -> Dict[str, Optional[str]]:
    """For each host, why its manual worksheet does not count as hashed and
    unchanged, or None when it does. A host counts only if at least one
    worksheet row resolves to <ledger folder>/worksheets/<H>-worksheet.csv
    and every such row still matches its file; an absent ledger means no
    host has a worksheet row. (The seal itself is seal_status.)"""
    ledger = Path(ledger)
    rows = read_ledger(ledger)
    folder = ledger.resolve().parent
    problems: Dict[str, Optional[str]] = {}
    for host in hosts:
        recorded = worksheet_rows(ledger, rows, folder, host)
        if not recorded:
            problems[host] = "no worksheet row in the ledger"
            continue
        reasons = []
        for row in recorded:
            state = file_state(ledger, row)
            if state == CHANGED:
                reasons.append(f"worksheet changed after it was hashed: {row.path}")
            elif state == MISSING:
                reasons.append(f"hashed worksheet is missing: {row.path}")
        problems[host] = "; ".join(reasons) or None
    return problems


def worksheets_hashed(ledger: PathLike, hosts: Sequence[str]) -> Dict[str, bool]:
    """host -> True only if a worksheet row exists for its worksheet file and
    every such row still matches its hash."""
    return {host: reason is None for host, reason in worksheet_problems(ledger, hosts).items()}


def withdraw_host(ledger: PathLike, host: str, reason: str,
                  config_path: Optional[PathLike] = None) -> LedgerRow:
    """Append a withdrawal row for `host` (kind protocol, path = the study
    configuration, note 'withdrawn: <reason>') and return it. Refuses STUDY,
    an empty reason, a host already withdrawn, and a code that is not one of
    the study's hosts (seal_status), so a typo never adds a permanent row."""
    ledger = Path(ledger)
    host = validate_host_code(host)
    if is_study_code(host):
        raise StudyError(f"{STUDY_HOST_CODE} is not a host; give the code of the host that will not be "
                         "assessed, such as H3")
    reason = " ".join(str(reason or "").split())
    if not reason:
        raise StudyError("--reason must say why the host will not be assessed")
    config_file = Path(config_path) if config_path is not None else ledger.resolve().parent / CONFIG_FILE
    if not config_file.is_file():
        raise StudyError(f"study configuration not found: {config_file} (give it with --config)")
    config = load_config(config_file)
    rows = read_ledger(ledger)
    already = withdrawn_hosts(rows)
    if host in already:
        when, why = already[host]
        raise StudyError(f"{host} was already withdrawn at {when} ({why}); nothing was recorded")
    status = seal_status(ledger.resolve().parent, config, ledger_path=ledger)
    if host not in status.hosts:
        known = ", ".join(status.hosts) or "none"
        raise StudyError(f"{host} is not a host of this study (hosts: {known}); nothing was recorded")
    return record_files(ledger, host, PROTOCOL_KIND, [config_file], note=WITHDRAWN_NOTE_PREFIX + reason)[0]


@dataclass(frozen=True)
class HostStatus:
    """What the ledger holds for one host: kind -> recorded times (time
    order), the times of the rows that count as its worksheet (kind
    worksheet, path worksheets/<H>-worksheet.csv), and its withdrawal."""
    host_code: str
    kinds: Dict[str, List[str]]
    worksheet_times: Tuple[str, ...] = ()
    withdrawn: Optional[Tuple[str, str]] = None   # (recorded_at_utc, reason)

    @property
    def has_worksheet(self) -> bool:
        return bool(self.worksheet_times)


def host_status(ledger: PathLike, hosts: Optional[Sequence[str]] = None) -> List[HostStatus]:
    """Per host, which kinds of file have been recorded and when. Hosts named
    in `hosts` come first, in that order (even with nothing recorded); other
    hosts follow in the order they first appear in the ledger. A host has a
    worksheet only through a worksheet row whose path resolves to
    <ledger folder>/worksheets/<H>-worksheet.csv. Reads only the ledger,
    never the recorded files."""
    rows = read_ledger(ledger)
    folder = Path(ledger).resolve().parent
    withdrawn = withdrawn_hosts(rows)
    order: List[str] = list(hosts or [])
    for row in rows:
        if row.host_code not in order:
            order.append(row.host_code)
    known_kinds = {kind: index for index, kind in enumerate(LEDGER_KINDS)}
    statuses = []
    for host in order:
        times: Dict[str, List[str]] = {}
        for row in rows:
            if row.host_code == host:
                times.setdefault(row.kind, []).append(row.recorded_at_utc)
        ordered = sorted(times, key=lambda kind: (known_kinds.get(kind, len(known_kinds)), kind))
        sheet_times: Tuple[str, ...] = ()
        if _valid_host(host) and not is_study_code(host):
            sheet_times = tuple(sorted(row.recorded_at_utc for row in worksheet_rows(ledger, rows, folder, host)))
        statuses.append(HostStatus(host_code=host, kinds={kind: sorted(times[kind]) for kind in ordered},
                                   worksheet_times=sheet_times, withdrawn=withdrawn.get(host)))
    return statuses


# ------------------------------------------------------------------ command line
# Note of a worksheet row that `record --kind worksheet --force` recorded although
# the pre-hash lint (agreement.lint_worksheet) found problems; the findings follow it.
LINT_NOTE_PREFIX = "recorded despite lint findings: "


def configure(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="action", metavar="{record,verify,status,withdraw}", required=True)

    record = sub.add_parser("record", help="Hash files, keep a copy of each, and append one ledger row per file.",
                            description="Hash files and append one ledger row per file. Each file is also "
                                        f"copied to {ARCHIVE_DIR}/<sha256><suffix> next to the ledger (never "
                                        "replaced), so a hashed file changed by accident can be restored. With "
                                        "--kind worksheet, each worksheet is first linted against the study "
                                        "configuration (blank or unreadable cells, the level range, levels that "
                                        "do not follow the declared manual level rule, the host code), because a "
                                        "hashed worksheet can never be corrected; any finding stops the record "
                                        "unless --force is given. The lint reads only the worksheet and the "
                                        "study configuration, never a tool output.")
    record.add_argument("--ledger", required=True, metavar="FILE",
                        help="The ledger CSV (created with a header if missing).")
    record.add_argument("--host", required=True, metavar="H",
                        help=f"Host code such as H1; use {STUDY_HOST_CODE} for study-wide files.")
    record.add_argument("--kind", required=True, choices=LEDGER_KINDS, help="What the files are.")
    record.add_argument("--note", default="", metavar="TEXT", help="Optional one-line note.")
    record.add_argument("--config", default=None, metavar="FILE",
                        help=f"--kind worksheet only: the study configuration the lint uses (default: {CONFIG_FILE} "
                             "next to the ledger).")
    record.add_argument("--force", action="store_true",
                        help="--kind worksheet only: record even though the lint found problems; the ledger note "
                             f"then starts '{LINT_NOTE_PREFIX.strip()}' and lists them.")
    record.add_argument("paths", nargs="+", metavar="PATH", help="Files to hash.")

    verify = sub.add_parser("verify", help="Re-hash every recorded file.",
                            description="Re-hash every recorded file and report OK, CHANGED, MISSING or "
                                        "SUPERSEDED per row, plus OUT OF ORDER for a row dated earlier than a "
                                        "row above it; exit 0 only if every row is OK or SUPERSEDED and in "
                                        "order. Worksheets, tool outputs, facts and register sheets are never "
                                        "SUPERSEDED.")
    verify.add_argument("--ledger", required=True, metavar="FILE", help="The ledger CSV.")

    status = sub.add_parser("status", help="Show which kinds of file each host has, and when.",
                            description="Show which kinds of file each host has recorded, and when, "
                                        "without reading the files, and which hosts are withdrawn. With "
                                        "--hosts, flag (and exit 1 for) hosts that are not withdrawn and have "
                                        "no worksheet row for worksheets/<H>-worksheet.csv.")
    status.add_argument("--ledger", required=True, metavar="FILE", help="The ledger CSV.")
    status.add_argument("--hosts", default=None, metavar="H1,H2,...",
                        help="Hosts that should each have a worksheet row.")

    withdraw = sub.add_parser("withdraw", help="Record that a host will not be assessed.",
                              description="Append a dated row (kind protocol, note 'withdrawn: <reason>') "
                                          "saying that a host will not be assessed. Only this takes a host out "
                                          "of the seal; it cannot be undone.")
    withdraw.add_argument("--ledger", required=True, metavar="FILE", help="The ledger CSV.")
    withdraw.add_argument("--host", required=True, metavar="H", help="The host that will not be assessed.")
    withdraw.add_argument("--reason", required=True, metavar="TEXT", help="Why (one line, also for the protocol log).")
    withdraw.add_argument("--config", default=None, metavar="FILE",
                          help=f"The study configuration recorded with the row (default: {CONFIG_FILE} next to "
                               "the ledger).")


def _print_recorded(ledger: str, rows: Sequence[LedgerRow]) -> None:
    for row in rows:
        print(f"{row.sha256}  {row.path}")
        print(f"archive copy: {ledger_relpath(ledger, archive_path(ledger, row))}")


def _lint_note(findings: Sequence[Tuple[Path, str, str]], several: bool) -> str:
    """The ledger note text listing lint findings (file names only when
    several files were recorded in one call)."""
    items = [(f"{path.name}: " if several else "") + f"{severity} {message}" for path, severity, message in findings]
    return LINT_NOTE_PREFIX + "; ".join(items)


def _lint_worksheets(args: argparse.Namespace) -> str:
    """The pre-hash worksheet lint of `ledger record --kind worksheet`: each
    file is checked with agreement.lint_worksheet against the study
    configuration (--config, default study.yaml next to the ledger), and
    must be DIR/worksheets/<H>-worksheet.csv, the only file the seal counts
    as H's worksheet. Prints every finding (to stderr). Refuses when there
    is any, unless --force; returns the note to record. Only the worksheets
    and the configuration are read."""
    from miccmac_study import agreement  # imported here: agreement imports this module

    host = validate_host_code(args.host)
    files = [Path(p) for p in args.paths]
    missing = [str(p) for p in files if not p.is_file()]
    if missing:
        raise StudyError(f"cannot record missing file(s): {', '.join(missing)}")
    folder = Path(args.ledger).resolve().parent
    config_path = Path(args.config) if args.config is not None else folder / CONFIG_FILE
    if not config_path.is_file():
        raise StudyError(f"the worksheet lint needs the study configuration, and {config_path} was not found; give "
                         "it with --config FILE (nothing was recorded)")
    config = load_config(config_path)
    own_sheet = file_key(worksheet_path(folder, host)) if not is_study_code(host) else None
    findings: List[Tuple[Path, str, str]] = []
    for path in files:
        for severity, message in agreement.lint_worksheet(path, config, host):
            findings.append((path, severity, message))
        if own_sheet is None or file_key(path) != own_sheet:
            findings.append((path, agreement.WARNING,
                             f"this is not {WORKSHEETS_DIR}/{worksheet_name(host) if own_sheet else '<H>-worksheet.csv'} "
                             f"next to the ledger, so the seal would not count this row as {host}'s worksheet"))
    for path, severity, message in findings:
        print(f"lint {severity} {path}: {message}", file=sys.stderr)
    note = args.note
    if not findings:
        return note
    if not args.force:
        raise StudyError(
            f"the worksheet lint found {len(findings)} problem(s), listed above; nothing was recorded. A hashed "
            "worksheet can never be corrected, so correct the worksheet and record it again, or add --force to "
            f"record it as it is (the ledger note then starts '{LINT_NOTE_PREFIX.strip()}' and lists them)")
    text = _lint_note(findings, several=len(files) > 1)
    return f"{note.strip()}; {text}" if note and note.strip() else text


def _run_record(args: argparse.Namespace) -> int:
    note = args.note
    if args.kind == WORKSHEET_KIND:
        note = _lint_worksheets(args)
    elif args.force or args.config is not None:
        raise StudyError("--config and --force belong to the worksheet lint and work only with --kind worksheet")
    _print_recorded(args.ledger, record_files(args.ledger, args.host, args.kind, args.paths, note=note))
    return 0


def _order_notes(states: Sequence[RowState]) -> Dict[int, str]:
    """index -> why the row is OUT OF ORDER (times only)."""
    notes: Dict[int, str] = {}
    latest: Optional[dt.datetime] = None
    for item in states:
        moment = _time(item.row.recorded_at_utc)
        if item.out_of_order:
            if moment is None:
                notes[item.index] = f"recorded_at_utc {item.row.recorded_at_utc!r} is not a timestamp"
            else:
                notes[item.index] = (f"recorded {item.row.recorded_at_utc}, earlier than "
                                     f"{latest.strftime('%Y-%m-%dT%H:%M:%SZ') if latest else '?'} above it")
        if moment is not None and (latest is None or moment > latest):
            latest = moment
    return notes


def _run_verify(args: argparse.Namespace) -> int:
    states = row_states(args.ledger)
    if not states:
        print(f"{args.ledger}: no rows recorded", file=sys.stderr)
    notes = _order_notes(states)
    for item in states:
        line = f"{item.state:<7} {item.row.path}  ({item.row.kind})"
        if item.out_of_order:
            line += f"  OUT OF ORDER ({notes.get(item.index, '')})"
        print(line)
    clean = all(item.state in (OK, SUPERSEDED) and not item.out_of_order for item in states)
    return 0 if clean else 1


def _run_status(args: argparse.Namespace) -> int:
    expected = parse_host_list(args.hosts) if args.hosts is not None else []
    statuses = host_status(args.ledger, expected)
    if not statuses:
        print(f"{args.ledger}: no rows recorded", file=sys.stderr)
        return 0
    width = max(len(status.host_code) for status in statuses)
    kind_width = max(len(kind) for kind in LEDGER_KINDS)
    flagged = False
    for status in statuses:
        for kind, times in status.kinds.items():
            print(f"{status.host_code:<{width}}  {kind:<{kind_width}}  {', '.join(times)}")
        if status.withdrawn is not None:
            when, reason = status.withdrawn
            print(f"{status.host_code:<{width}}  WITHDRAWN {when}: {reason}")
        elif status.host_code in expected and not status.has_worksheet:
            flagged = True
            if not status.kinds:
                suffix = " (nothing recorded for this host)"
            elif WORKSHEET_KIND in status.kinds:
                suffix = (f" for {WORKSHEETS_DIR}/{worksheet_name(status.host_code)} "
                          "(this host's worksheet rows name another file)")
            else:
                suffix = ""
            print(f"{status.host_code:<{width}}  NO WORKSHEET ROW{suffix}")
    return 1 if flagged else 0


def _run_withdraw(args: argparse.Namespace) -> int:
    row = withdraw_host(args.ledger, args.host, args.reason, config_path=args.config)
    _print_recorded(args.ledger, [row])
    print(f"{row.host_code} withdrawn at {row.recorded_at_utc}: {row.note[len(WITHDRAWN_NOTE_PREFIX):]}")
    return 0


def run(args: argparse.Namespace) -> int:
    if args.action == "record":
        return _run_record(args)
    if args.action == "verify":
        return _run_verify(args)
    if args.action == "withdraw":
        return _run_withdraw(args)
    return _run_status(args)
