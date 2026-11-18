"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

SHA-256 ledger of study files (protocol section 5), and the seal that keeps
tool results hidden until every host's worksheet is hashed.

    python -m miccmac_study ledger record --ledger FILE --host H --kind KIND [--note TEXT]
        [--config FILE] [--force] PATH [PATH ...]
    python -m miccmac_study ledger verify --ledger FILE
    python -m miccmac_study ledger status --ledger FILE [--hosts H1,H2,...]
    python -m miccmac_study ledger withdraw --ledger FILE --host H --reason TEXT [--config FILE]
        [--after-unseal]

The ledger (formats.LEDGER_COLUMNS) only grows: each `record` call appends
one row per file with the time, host code, kind, path, SHA-256, size and an
optional note. A file inside the ledger's folder is recorded relative to that
folder, so the study folder can be moved or copied as a whole. `record` also
keeps a copy of each file in <ledger folder>/ledger-archive/<sha256><suffix>
(never replaced, and checked against the hash), so a hashed file that is
changed by accident can be restored byte for byte.

A sealed file is hashed once. A sealed path is a file in worksheets/,
outputs/ or register/ of the ledger's folder, or any file for which the
ledger already holds a row of a kind in FROZEN_KINDS (worksheets, tool
outputs, facts, register sheets); paths are compared resolved (and
case-folded where the file system ignores case), so spelling does not
matter. `record` (record_files, so every caller)
refuses a sealed path whose bytes differ from its first row, names that row
and the archive copy to restore, and records nothing; no flag overrides
this. A sealed path recorded again with the same kind and hash adds no row:
the command prints "already recorded at <time> (ledger line <n>):" and that
row's usual lines.

`record --kind worksheet` first lints each worksheet against the study
configuration (--config, default study.yaml next to the ledger) with
agreement.lint_worksheet: blank or unreadable verdicts and levels, levels
outside the study's range or not following the declared manual level rule,
the host code, the synthetic flag, and a file that is not
worksheets/<H>-worksheet.csv. It prints each finding and records nothing
while there is one, unless --force is given; the note then starts
"recorded despite lint findings: " and lists them. The lint reads only the
worksheet and the configuration, and runs after the sealed-path check, so a
hashed worksheet that was edited is refused with the restore advice. A file
named study.yaml (any letter case) is recorded only if it is a valid study
configuration. The library function record_files never lints.

`verify` re-hashes every recorded file and prints one line per row:

    OK          the file still has its recorded hash
    CHANGED     the file differs from its recorded hash
    MISSING     the file is gone or cannot be read
    SUPERSEDED  a CHANGED row that a later, still-matching row for the same
                file (of any kind not in FROZEN_KINDS) replaced in time (see
                row_states)
    ARCHIVED    a withdrawal or seal-opening row, which records the
                configuration in force at that moment, whose file changed or
                is gone since, while its ledger-archive copy still matches

and adds OUT OF ORDER to a row dated strictly earlier than a row above it
(rows in the same second are in order). It exits 0 only when every row is
OK, SUPERSEDED or ARCHIVED and none is OUT OF ORDER. Rows of the kinds in
FROZEN_KINDS, and every row for a sealed path whatever its kind, are never
SUPERSEDED.

`record` (the command) also refuses a file in worksheets/, outputs/ or
register/ under a kind other than that folder's own, and an input file not
named <H>-attestation.json or <H>-inventory-record.json.

The seal (seal_status) waits for every host named in the study
configuration, in DIR/study.yaml or in any version of it in force at or
after the first tool run, in a ledger row, or in a worksheet or tool-output
file name, until its worksheet matches the first worksheet row recorded for
it. study.yaml must also still match its latest ledger row. Editing
study.yaml or passing another configuration never opens the seal; only
`withdraw` takes a host out. register-sheet and agreement append a "seal
opened by" row (record_seal_opened) each time they open the seal, so the
ledger shows when tool results became available. A
withdrawal after the first seal opening needs --after-unseal and says so in
its note.

Nothing here prints file contents or any tool result.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PureWindowsPath
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY

from miccmac_study.formats import (
    CONFIG_FILE,
    LEDGER_COLUMNS,
    LEDGER_FILE,
    LEDGER_KINDS,
    OUTPUTS_DIR,
    REGISTER_DIR,
    WORKSHEETS_DIR,
    LedgerRow,
    StudyConfig,
    StudyError,
    ledger_relpath,
    load_study_config,
    parse_utc_timestamp,
    plain_path,
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
ARCHIVED = "ARCHIVED"
# States that let `ledger verify` exit 0.
CLEAN_STATES = (OK, SUPERSEDED, ARCHIVED)

# Host code for rows about the whole study rather than one host: the
# protocol, study.yaml, the list-checks file, seal openings.
STUDY_HOST_CODE = "STUDY"

WORKSHEET_KIND = "worksheet"
INPUT_KIND = "input"
FACTS_KIND = "facts"
TOOL_OUTPUT_KIND = "tool-output"
PROTOCOL_KIND = "protocol"
# Kinds whose files never change once hashed: a CHANGED row of these kinds
# stays CHANGED whatever is recorded later.
FROZEN_KINDS = ("worksheet", "tool-output", "facts", "register-review", "missed-gaps")
# Folders of the ledger's folder whose files are sealed paths, whatever kind
# their rows were given.
SEALED_DIRS = (WORKSHEETS_DIR, OUTPUTS_DIR, REGISTER_DIR)

# Note of the ledger row register-sheet appends when it is forced before
# every worksheet is hashed (register_sheet imports it from here).
FORCE_NOTE_PREFIX = "register sheets generated before every worksheet was hashed: "
# Note of the STUDY row (kind protocol) a command appends each time it opens
# the seal (record_seal_opened): "seal opened by <command>: hosts H1, H2;
# withdrawn: none". This row and a FORCE_NOTE_PREFIX row are seal openings.
SEAL_OPENED_NOTE_PREFIX = "seal opened by "
# Note of a withdrawal row (kind protocol): "withdrawn: <reason>".
WITHDRAWN_NOTE_PREFIX = "withdrawn: "
# Start of the reason of a withdrawal recorded after the seal was opened.
AFTER_UNSEAL_REASON_PREFIX = "(after the seal was opened) "

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

# Roles of a host's input files (assessor_inputs), from the recorded file name.
ATTESTATION_ROLE = "attestation"
INVENTORY_ROLE = "inventory_record"
ROLE_SUFFIXES = (("-attestation.json", ATTESTATION_ROLE), ("-inventory-record.json", INVENTORY_ROLE))

# Codes of check_run_inputs.
INPUT_DUPLICATE = "duplicate"
INPUT_SWAPPED = "swapped"
INPUT_LATER_VERSION = "later-version"
INPUT_NOT_RECORDED = "not-recorded"
INPUT_ROLE_UNKNOWN = "role-unknown"
INPUT_MISSING = "missing"
INPUT_CODES = (INPUT_DUPLICATE, INPUT_SWAPPED, INPUT_LATER_VERSION, INPUT_NOT_RECORDED, INPUT_ROLE_UNKNOWN,
               INPUT_MISSING)

PathLike = Union[str, Path]

_WORKSHEET_SUFFIX = "-worksheet.csv"
_FACTS_SUFFIX = "-facts.json"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
# How each input role is named in messages: (what it is, the miccmac option).
_ROLE_WORDS = {ATTESTATION_ROLE: ("attestation", "--attestation"),
               INVENTORY_ROLE: ("inventory record", "--inventory-record")}


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
    """How two paths are compared: resolved, without a Windows \\\\?\\ prefix
    (formats.plain_path), and case-folded where the file system ignores case
    (os.path.normcase), as agreement matches them."""
    return os.path.normcase(str(plain_path(Path(path).resolve())))


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
    (whatever host code they were recorded under), in ledger order. The
    first of them is binding: the seal counts the sheet only while it
    matches that row."""
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


def is_seal_opening(row: LedgerRow) -> bool:
    """A seal opening: a STUDY row whose note starts with
    SEAL_OPENED_NOTE_PREFIX (record_seal_opened) or with FORCE_NOTE_PREFIX
    (register-sheet --force-before-unseal), whatever its kind."""
    return is_study_code(row.host_code) and (row.note or "").startswith((SEAL_OPENED_NOTE_PREFIX, FORCE_NOTE_PREFIX))


def is_event_row(row: LedgerRow) -> bool:
    """A withdrawal or a seal opening: a row that records the configuration
    in force at that moment, as a fact of its own."""
    return is_withdrawal(row) or is_seal_opening(row)


def _archive_matches(ledger: PathLike, row: LedgerRow) -> bool:
    """True when the row's ledger-archive copy exists and has its hash."""
    copy = archive_path(ledger, row)
    try:
        return copy.is_file() and sha256_file(copy) == row.sha256
    except OSError:
        return False


def first_seal_opening(rows: Sequence[LedgerRow]) -> Optional[Tuple[int, LedgerRow]]:
    """The first seal opening in ledger order, with its 0-based index, or None."""
    for index, row in enumerate(rows):
        if is_seal_opening(row):
            return index, row
    return None


def first_tool_row(rows: Sequence[LedgerRow], host: Optional[str] = None) -> Optional[Tuple[int, LedgerRow]]:
    """The first row of kind tool-output or facts in ledger order, of `host`
    only when it is given (else of any host), with its 0-based index, or None."""
    for index, row in enumerate(rows):
        if row_kind(row) not in (TOOL_OUTPUT_KIND, FACTS_KIND):
            continue
        if host is None or (row.host_code or "").strip() == host:
            return index, row
    return None


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


def _rows_for_append(ledger: Path) -> List[LedgerRow]:
    """The rows of a ledger that can take new rows (an absent or empty one
    has none); a ledger that cannot be appended to raises StudyError."""
    return read_ledger(ledger) if _existing_header(ledger) is not None else []


# ------------------------------------------------------------------ archive copies
def archive_path(ledger: PathLike, row: LedgerRow) -> Path:
    """Where `record` keeps the copy of a row's file:
    <ledger folder>/ledger-archive/<sha256><suffix of the recorded file>."""
    return Path(ledger).resolve().parent / ARCHIVE_DIR / f"{row.sha256}{PurePath(row.path).suffix}"


def _archive_name(ledger: PathLike, row: LedgerRow) -> Tuple[str, bool]:
    """The archive copy of a row, relative to the ledger, and whether it exists."""
    copy = archive_path(ledger, row)
    return ledger_relpath(ledger, copy), copy.is_file()


def _restore_from(ledger: PathLike, row: LedgerRow) -> str:
    """Where a sealed file's recorded bytes can be restored from: its archive
    copy (or a commit or e-mailed copy), or only those when the copy is gone."""
    name, present = _archive_name(ledger, row)
    if present:
        return f"{name} (or your commit or e-mailed copy)"
    return f"your commit or e-mailed copy (its archive copy {name} is missing)"


def _restore_config_from(ledger: PathLike, row: LedgerRow) -> str:
    """Where a recorded study.yaml can be restored from."""
    name, present = _archive_name(ledger, row)
    return name if present else f"your commit (its archive copy {name} is missing)"


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


# ------------------------------------------------------------------ sealed paths
def _sealed_dir_keys(ledger: PathLike) -> Tuple[str, ...]:
    folder = Path(ledger).resolve().parent
    return tuple(file_key(folder / name) for name in SEALED_DIRS)


def _in_folders(key: str, folders: Sequence[str]) -> bool:
    """True when the file key lies inside one of the folder keys."""
    return bool(key) and any(key.startswith(folder.rstrip("\\/") + os.sep) for folder in folders)


def is_sealed_path(ledger: PathLike, path: PathLike, rows: Sequence[LedgerRow]) -> bool:
    """True for a sealed path: a file that resolves inside worksheets/,
    outputs/ or register/ of the ledger's folder, or one for which `rows`
    (the ledger's rows) already hold a row of a kind in FROZEN_KINDS. Paths
    are compared as file_key and path_key compare them."""
    key = file_key(path)
    if _in_folders(key, _sealed_dir_keys(ledger)):
        return True
    return any(row_kind(row) in FROZEN_KINDS and path_key(ledger, row.path) == key for row in rows)


def _rehash_refusal(ledger: PathLike, index: int, first: LedgerRow) -> str:
    return (f"{first.path} was hashed at {first.recorded_at_utc} (ledger line {index + 2}, kind {row_kind(first)}); "
            "a hashed worksheet, tool output, facts file or register sheet never changes, so nothing was recorded. "
            f"To undo an edit, restore the recorded bytes from {_restore_from(ledger, first)}; a correction goes "
            "in the disagreement log or the protocol log.")


def _sealed_matches(ledger: Path, earlier: Sequence[LedgerRow], kind: str, files: Sequence[Path],
                    digests: Sequence[str], event: bool = False) -> List[Optional[int]]:
    """The sealed-path rule of record_files. For each file: when it is a
    sealed path, its hash must equal its first row's (any kind), or the
    whole call is refused (StudyError naming that row and its archive copy);
    and the 0-based index of an earlier row with the same kind and hash, for
    which nothing is appended, else None. An `event` row (a withdrawal or a
    seal opening, which records the configuration as a fact of its own) is
    always appended, after the same check."""
    folders = _sealed_dir_keys(ledger)
    keys = [path_key(ledger, row.path) for row in earlier]
    frozen = {key for key, row in zip(keys, earlier) if key and row_kind(row) in FROZEN_KINDS}
    matches: List[Optional[int]] = []
    for path, digest in zip(files, digests):
        key = file_key(path)
        same = [index for index, other in enumerate(keys) if other == key]
        if not same or not (key in frozen or _in_folders(key, folders)):
            matches.append(None)
            continue
        if earlier[same[0]].sha256 != digest:
            raise StudyError(_rehash_refusal(ledger, same[0], earlier[same[0]]))
        if event:
            matches.append(None)
            continue
        matches.append(next((index for index in same
                             if row_kind(earlier[index]) == kind and earlier[index].sha256 == digest), None))
    return matches


def _record_files(ledger: PathLike, host: str, kind: str, paths: Sequence[PathLike], note: str = "",
                  archive: bool = True, event: bool = False) -> List[Tuple[LedgerRow, Optional[int]]]:
    """record_files, reporting every file: (the new row, None) when a row was
    appended, or (the earlier row, its 0-based index) when the file is a
    sealed path already recorded with the same kind and hash."""
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
    ledger_key = file_key(ledger)
    if any(file_key(p) == ledger_key for p in files):
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
    earlier = _rows_for_append(ledger)  # a ledger that cannot take new rows stops the call before any copy is made
    matches = _sealed_matches(ledger, earlier, kind, files, [row.sha256 for row in rows], event=event)
    if archive:
        for path, row, match in zip(files, rows, matches):
            _archive_copy(ledger, path, row if match is None else earlier[match])
    new_rows = [row for row, match in zip(rows, matches) if match is None]
    if new_rows:
        _append_rows(ledger, new_rows)
    return [(row, None) if match is None else (earlier[match], match) for row, match in zip(rows, matches)]


# ------------------------------------------------------------------ library functions
def record_files(ledger: PathLike, host: str, kind: str, paths: Sequence[PathLike],
                 note: str = "", archive: bool = True) -> List[LedgerRow]:
    """Hash each file and append one ledger row per file, in the order given.
    With `archive` (the default), each file is first copied to
    archive_path(); a copy that cannot be made or does not match its hash
    stops the call. Nothing is appended unless every file exists (and was
    archived).

    A sealed path (is_sealed_path) is hashed once: when its bytes differ
    from its first row's, the whole call is refused (StudyError naming that
    row and the archive copy to restore; nothing appended, nothing
    archived), and when an earlier row has the same kind and hash, no row is
    appended for it. Returns the new rows."""
    return [row for row, match in _record_files(ledger, host, kind, paths, note=note, archive=archive)
            if match is None]


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
    state: str          # OK, CHANGED, MISSING, SUPERSEDED or ARCHIVED
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
      protocol, other), and its path is not a sealed path (a file in
      worksheets/, outputs/ or register/ of the ledger's folder, or one with
      a row of a kind in FROZEN_KINDS anywhere in the ledger);
    - a later row (further down) has a known kind not in FROZEN_KINDS (any
      of them: a withdrawal or seal-opening row that recorded study.yaml is
      superseded by a correction recorded with --kind other), a path that
      resolves to the same file, the state OK, a readable time and no order
      problem;
    - that later row was recorded strictly before the deadline: for a STUDY
      row, the first tool-output or facts row of any host; for a host row,
      that host's first worksheet row (or first tool-output or facts row, if
      earlier).
    So a correction of study.yaml or of an input file made, and re-recorded,
    before it could matter stops failing verify, while any change after that
    point, and any change to a worksheet, tool output, facts file or
    register sheet, stays CHANGED.

    A withdrawal or seal-opening row records the configuration in force at
    that moment, not a file that must stay as it is: when its file changed
    or is gone (study.yaml recorded again later, a sensitivity --config
    moved away), it is ARCHIVED while its ledger-archive copy still has the
    recorded hash, else CHANGED or MISSING. Such a row is never SUPERSEDED.

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
    folders = _sealed_dir_keys(ledger)
    frozen_files = {key for key, kind in zip(keys, kinds) if key and kind in FROZEN_KINDS}
    replaceable = [kind in LEDGER_KINDS and kind not in FROZEN_KINDS for kind in kinds]
    states = list(base)
    for i, row in enumerate(rows):
        if is_event_row(row):
            if base[i] in (CHANGED, MISSING) and _archive_matches(ledger, row):
                states[i] = ARCHIVED
            continue
        if (base[i] != CHANGED or not replaceable[i] or not keys[i] or keys[i] in frozen_files
                or _in_folders(keys[i], folders)):
            continue
        known, deadline = _supersede_deadline(ledger, rows, kinds, keys, times, row.host_code)
        if not known:
            continue
        for j in range(i + 1, len(rows)):
            moment = times[j]
            if (replaceable[j] and keys[j] == keys[i] and base[j] == OK and not late[j]
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
    advice), or None when it does: it must match the first worksheet row
    recorded for it."""
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
    if current == first.sha256:
        return None
    return f"{WORKSHEET_CHANGED}: {rel}; restore the original bytes from {_restore_from(ledger, first)}; {NO_REHASH}"


def study_config_rows(ledger: PathLike, rows: Sequence[LedgerRow],
                      study_dir: Optional[PathLike] = None) -> List[Tuple[int, LedgerRow]]:
    """(0-based index, row) of every row whose path resolves to
    DIR/study.yaml (any kind), in ledger order, seal openings left out: each
    is a recorded version of the study configuration. DIR is `study_dir`,
    default the ledger's folder."""
    folder = Path(study_dir) if study_dir is not None else Path(ledger).resolve().parent
    target = file_key(folder / CONFIG_FILE)
    return [(index, row) for index, row in enumerate(rows)
            if path_key(ledger, row.path) == target and not is_seal_opening(row)]


def study_config_problem(ledger: PathLike, rows: Sequence[LedgerRow],
                         study_dir: Optional[PathLike] = None) -> Optional[str]:
    """Why DIR/study.yaml does not match its latest version in the ledger
    (study_config_rows), or None when it does or was never recorded."""
    recorded = study_config_rows(ledger, rows, study_dir)
    if not recorded:
        return None
    index, latest = recorded[-1]
    config = (Path(study_dir) if study_dir is not None else Path(ledger).resolve().parent) / CONFIG_FILE
    if not config.is_file():
        return f"{CONFIG_FILE} is missing; restore it from {_restore_config_from(ledger, latest)}"
    try:
        current = sha256_file(config)
    except OSError as exc:
        return f"{CONFIG_FILE} cannot be read ({exc}); close any program that holds it and try again"
    if current == latest.sha256:
        return None
    return (f"{CONFIG_FILE} changed since it was last recorded (ledger line {index + 2}, {latest.recorded_at_utc}): "
            f"restore it from {_restore_config_from(ledger, latest)} or record it again; editing {CONFIG_FILE} "
            "never opens the seal")


def _config_versions(ledger: Path, rows: Sequence[LedgerRow], study_dir: Path) -> List[Tuple[int, LedgerRow]]:
    """The versions of DIR/study.yaml in force at or after the first tool
    run: the latest one recorded before the first tool-output or facts row
    (of any host) and every one recorded after it; with no such row yet,
    only the latest one."""
    recorded = study_config_rows(ledger, rows, study_dir)
    first = first_tool_row(rows)
    if first is None:
        return recorded[-1:]
    before = [item for item in recorded if item[0] < first[0]]
    return before[-1:] + [item for item in recorded if item[0] > first[0]]


def _archived_config_hosts(ledger: Path, row: LedgerRow) -> Optional[List[str]]:
    """The hosts of a recorded study.yaml version, read from its archive copy
    once that copy has the recorded hash, or None when it cannot be."""
    copy = archive_path(ledger, row)
    try:
        if not copy.is_file() or sha256_file(copy) != row.sha256:
            return None
        return list(load_config(copy).hosts)
    except (OSError, StudyError):
        return None


def seal_status(study_dir: PathLike, config: Union[StudyConfig, PathLike],
                ledger_path: Optional[PathLike] = None) -> SealStatus:
    """Whether tool results may be shown for the study in `study_dir`.

    Every host in the study must have its worksheet hashed and unchanged.
    The study's hosts are the union of: config.hosts; the hosts of
    DIR/study.yaml (when it exists); the hosts of every version of
    DIR/study.yaml in force at or after the first tool run (the latest one
    recorded before the first tool-output or facts row, and every one
    recorded after it; with no such row, only the latest one), read from its
    archive copy once that copy has the recorded hash (a version with the
    hash of DIR/study.yaml is DIR/study.yaml); every host code other than
    STUDY in a ledger row; and every host named by a file
    DIR/worksheets/<H>-worksheet.csv, DIR/outputs/<H>-facts.json or
    DIR/outputs/<H>-<methodology>.json. A host leaves only through a
    withdrawal row (ledger withdraw). A remaining host has a problem unless
    DIR/worksheets/<H>-worksheet.csv exists and matches the first ledger row
    of kind worksheet that resolves to it (later rows with another hash
    stay CHANGED in `ledger verify`).

    When DIR/study.yaml has ledger rows (seal openings aside), it must exist
    and match the latest of them, or the seal stays closed.

    `config` is a StudyConfig or the path of one; `ledger_path` defaults to
    DIR/ledger.csv. Problems about the study as a whole (no ledger, an
    unreadable or changed study.yaml, a recorded version whose hosts are
    unknown, an invalid host code in the ledger) are reported under the host
    code STUDY. Only file names, hashes and archived study.yaml copies are
    read: no tool output is opened. An unreadable ledger raises StudyError."""
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
    current_hash: Optional[str] = None
    if default_config.is_file():
        try:
            current_hash = sha256_file(default_config)
        except OSError:
            current_hash = None
        try:
            universe.update(load_config(default_config).hosts)
        except StudyError as exc:
            study_problems.append(f"{CONFIG_FILE} in the study folder cannot be read, so its hosts are "
                                  f"unknown: {exc}")
    changed = study_config_problem(ledger, rows, study_dir)
    if changed:
        study_problems.append(changed)
    loaded: Set[str] = set()
    for index, row in _config_versions(ledger, rows, study_dir):
        if row.sha256 == current_hash or row.sha256 in loaded:
            continue    # DIR/study.yaml itself is that version, or it was read already
        hosts = _archived_config_hosts(ledger, row)
        if hosts is None:
            study_problems.append(
                f"the hosts of {CONFIG_FILE} as recorded at ledger line {index + 2} are unknown: its archive copy "
                f"{ledger_relpath(ledger, archive_path(ledger, row))} is missing or unreadable; restore "
                f"{ARCHIVE_DIR} from your commit")
            continue
        loaded.add(row.sha256)
        universe.update(hosts)
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
    unchanged, or None when it does. A host counts only if a worksheet row
    resolves to <ledger folder>/worksheets/<H>-worksheet.csv and the file
    still matches the first such row; an absent ledger means no host has a
    worksheet row. (The seal itself is seal_status.)"""
    ledger = Path(ledger)
    rows = read_ledger(ledger)
    folder = ledger.resolve().parent
    problems: Dict[str, Optional[str]] = {}
    for host in hosts:
        recorded = worksheet_rows(ledger, rows, folder, host)
        if not recorded:
            problems[host] = "no worksheet row in the ledger"
            continue
        first = recorded[0]
        state = file_state(ledger, first)
        if state == CHANGED:
            problems[host] = f"worksheet changed after it was hashed: {first.path}"
        elif state == MISSING:
            problems[host] = f"hashed worksheet is missing: {first.path}"
        else:
            problems[host] = None
    return problems


def worksheets_hashed(ledger: PathLike, hosts: Sequence[str]) -> Dict[str, bool]:
    """host -> True only if a worksheet row exists for its worksheet file and
    the file still matches the first such row."""
    return {host: reason is None for host, reason in worksheet_problems(ledger, hosts).items()}


def record_seal_opened(ledger: PathLike, command: str, config_path: PathLike, status: SealStatus) -> LedgerRow:
    """Append the seal-opening row of a command that opens the seal (it is
    about to show tool results): one STUDY row of kind protocol for the
    configuration file used (archived like any row), with the note
    "seal opened by <command>: hosts H1, H2, H3; withdrawn: none" (or
    "withdrawn: H4, H5"), and return it. `status` is the open seal
    (seal_status); a status with problems is refused. The note names host
    codes only."""
    if not status.ok:
        raise StudyError("the seal is not open, so no seal-opening row was recorded")
    command = " ".join(str(command or "").split())
    if not command:
        raise StudyError("record_seal_opened needs the name of the command that opened the seal")
    hosts = ", ".join(status.hosts) or "none"
    withdrawn = ", ".join(sorted(status.withdrawn)) or "none"
    note = f"{SEAL_OPENED_NOTE_PREFIX}{command}: hosts {hosts}; withdrawn: {withdrawn}"
    return _record_files(ledger, STUDY_HOST_CODE, PROTOCOL_KIND, [config_path], note=note, event=True)[0][0]


def record_forced_unseal(ledger: PathLike, config_path: PathLike, reason: str) -> LedgerRow:
    """Append the row of register-sheet --force-before-unseal (a seal opening
    while the seal is closed): one STUDY row of kind other for the
    configuration file used, note FORCE_NOTE_PREFIX + reason, and return it."""
    reason = " ".join(str(reason or "").split())
    if not reason:
        raise StudyError("--force-before-unseal needs a non-empty --reason")
    return _record_files(ledger, STUDY_HOST_CODE, "other", [config_path], note=FORCE_NOTE_PREFIX + reason,
                         event=True)[0][0]


def withdraw_host(ledger: PathLike, host: str, reason: str, config_path: Optional[PathLike] = None,
                  after_unseal: bool = False) -> LedgerRow:
    """Append a withdrawal row for `host` (kind protocol, path = the study
    configuration, note 'withdrawn: <reason>') and return it. Refuses STUDY,
    an empty reason, a host already withdrawn, a study.yaml next to the
    ledger that changed since it was last recorded (study_config_problem),
    and a code that is not one of the study's hosts (seal_status), so a typo
    never adds a permanent row. Once the seal was opened (first_seal_opening)
    a withdrawal is a post-hoc exclusion: it is refused unless
    `after_unseal`, and its reason then starts '(after the seal was opened) '.
    `after_unseal` before any seal opening is refused too."""
    ledger = Path(ledger)
    host = validate_host_code(host)
    if is_study_code(host):
        raise StudyError(f"{STUDY_HOST_CODE} is not a host; give the code of the host that will not be "
                         "assessed, such as H3")
    reason = " ".join(str(reason or "").split())
    if not reason:
        raise StudyError("--reason must say why the host will not be assessed")
    folder = ledger.resolve().parent
    config_file = Path(config_path) if config_path is not None else folder / CONFIG_FILE
    if not config_file.is_file():
        raise StudyError(f"study configuration not found: {config_file} (give it with --config)")
    config = load_config(config_file)
    rows = read_ledger(ledger)
    already = withdrawn_hosts(rows)
    if host in already:
        when, why = already[host]
        raise StudyError(f"{host} was already withdrawn at {when} ({why}); nothing was recorded")
    changed = study_config_problem(ledger, rows, folder)
    if changed:
        raise StudyError(f"{changed}; record or restore {CONFIG_FILE} first; nothing was recorded")
    status = seal_status(folder, config, ledger_path=ledger)
    if host not in status.hosts:
        known = ", ".join(status.hosts) or "none"
        raise StudyError(f"{host} is not a host of this study (hosts: {known}); nothing was recorded")
    opened = first_seal_opening(rows)
    if opened is not None and not after_unseal:
        index, row = opened
        raise StudyError(f"the seal was opened at {row.recorded_at_utc} (ledger line {index + 2}): withdrawing "
                         f"{host} now is a post-hoc exclusion, which agreement reports as CRITICAL; add "
                         "--after-unseal to record it anyway")
    if after_unseal:
        if opened is None:
            raise StudyError("the seal has not been opened (the ledger has no seal-opening row), so --after-unseal "
                             "does not apply: withdraw without it; nothing was recorded")
        reason = AFTER_UNSEAL_REASON_PREFIX + reason
    return _record_files(ledger, host, PROTOCOL_KIND, [config_file], note=WITHDRAWN_NOTE_PREFIX + reason,
                         event=True)[0][0]


# ------------------------------------------------------------------ the assessor's input files
@dataclass
class AssessorInput:
    """One input file of a host as assessor_inputs reports it."""
    role: Optional[str]                  # "attestation", "inventory_record", or None (from the recorded name)
    rel_path: str                        # the path as recorded (its first row)
    sha256: str                          # the version the assessor had ("" when none was recorded in time)
    row_index: int                       # 0-based ledger index of the row giving it (-1 when none)
    recorded_at_utc: str                 # when that row was recorded ("" when none)
    later: List[Tuple[int, str, str]]    # (row_index, recorded_at_utc, sha256) after the first worksheet row


def input_role(recorded: str) -> Optional[str]:
    """ATTESTATION_ROLE for a recorded file name ending with -attestation.json,
    INVENTORY_ROLE for one ending with -inventory-record.json (any letter
    case), else None."""
    name = PureWindowsPath(recorded or "").name.lower()
    for suffix, role in ROLE_SUFFIXES:
        if name.endswith(suffix):
            return role
    return None


def assessor_inputs(ledger_path: PathLike, host: str) -> Tuple[Optional[str], List[AssessorInput]]:
    """The recorded_at_utc of `host`'s first worksheet row (kind worksheet,
    path DIR/worksheets/<H>-worksheet.csv, in ledger order), or None, and one
    AssessorInput per distinct input file of the host (rows of kind input
    with that host code; files compared as path_key compares them), in
    first-seen order. A file's assessor version is its latest input row
    recorded before the host's first worksheet row, in ledger order (with no
    worksheet row yet, its latest row); its rows after the worksheet row are
    `later`. A file first recorded after the worksheet row has no assessor
    version: sha256 '', row_index -1, recorded_at_utc ''. Reads only the
    ledger."""
    ledger = Path(ledger_path)
    host = validate_host_code(host)
    rows = read_ledger(ledger)
    target = file_key(worksheet_path(ledger.resolve().parent, host))
    sheet = next((index for index, row in enumerate(rows)
                  if row_kind(row) == WORKSHEET_KIND and path_key(ledger, row.path) == target), None)
    files: Dict[str, List[int]] = {}
    for index, row in enumerate(rows):
        if row_kind(row) != INPUT_KIND or (row.host_code or "").strip() != host:
            continue
        key = path_key(ledger, row.path)
        if key:
            files.setdefault(key, []).append(index)
    inputs: List[AssessorInput] = []
    for indices in files.values():
        before = indices if sheet is None else [index for index in indices if index < sheet]
        after = [] if sheet is None else [index for index in indices if index > sheet]
        first = rows[indices[0]]
        if before:
            chosen = rows[before[-1]]
            sha256, row_index, when = chosen.sha256, before[-1], chosen.recorded_at_utc
        else:
            sha256, row_index, when = "", -1, ""
        inputs.append(AssessorInput(role=input_role(first.path), rel_path=first.path, sha256=sha256,
                                    row_index=row_index, recorded_at_utc=when,
                                    later=[(index, rows[index].recorded_at_utc, rows[index].sha256)
                                           for index in after]))
    return (rows[sheet].recorded_at_utc if sheet is not None else None), inputs


def _sha_text(digest: str) -> str:
    """A SHA-256 taken from a run's provenance as messages show it: its
    first 12 characters when it is a hex digest, never other text."""
    return f"sha256 {digest[:12]}..." if _SHA256_RE.fullmatch(digest) else "no valid sha256"


def _other_role(role: str) -> str:
    return INVENTORY_ROLE if role == ATTESTATION_ROLE else ATTESTATION_ROLE


def _check_one_input(key: str, digest: str, inputs: Sequence[AssessorInput], host: str,
                     worksheet_at_utc: Optional[str]) -> List[Tuple[str, str]]:
    """The finding for one input the run had, or [] when it is the assessor's
    version of a file of its own role."""
    label, _ = _ROLE_WORDS[key]
    if any(item.role == key and item.sha256 == digest for item in inputs):
        return []
    other = _other_role(key)
    swapped = next((item for item in inputs if item.role == other and item.sha256 == digest), None)
    if swapped is not None:
        return [(INPUT_SWAPPED, f"the {label} the tool used ({_sha_text(digest)}) is {swapped.rel_path}, {host}'s "
                                f"{_ROLE_WORDS[other][0]} as recorded at {swapped.recorded_at_utc}: the two input "
                                "files were swapped or mixed up")]
    unknown = next((item for item in inputs if item.role is None and item.sha256 == digest), None)
    if unknown is not None:
        return [(INPUT_ROLE_UNKNOWN, f"cannot tell whether {unknown.rel_path} is an attestation or an inventory "
                                     f"record: name it {host}-attestation.json or {host}-inventory-record.json")]
    for item in inputs:
        for _, when, sha256 in item.later:
            if sha256 == digest:
                hashed = f" at {worksheet_at_utc}" if worksheet_at_utc else ""
                had = (f"the version recorded at {item.recorded_at_utc}" if item.sha256
                       else "no version of it recorded before then")
                return [(INPUT_LATER_VERSION, f"the tool used {item.rel_path} as recorded at {when}, after {host}'s "
                                              f"worksheet was hashed{hashed}; the assessor had {had}")]
    return [(INPUT_NOT_RECORDED, f"the {label} the tool used ({_sha_text(digest)}) is not one of the input files "
                                 f"recorded for {host} in the ledger")]


def check_run_inputs(given: Mapping[str, str], inputs: Sequence[AssessorInput], needs_inputs: bool, host: str,
                     worksheet_at_utc: Optional[str] = None) -> List[Tuple[str, str]]:
    """Whether a run's input files are the ones the assessor had. `given`
    maps "attestation" and "inventory_record" to the sha256 of the input the
    run had (a key is absent, or empty, when that input was not given; other
    keys are ignored), `inputs` is assessor_inputs(...)[1], `needs_inputs`
    whether an input-driven check was enabled, and `worksheet_at_utc` (the
    first value of assessor_inputs) the time quoted in a later-version
    message. Returns (code, message) pairs, codes from INPUT_CODES:

    - duplicate: the same sha256 given as attestation and inventory record;
    - otherwise per input given: accepted when it is the assessor version of
      a file of its own role; swapped when it is the other role's assessor
      version; accepted with a role-unknown pair when it is the assessor
      version of a file whose role is None; later-version when it is only a
      version recorded after the host's first worksheet row; not-recorded
      when it is none of these;
    - with needs_inputs, missing: a host with an attestation file needs an
      attestation given, one with an inventory-record file an inventory
      record; when a file's role is None, at least min(files, 2) of the two
      must be given.

    Messages name files, times and hash prefixes only."""
    digests: Dict[str, str] = {}
    for key in (ATTESTATION_ROLE, INVENTORY_ROLE):
        value = given.get(key)
        if isinstance(value, str) and value.strip():
            digests[key] = value.strip().lower()
    found: List[Tuple[str, str]] = []
    if len(digests) == 2 and digests[ATTESTATION_ROLE] == digests[INVENTORY_ROLE]:
        digest = digests[ATTESTATION_ROLE]
        same = next((item for item in inputs if item.sha256 == digest), None)
        where = f": {same.rel_path} as recorded at {same.recorded_at_utc}" if same is not None else ""
        found.append((INPUT_DUPLICATE, f"the run was given the same file ({_sha_text(digest)}) as --attestation "
                                       f"and as --inventory-record{where}"))
    else:
        for key, digest in digests.items():
            found.extend(_check_one_input(key, digest, inputs, host, worksheet_at_utc))
    if not needs_inputs:
        return found
    missing: List[Tuple[str, str]] = []
    for key in (ATTESTATION_ROLE, INVENTORY_ROLE):
        mine = next((item for item in inputs if item.role == key), None)
        if mine is not None and key not in digests:
            label, flag = _ROLE_WORDS[key]
            missing.append((INPUT_MISSING, f"the run had no {flag}, although the ledger holds {host}'s {label} "
                                           f"{mine.rel_path}"))
    if any(item.role is None for item in inputs):
        required = min(len(inputs), 2)
        if required - len(digests) > len(missing):
            missing.append((INPUT_MISSING, f"the ledger holds {len(inputs)} input file(s) for {host}, but the run had "
                                           f"{len(digests)} of --attestation and --inventory-record"))
    return found + missing


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
                                        "replaced), so a hashed file changed by accident can be restored. A file "
                                        "in worksheets/, outputs/ or register/, or one already recorded as a "
                                        "worksheet, tool output, facts file or register sheet, is hashed once: "
                                        "changed bytes are refused (whatever --force says), and the same bytes "
                                        "recorded again add no row. With --kind worksheet, each worksheet is then "
                                        "linted against the study configuration (blank or unreadable cells, the "
                                        "level range, levels that do not follow the declared manual level rule, "
                                        "the host code), because a hashed worksheet can never be corrected; any "
                                        "finding stops the record unless --force is given. The lint reads only "
                                        "the worksheet and the study configuration, never a tool output. A file "
                                        f"named {CONFIG_FILE} must be a valid study configuration.")
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
                             f"then starts '{LINT_NOTE_PREFIX.strip()}' and lists them. It never records a "
                             "hashed file whose bytes changed.")
    record.add_argument("paths", nargs="+", metavar="PATH", help="Files to hash.")

    verify = sub.add_parser("verify", help="Re-hash every recorded file.",
                            description="Re-hash every recorded file and report OK, CHANGED, MISSING, "
                                        "SUPERSEDED or ARCHIVED per row, plus OUT OF ORDER for a row dated "
                                        "earlier than a row above it; exit 0 only if every row is OK, "
                                        "SUPERSEDED or ARCHIVED and in order. Worksheets, tool outputs, facts "
                                        "and register sheets, and every file in worksheets/, outputs/ or "
                                        "register/, are never SUPERSEDED. ARCHIVED: a withdrawal or seal-opening "
                                        "row whose configuration file changed since, while its ledger-archive "
                                        "copy still has the recorded hash.")
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
                                          "of the seal; it cannot be undone. Once the seal was opened (register "
                                          "sheets or the analysis were produced), a withdrawal is a post-hoc "
                                          "exclusion and needs --after-unseal.")
    withdraw.add_argument("--ledger", required=True, metavar="FILE", help="The ledger CSV.")
    withdraw.add_argument("--host", required=True, metavar="H", help="The host that will not be assessed.")
    withdraw.add_argument("--reason", required=True, metavar="TEXT", help="Why (one line, also for the protocol log).")
    withdraw.add_argument("--config", default=None, metavar="FILE",
                          help=f"The study configuration recorded with the row (default: {CONFIG_FILE} next to "
                               "the ledger).")
    withdraw.add_argument("--after-unseal", action="store_true",
                          help="Record the withdrawal although the seal was already opened; the note then says "
                               "so, and agreement reports it as a post-hoc exclusion.")


def _print_outcomes(ledger: str, outcomes: Sequence[Tuple[LedgerRow, Optional[int]]]) -> None:
    """Per file: '<sha256>  <path>' and its archive copy, after an
    'already recorded at ...' line when no row was appended for it."""
    for row, index in outcomes:
        if index is not None:
            print(f"already recorded at {row.recorded_at_utc} (ledger line {index + 2}):")
        print(f"{row.sha256}  {row.path}")
        print(f"archive copy: {ledger_relpath(ledger, archive_path(ledger, row))}")


def _print_recorded(ledger: str, rows: Sequence[LedgerRow]) -> None:
    _print_outcomes(ledger, [(row, None) for row in rows])


def _lint_note(findings: Sequence[Tuple[Path, str, str]], several: bool) -> str:
    """The ledger note text listing lint findings (file names only when
    several files were recorded in one call)."""
    items = [(f"{path.name}: " if several else "") + f"{severity} {message}" for path, severity, message in findings]
    return LINT_NOTE_PREFIX + "; ".join(items)


def _lint_worksheets(args: argparse.Namespace, host: str, files: Sequence[Path]) -> str:
    """The pre-hash worksheet lint of `ledger record --kind worksheet`: each
    file not recorded yet is checked with agreement.lint_worksheet against
    the study configuration (--config, default study.yaml next to the
    ledger), and must be DIR/worksheets/<H>-worksheet.csv, the only file the
    seal counts as H's worksheet. Prints every finding (to stderr). Refuses
    when there is any, unless --force; returns the note to record. Only the
    worksheets and the configuration are read."""
    from miccmac_study import agreement  # imported here: agreement imports this module

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


# What `ledger record` may record a file in each sealed folder as. Such a file
# is hashed once, so a first row of another kind (say a blank worksheet
# recorded as "other") would leave it unrecordable under its own kind.
_FOLDER_KINDS = ((WORKSHEETS_DIR, (WORKSHEET_KIND,)),
                 (OUTPUTS_DIR, (TOOL_OUTPUT_KIND, FACTS_KIND)),
                 (REGISTER_DIR, ("register-review", "missed-gaps")))


def _check_kinds(ledger: Path, kind: str, files: Sequence[Path]) -> None:
    """`ledger record` refuses a file in worksheets/, outputs/ or register/
    next to the ledger under a kind other than that folder's own
    (_FOLDER_KINDS), and an input file whose name gives no role: it must end
    with -attestation.json or -inventory-record.json, or a swap of the two
    files could not be detected (check_run_inputs)."""
    folder = ledger.resolve().parent
    for name, kinds in _FOLDER_KINDS:
        if kind in kinds:
            continue
        key = file_key(folder / name)
        for path in files:
            if _in_folders(file_key(path), (key,)):
                allowed = " or ".join(f"--kind {value}" for value in kinds)
                raise StudyError(f"{path} is in {name}/, whose files are recorded only with {allowed} (each is "
                                 f"hashed once, under its own kind), not --kind {kind}; nothing was recorded")
    if kind == INPUT_KIND:
        for path in files:
            if input_role(str(path)) is None:
                raise StudyError(
                    f"{path}: name an input file <H>-attestation.json or <H>-inventory-record.json, so that its role "
                    "is known and a swap of the two files can be detected; nothing was recorded")


def _check_study_configs(files: Sequence[Path]) -> None:
    """A file named study.yaml (any letter case) is recorded only when it is
    a valid study configuration."""
    for path in files:
        if path.name.lower() != CONFIG_FILE.lower():
            continue
        try:
            load_config(path)
        except StudyError as exc:
            raise StudyError(f"{path} is not a valid study configuration: {exc}; nothing was recorded") from None


def _run_record(args: argparse.Namespace) -> int:
    if args.kind != WORKSHEET_KIND and (args.force or args.config is not None):
        raise StudyError("--config and --force belong to the worksheet lint and work only with --kind worksheet")
    note = " ".join(str(args.note or "").split())
    for prefix, owner in ((WITHDRAWN_NOTE_PREFIX, "ledger withdraw"),
                          (SEAL_OPENED_NOTE_PREFIX, "register-sheet and agreement"),
                          (FORCE_NOTE_PREFIX, "register-sheet --force-before-unseal")):
        if note.startswith(prefix):
            raise StudyError(f"a note starting {prefix.strip()!r} is written only by {owner}; nothing was recorded")
    host = validate_host_code(args.host)
    ledger = Path(args.ledger)
    files = [Path(p) for p in args.paths]
    missing = [str(p) for p in files if not p.is_file()]
    if missing:
        raise StudyError(f"cannot record missing file(s): {', '.join(missing)}")
    _check_kinds(ledger, args.kind, files)
    _check_study_configs(files)
    note = args.note
    if args.kind == WORKSHEET_KIND:
        # The sealed-path rule first: an edited, hashed sheet is refused with the restore advice, never linted.
        matches = _sealed_matches(ledger, _rows_for_append(ledger), args.kind, files,
                                  [_hash_file(path) for path in files])
        pending = [path for path, match in zip(files, matches) if match is None]
        if pending:
            note = _lint_worksheets(args, host, pending)
    _print_outcomes(args.ledger, _record_files(ledger, host, args.kind, files, note=note))
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
        if item.state == ARCHIVED:
            what = (f"{item.row.host_code} withdrawn" if is_withdrawal(item.row)
                    else "the configuration when the seal was opened")
            line += (f"  {what}; the file has changed since, and "
                     f"{ledger_relpath(args.ledger, archive_path(args.ledger, item.row))} keeps the recorded copy")
        if item.out_of_order:
            line += f"  OUT OF ORDER ({notes.get(item.index, '')})"
        print(line)
    clean = all(item.state in CLEAN_STATES and not item.out_of_order for item in states)
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
    row = withdraw_host(args.ledger, args.host, args.reason, config_path=args.config,
                        after_unseal=args.after_unseal)
    _print_recorded(args.ledger, [row])
    print(f"{row.host_code} withdrawn at {row.recorded_at_utc}: {row.note[len(WITHDRAWN_NOTE_PREFIX):]}")
    hashed = first_tool_row(read_ledger(args.ledger), row.host_code)
    if hashed is not None:
        print(f"note: {row.host_code}'s tool outputs were hashed at {hashed[1].recorded_at_utc}; agreement reports "
              "this withdrawal with that time", file=sys.stderr)
    return 0


def run(args: argparse.Namespace) -> int:
    if args.action == "record":
        return _run_record(args)
    if args.action == "verify":
        return _run_verify(args)
    if args.action == "withdraw":
        return _run_withdraw(args)
    return _run_status(args)
