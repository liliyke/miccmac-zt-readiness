"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Health check for sealed tool outputs and saved facts files (protocol section 5).

    python -m miccmac_study health [--expect-as-of YYYY-MM-DD] [--expect-commit SHA]
        [--list-checks FILE] [--pair] [--ledger FILE --host H] PATH [PATH ...]
    python -m miccmac_study health --inputs [--as-of YYYY-MM-DD] FILE [FILE ...]

After each sealed tool run the operator needs to know that the run worked,
without seeing any result. This command reads each file, works out whether
it is a saved facts envelope (it has facts_format) or a tool output (an
assessment JSON), and prints one line per test:

    ok      <test>
    PROBLEM <test>: <short reason>

It exits 0 only when every test is ok.

With --ledger FILE --host H, each tool output is also compared with H's rows
in the ledger, reporting yes/no only: its input files and facts file are the
ones hashed for H, and H's worksheet was hashed before the run.

With --inputs, the files are the researcher's attestation and inventory-record
files, checked before the study: miccmac's own checks run in-process on each
file alone (no facts) and the only thing reported is whether every date they
read from it is readable; a date the tool would report as ERROR is named with
its field and value (INV-04, ASM-01 and ASM-02 write nothing else into such a
detail). No other status, score or detail is ever printed.

It never prints a status value, score, level, level label, readiness tier,
check name, detail string, register entry, or a count of statuses or
entries. Every printed value is fixed text, a yes/no, a file path, or
something the operator chose before the run (dates, commit, methodology
name, check ids, extended-fact item names, host codes, the input files'
own date fields), and values read from a file are printed only after they
match a strict pattern.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY
from miccmac.model import PROPERTY_KEYS

from miccmac_study.formats import (
    FACTS_FORMAT,
    PROVENANCE_FORMAT,
    TOOL_STATUSES,
    LedgerRow,
    StudyError,
    ToolOutput,
    check_ids_fingerprint,
    load_tool_output,
    parse_utc_timestamp,
    read_ledger,
    sha256_file,
    validate_host_code,
    worksheet_name,
)
from miccmac_study.ledger import (
    FACTS_KIND,
    INPUT_KIND,
    is_study_code,
    path_key,
    row_kind,
    worksheet_rows,
)
from miccmac_study.worksheet import read_list_checks

PathLike = Union[str, Path]

_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_COMMIT_PREFIX_RE = re.compile(r"[0-9a-f]{4,40}")
# Ids and item names are echoed only when they look like identifiers.
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
_INPUT_KEYS = ("attestation", "inventory_record", "config")
# Statuses that mean part of the run did not work.
_FLAGGED_STATUSES = ("ERROR", "NOT_IMPLEMENTED")
_NOT_A_DATE = "missing or not a YYYY-MM-DD date"


@dataclass(frozen=True)
class HealthResult:
    """One test: what was tested, whether it is ok and, if not, why."""
    test: str
    ok: bool
    reason: str = ""

    def line(self) -> str:
        if self.ok:
            return f"ok      {self.test}"
        return f"PROBLEM {self.test}: {self.reason}"


def _result(label: str, test: str, ok: bool, reason: str = "") -> HealthResult:
    return HealthResult(f"{label}: {test}", ok, "" if ok else reason)


def _token(value: object) -> str:
    text = str(value)
    return text if _TOKEN_RE.fullmatch(text) else "<unprintable>"


def _non_blank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_iso_date(value: object) -> bool:
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        return False
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _is_timestamp(value: object) -> bool:
    if not _non_blank(value):
        return False
    try:
        parse_utc_timestamp(str(value))
    except StudyError:
        return False
    return True


def _as_of_result(label: str, value: object, expect_as_of: Optional[str]) -> HealthResult:
    valid = _is_iso_date(value)
    if expect_as_of is not None:
        reason = f"found {value}" if valid else _NOT_A_DATE
        return _result(label, f"as_of is {expect_as_of}", valid and value == expect_as_of, reason)
    test = f"as_of present ({value})" if valid else "as_of present"
    return _result(label, test, valid, _NOT_A_DATE)


# ------------------------------------------------------------------ facts envelope
def _extended_facts_results(label: str, facts: object) -> List[HealthResult]:
    """How many extended facts were collected, naming only the items that
    were not (never their data or error text). An item that could not be
    collected is information, not a problem: every extended item is
    optional and no check reads them in this version. A facts file with no
    extended section at all was not saved by --save-facts, which always
    collects one, so that is a problem."""
    if not isinstance(facts, dict) or "extra" not in facts:
        return [_result(label, "extended facts present", False,
                        "no extended section (facts saved with --save-facts always have one)")]
    extra = facts["extra"]
    if not isinstance(extra, dict):
        return [_result(label, "extended facts present", False, "extra is not a mapping")]
    collected = sum(1 for item in extra.values() if isinstance(item, dict) and item.get("ok") is True)
    not_collected = sorted({
        _token(name) for name, item in extra.items()
        if not (isinstance(item, dict) and item.get("ok") is True)
    })
    test = f"extended facts: {collected} of {len(extra)} items collected"
    if not_collected:
        test += " (not collected: " + ", ".join(not_collected) + ")"
    return [_result(label, test, True)]


def check_facts_file(label: str, data: dict, expect_as_of: Optional[str] = None) -> List[HealthResult]:
    """Tests for one saved facts envelope (miccmac --save-facts)."""
    facts = data.get("facts")
    os_info = facts.get("os") if isinstance(facts, dict) else None
    results = [
        _result(label, f"facts format {FACTS_FORMAT}", data.get("facts_format") == FACTS_FORMAT,
                "unexpected facts_format"),
        _result(label, "collected_at_utc is a UTC timestamp", _is_timestamp(data.get("collected_at_utc")),
                "missing or not a timestamp"),
        _as_of_result(label, data.get("as_of"), expect_as_of),
        _result(label, "connector and target recorded",
                _non_blank(data.get("connector")) and _non_blank(data.get("target")),
                "connector or target missing"),
        _result(label, "facts include os.platform",
                isinstance(os_info, dict) and _non_blank(os_info.get("platform")),
                "facts missing, or without os.platform"),
    ]
    results.extend(_extended_facts_results(label, facts))
    return results


# ------------------------------------------------------------------ tool output
def _check_list(assessment: dict) -> Optional[List[dict]]:
    """Every check dict in report order, or None if any entry is malformed."""
    checks = []
    for prop in assessment.get("properties", []):
        if not isinstance(prop, dict) or not isinstance(prop.get("checks"), list):
            return None
        for check in prop["checks"]:
            if not isinstance(check, dict) or not _non_blank(check.get("check_id")):
                return None
            checks.append(check)
    return checks


def _excluded_ids(assessment: dict) -> List[str]:
    raw = assessment.get("excluded_check_ids") or []
    return [item for item in raw if isinstance(item, str)] if isinstance(raw, list) else []


def _enabled_orders(assessment: dict) -> List[List[str]]:
    """The output's enabled check ids (excluded ones left out), in miccmac's
    list-checks order (sorted within each property) and in report order.
    The two differ only when a custom check plugin reports its checks in an
    order of its own."""
    excluded = set(_excluded_ids(assessment))
    canonical: List[str] = []
    report: List[str] = []
    for prop in assessment["properties"]:
        ids = [check["check_id"] for check in prop["checks"] if check["check_id"] not in excluded]
        canonical.extend(sorted(ids))
        report.extend(ids)
    return [canonical] if canonical == report else [canonical, report]


def _list_checks_result(label: str, list_checks: List[str], enabled: List[List[str]]) -> HealthResult:
    test = "check ids match --list-checks"
    if any(list_checks == candidate for candidate in enabled):
        return _result(label, test, True)
    expected = enabled[0]
    not_enabled = [_token(c) for c in list_checks if c not in expected]
    not_listed = [_token(c) for c in expected if c not in list_checks]
    parts = []
    if not_enabled:
        parts.append("not enabled in the output: " + ", ".join(not_enabled))
    if not_listed:
        parts.append("enabled in the output but not in --list-checks: " + ", ".join(not_listed))
    return _result(label, test, False, "; ".join(parts) or "same check ids in a different order")


def _check_results(label: str, assessment: dict, checks: List[dict],
                   list_checks: Optional[List[str]]) -> List[HealthResult]:
    ids = [check["check_id"] for check in checks]
    results = []
    if len(set(ids)) != len(ids):
        results.append(_result(label, "check ids unique", False, "a check id appears more than once"))
    if list_checks is not None:
        results.append(_list_checks_result(label, list_checks, _enabled_orders(assessment)))
    else:
        results.append(_result(label, f"{len(ids)} checks (no --list-checks given)", True))
    statuses = [check.get("status") for check in checks]
    results.append(_result(label, "every status is a known value",
                           all(isinstance(s, str) and s in TOOL_STATUSES for s in statuses),
                           "a check has an unrecognized status"))
    flagged = any(s in _FLAGGED_STATUSES for s in statuses if isinstance(s, str))
    test = "ERROR or NOT_IMPLEMENTED present" + ("" if flagged else ": no")
    results.append(_result(label, test, not flagged, "yes"))
    return results


def _commit_result(label: str, commit: object, expect_commit: Optional[str]) -> HealthResult:
    value = commit.lower() if isinstance(commit, str) else ""
    valid = bool(_COMMIT_RE.fullmatch(value))
    if expect_commit is not None:
        reason = f"found {value[:12]}" if valid else "tool_commit not recorded"
        return _result(label, f"tool_commit starts with {expect_commit}",
                       valid and value.startswith(expect_commit), reason)
    test = f"tool_commit recorded ({value[:12]})" if valid else "tool_commit recorded"
    return _result(label, test, valid, "missing or not a 40-character commit hash")


def _tree_clean_result(label: str, provenance: dict) -> HealthResult:
    clean = provenance.get("tool_tree_clean")
    reason = "the tool's working tree had uncommitted changes" if clean is False else "not recorded"
    return _result(label, "tool_tree_clean is true", clean is True, reason)


def _methodology_result(label: str, assessment: dict, provenance: Optional[dict]) -> HealthResult:
    methodology = assessment.get("methodology")
    if not isinstance(methodology, dict):
        return _result(label, "methodology present", False, "no methodology block (run with --methodology)")
    name = methodology.get("name")
    if not isinstance(name, str) or name not in METHODOLOGY_REGISTRY:
        return _result(label, "methodology present", False, "unknown methodology name")
    test = f"methodology present ({name})"
    properties = methodology.get("properties")
    complete = (isinstance(methodology.get("overall"), dict) and isinstance(properties, dict)
                and all(key in properties for key in PROPERTY_KEYS))
    if not complete:
        return _result(label, test, False, "methodology block incomplete")
    if isinstance(provenance, dict) and provenance.get("methodology") != name:
        return _result(label, test, False, "provenance names a different methodology")
    return _result(label, test, True)


def _fingerprint_result(label: str, assessment: dict, checks: List[dict], provenance: dict) -> HealthResult:
    """The provenance's enabled-check fingerprint must match this output's own
    checks: its enabled ids in list-checks or report order, or (literally)
    every check id in report order, which is the same list when nothing is
    excluded."""
    test = "enabled check ids fingerprint matches the checks"
    recorded = provenance.get("enabled_check_ids_fingerprint")
    if not _non_blank(recorded):
        return _result(label, test, False, "fingerprint not recorded")
    candidates = _enabled_orders(assessment) + [[check["check_id"] for check in checks]]
    if recorded not in {check_ids_fingerprint(candidate) for candidate in candidates}:
        return _result(label, test, False, "fingerprint does not match the output's checks")
    listed = provenance.get("enabled_check_ids")
    if listed is not None:
        if not isinstance(listed, list) or listed not in candidates:
            return _result(label, test, False, "enabled_check_ids does not match the output's checks")
        if check_ids_fingerprint(listed) != recorded:
            return _result(label, test, False, "enabled_check_ids and its fingerprint disagree")
    return _result(label, test, True)


def _locate(recorded: object, output_dir: Path) -> Optional[Path]:
    """The recorded facts file: as recorded if absolute, else relative to the
    current folder or to the output's folder; finally the same file name in
    the output's folder (the study layout keeps them side by side). The hash
    comparison guards against picking up the wrong file."""
    if not _non_blank(recorded):
        return None
    raw = Path(str(recorded))
    candidates = [raw] if raw.is_absolute() else [Path.cwd() / raw, output_dir / raw]
    name = PureWindowsPath(str(recorded)).name
    if name:
        candidates.append(output_dir / name)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _facts_file_result(label: str, facts_file: object, output_dir: Path) -> HealthResult:
    test = "facts file hash matches"
    recorded_hash = facts_file.get("sha256") if isinstance(facts_file, dict) else None
    if not _non_blank(recorded_hash):
        return _result(label, test, False, "no facts file recorded in provenance (run with --save-facts)")
    found = _locate(facts_file.get("path"), output_dir)
    if found is None:
        return _result(label, test, False, "facts file not found")
    try:
        digest = sha256_file(found)
    except OSError:
        return _result(label, test, False, "facts file could not be read")
    return _result(label, test, digest == str(recorded_hash).lower(),
                   "facts file differs from the hash recorded at run time")


def _register_result(label: str, output: ToolOutput, provenance: Optional[dict]) -> HealthResult:
    present = output.risk_register is not None
    recorded = provenance.get("risk_register") if isinstance(provenance, dict) else None
    consistent = not isinstance(recorded, bool) or recorded == present
    return _result(label, f"risk register present: {'yes' if present else 'no'}", consistent,
                   "provenance records the opposite")


def check_tool_output(label: str, output: ToolOutput, expect_as_of: Optional[str] = None,
                      expect_commit: Optional[str] = None,
                      list_checks: Optional[List[str]] = None) -> List[HealthResult]:
    """Tests for one tool output (miccmac assess --format json)."""
    assessment = output.assessment
    results = [_result(label, "assessment JSON readable", True)]
    keys = [prop.get("key") if isinstance(prop, dict) else None for prop in assessment["properties"]]
    results.append(_result(label, "7 properties in MICCMAC order", keys == list(PROPERTY_KEYS),
                           f"found {len(keys)} properties" if len(keys) != len(PROPERTY_KEYS)
                           else "properties out of order or unknown"))
    checks = _check_list(assessment)
    if checks is None:
        results.append(_result(label, "check list readable", False, "a property or check entry is malformed"))
    else:
        results.extend(_check_results(label, assessment, checks, list_checks))

    provenance = assessment.get("provenance")
    if not isinstance(provenance, dict):
        results.append(_result(label, f"provenance present ({PROVENANCE_FORMAT})", False, "no provenance block"))
        provenance = None
    else:
        results.append(_result(label, f"provenance present ({PROVENANCE_FORMAT})",
                               provenance.get("provenance_format") == PROVENANCE_FORMAT,
                               "unexpected provenance_format"))
        results.append(_as_of_result(label, provenance.get("as_of"), expect_as_of))
        results.append(_commit_result(label, provenance.get("tool_commit"), expect_commit))
        results.append(_tree_clean_result(label, provenance))
    results.append(_methodology_result(label, assessment, provenance))
    if provenance is not None:
        if checks is not None:
            results.append(_fingerprint_result(label, assessment, checks, provenance))
        results.append(_facts_file_result(label, provenance.get("facts_file"), output.path.parent))
    results.append(_register_result(label, output, provenance))
    return results


# ------------------------------------------------------------------ --pair
def _all_equal(values: Sequence[object]) -> bool:
    return all(value == values[0] for value in values[1:])


def _status_map(output: ToolOutput) -> Optional[Dict[str, object]]:
    checks = _check_list(output.assessment)
    if checks is None:
        return None
    return {check["check_id"]: check.get("status") for check in checks}


def _input_hashes(provenance: dict) -> Optional[Tuple[Tuple[str, Optional[str]], ...]]:
    inputs = provenance.get("inputs")
    if not isinstance(inputs, dict):
        return None
    hashes = []
    for key in _INPUT_KEYS:
        entry = inputs.get(key)
        if entry is not None and not isinstance(entry, dict):
            return None
        hashes.append((key, entry.get("sha256") if entry else None))
    return tuple(hashes)


def _same(test: str, values: Sequence[object], missing: str = "not recorded in every output") -> HealthResult:
    """'<test>: yes' when every value is present and identical, else a
    problem whose reason is only 'no' or why a value is missing."""
    if any(value is None for value in values):
        return HealthResult(test, False, missing)
    if _all_equal(values):
        return HealthResult(f"{test}: yes", True)
    return HealthResult(test, False, "no")


def check_pair(outputs: Sequence[Tuple[str, ToolOutput]]) -> List[HealthResult]:
    """Tests across tool outputs that should come from one run's facts (for
    example the same host scored with two methodologies). Reports yes/no only."""
    if len(outputs) < 2:
        return [HealthResult("pair", False, "needs at least two readable tool outputs")]
    assessments = [output.assessment for _, output in outputs]
    provenances = [a.get("provenance") if isinstance(a.get("provenance"), dict) else {} for a in assessments]
    targets = [a.get("target") or None for a in assessments]
    status_maps = [_status_map(output) for _, output in outputs]
    facts_hashes = [(p.get("facts_file").get("sha256") or None) if isinstance(p.get("facts_file"), dict) else None
                    for p in provenances]
    return [
        HealthResult("pair: same target", None not in targets and _all_equal(targets),
                     "the outputs are not all for the same target"),
        _same("pair: per-check statuses identical", status_maps, missing="a check list is malformed"),
        _same("pair: facts_file.sha256 identical", facts_hashes),
        _same("pair: input hashes identical", [_input_hashes(p) for p in provenances]),
        _same("pair: as_of identical", [p.get("as_of") or None for p in provenances]),
    ]


# ------------------------------------------------------------------ --ledger FILE --host H
def _yes_no(label: str, test: str, ok: bool, reason: str = "no") -> HealthResult:
    """'<label>: <test>: yes' when ok, else a problem with a fixed reason."""
    if ok:
        return HealthResult(f"{label}: {test}: yes", True)
    return HealthResult(f"{label}: {test}", False, reason)


def _sha(entry: object) -> Optional[str]:
    """The sha256 of a provenance file record, or None when there is none."""
    if not isinstance(entry, dict):
        return None
    value = entry.get("sha256")
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _given_inputs(provenance: dict) -> Dict[str, str]:
    """Provenance input key (attestation, inventory_record, config) -> sha256,
    for the inputs the run was given."""
    inputs = provenance.get("inputs")
    if not isinstance(inputs, dict):
        return {}
    given = {}
    for key in _INPUT_KEYS:
        digest = _sha(inputs.get(key))
        if digest is not None:
            given[key] = digest
    return given


def _optional_time(raw: object) -> Optional[dt.datetime]:
    if not _non_blank(raw):
        return None
    try:
        return parse_utc_timestamp(str(raw))
    except StudyError:
        return None


def check_against_ledger(label: str, output: ToolOutput, host: str, ledger: PathLike,
                         rows: Sequence[LedgerRow]) -> List[HealthResult]:
    """Yes/no tests linking one tool output to host H's ledger rows:

    - inputs match the ledger for H: every input the run was given has the
      sha256 of one of H's rows of kind input (the miccmac config may
      instead match a STUDY row); a problem when H has no input rows;
    - inputs given (only when H has input rows): the run was given an
      attestation and an inventory record for as many of them as the
      ledger holds input files for H (at most two);
    - facts file matches the ledger: provenance facts_file.sha256 is the
      sha256 of one of H's facts rows;
    - worksheet hashed before this run: the first worksheet row for
      <ledger folder>/worksheets/H-worksheet.csv is strictly earlier than
      the run's run_at_utc and facts_collected_at_utc.

    Only file hashes and times are compared; no result is read."""
    provenance = output.provenance if isinstance(output.provenance, dict) else None
    if provenance is None:
        return [_result(label, f"matches the ledger for {host}", False, "no provenance block")]
    results: List[HealthResult] = []

    input_rows = [row for row in rows if row.host_code == host and row_kind(row) == INPUT_KIND]
    given = _given_inputs(provenance)
    test = f"inputs match the ledger for {host}"
    if not input_rows:
        results.append(_result(label, test, False, f"no input rows for {host} in the ledger"))
    else:
        host_hashes = {row.sha256 for row in input_rows}
        study_hashes = {row.sha256 for row in rows if is_study_code(row.host_code)}
        unmatched = [key for key, digest in given.items()
                     if digest not in host_hashes and not (key == "config" and digest in study_hashes)]
        results.append(_yes_no(label, test, not unmatched, f"no ({', '.join(unmatched)})"))
        files = len({path_key(ledger, row.path) for row in input_rows})
        required = min(files, 2)
        count = sum(1 for key in ("attestation", "inventory_record") if key in given)
        results.append(_yes_no(label, "inputs given", count >= required,
                               f"no (the ledger holds {files} input file(s) for {host}, but the run had "
                               f"{count} of --attestation and --inventory-record)"))

    test = "facts file matches the ledger"
    facts_rows = [row for row in rows if row.host_code == host and row_kind(row) == FACTS_KIND]
    digest = _sha(provenance.get("facts_file"))
    if digest is None:
        results.append(_result(label, test, False, "no facts file recorded in provenance"))
    elif not facts_rows:
        results.append(_result(label, test, False, f"no facts rows for {host} in the ledger"))
    else:
        results.append(_yes_no(label, test, digest in {row.sha256 for row in facts_rows}))

    test = "worksheet hashed before this run"
    sheet_rows = worksheet_rows(ledger, rows, Path(ledger).resolve().parent, host)
    times = [_optional_time(row.recorded_at_utc) for row in sheet_rows]
    run_at = _optional_time(provenance.get("run_at_utc"))
    collected = _optional_time(provenance.get("facts_collected_at_utc"))
    if not sheet_rows:
        results.append(_result(label, test, False,
                               f"no worksheet row for worksheets/{worksheet_name(host)} in the ledger"))
    elif any(moment is None for moment in times):
        results.append(_result(label, test, False, "a worksheet row's recorded_at_utc is not a timestamp"))
    elif run_at is None or collected is None:
        results.append(_result(label, test, False, "run_at_utc or facts_collected_at_utc not recorded"))
    else:
        hashed = min(moment for moment in times if moment is not None)
        results.append(_yes_no(label, test, hashed < run_at and hashed < collected))
    return results


# ------------------------------------------------------------------ --inputs
# The only checks whose ERROR comes from an input file. Their ERROR detail
# is, by their code (miccmac/checks/assessed.py, inventoried.py), exactly
# "Attestation's <field>=<value> is not a valid ISO date." or "Supplied
# inventory record's last_reviewed=<value> is not a valid ISO date.": the
# field and the researcher's own value, nothing about a host.
_DATE_DETAIL_CHECKS = ("INV-04", "ASM-01", "ASM-02")
_STUB_TARGET = "input-check"


def _error_checks(assessment) -> List[Tuple[str, str]]:
    """(check id, detail) of every check whose status is ERROR."""
    from miccmac.model import Status

    return [(check.check_id, check.detail or "") for prop in assessment.properties for check in prop.checks
            if check.status == Status.ERROR]


def check_input_files(paths: Sequence[PathLike], as_of: Optional[str] = None) -> List[HealthResult]:
    """For each attestation or inventory-record file: run miccmac's checks
    in-process with that file as both inputs and no facts (an empty facts
    mapping, so the inventory checks run too), and report either that every
    date the checks read from it is readable, or each check that reports
    ERROR. The file is read the way miccmac reads --attestation and
    --inventory-record. Nothing else of the run is reported."""
    from miccmac.cli import _load_json_file  # the tool's own reader: accept exactly what the tool accepts
    from miccmac.config import Config, ConfigError
    from miccmac.engine import run_assessment

    base: Dict[str, object] = {"facts": {}}
    if as_of is not None:
        if not _is_iso_date(as_of):
            raise StudyError(f"--as-of {as_of!r} must be a YYYY-MM-DD date")
        base["as_of"] = dt.date.fromisoformat(as_of)
    baseline: Set[str] = {check_id for check_id, _ in
                          _error_checks(run_assessment(_STUB_TARGET, context=dict(base), config=Config()))}
    results: List[HealthResult] = []
    for raw in paths:
        label = str(raw)
        try:
            value, _ = _load_json_file(str(raw), "input")
        except ConfigError as exc:
            results.append(HealthResult(f"{label}: readable input file", False, str(exc)))
            continue
        context = dict(base, attestation=value, inventory_record=value)
        try:
            assessment = run_assessment(_STUB_TARGET, context=context, config=Config())
        except Exception as exc:  # the tool would stop on this file too
            results.append(HealthResult(f"{label}: miccmac's checks run with this file", False,
                                        f"{type(exc).__name__}: {exc}"))
            continue
        errors = [(check_id, detail) for check_id, detail in _error_checks(assessment) if check_id not in baseline]
        if not errors:
            results.append(HealthResult(f"{label}: every date the checks read is readable", True))
        for check_id, detail in errors:
            reason = detail if check_id in _DATE_DETAIL_CHECKS else "it cannot be evaluated with this file"
            results.append(HealthResult(f"{label}: {_token(check_id)} cannot read a date", False, reason))
    return results


# ------------------------------------------------------------------ files and options
def _read_json(path: Path) -> Tuple[object, Optional[str]]:
    """(parsed JSON, None) or (None, why it could not be read). Plain UTF-8
    only, as miccmac writes it and as the analysis reads it."""
    if not path.is_file():
        return None, "file not found"
    try:
        text = path.read_bytes().decode("utf-8")
    except OSError:
        return None, "file could not be read"
    except UnicodeDecodeError:
        return None, "not UTF-8 text"
    if text.startswith("﻿"):
        return None, "starts with a byte-order mark; save it as plain UTF-8"
    try:
        return json.loads(text), None
    except ValueError:
        return None, "not valid JSON"


def _expect_as_of(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    if not _is_iso_date(raw):
        raise StudyError(f"--expect-as-of {raw!r} must be a YYYY-MM-DD date")
    return raw


def _expect_commit(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    value = raw.strip().lower()
    if not _COMMIT_PREFIX_RE.fullmatch(value):
        raise StudyError(f"--expect-commit {raw!r} must be 4 to 40 hexadecimal characters")
    return value


def _ledger_rows(ledger: Optional[PathLike], host: Optional[str]) -> Optional[List[LedgerRow]]:
    """The ledger rows for --ledger/--host, or None when neither is given."""
    if ledger is None and host is None:
        return None
    if ledger is None or host is None:
        raise StudyError("--ledger and --host go together")
    validate_host_code(host)
    if is_study_code(host):
        raise StudyError("--host takes a host code such as H1, not STUDY")
    if not Path(ledger).is_file():
        raise StudyError(f"ledger {ledger} not found")
    return read_ledger(ledger)


def run_health(paths: Sequence[PathLike], expect_as_of: Optional[str] = None,
               expect_commit: Optional[str] = None, list_checks: Optional[PathLike] = None,
               pair: bool = False, ledger: Optional[PathLike] = None,
               host: Optional[str] = None) -> List[HealthResult]:
    """Every test for every file, in the order given, then the --pair tests.
    With `ledger` and `host`, each tool output's tests end with the
    check_against_ledger tests."""
    expect_as_of = _expect_as_of(expect_as_of)
    expect_commit = _expect_commit(expect_commit)
    listed = read_list_checks(list_checks) if list_checks is not None else None
    ledger_rows = _ledger_rows(ledger, host)

    results: List[HealthResult] = []
    outputs: List[Tuple[str, ToolOutput]] = []
    for raw in paths:
        label = str(raw)
        path = Path(raw)
        data, problem = _read_json(path)
        if problem is not None:
            results.append(HealthResult(f"{label}: readable JSON file", False, problem))
        elif isinstance(data, dict) and "facts_format" in data:
            results.extend(check_facts_file(label, data, expect_as_of))
        elif isinstance(data, dict) and ("assessment" in data or "properties" in data):
            try:
                output = load_tool_output(path)
            except StudyError:
                results.append(HealthResult(f"{label}: assessment JSON readable", False,
                                            "not a miccmac assessment JSON file"))
                continue
            results.extend(check_tool_output(label, output, expect_as_of, expect_commit, listed))
            if ledger_rows is not None and ledger is not None and host is not None:
                results.extend(check_against_ledger(label, output, host, ledger, ledger_rows))
            outputs.append((label, output))
        else:
            results.append(HealthResult(f"{label}: file type", False,
                                        "neither a facts file nor a tool output"))
    if pair:
        results.extend(check_pair(outputs))
    return results


# ------------------------------------------------------------------ command line
def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--expect-as-of", default=None, metavar="YYYY-MM-DD",
                        help="The session date every file's as_of must equal.")
    parser.add_argument("--expect-commit", default=None, metavar="SHA",
                        help="Commit (or its first characters) the tool must have run from.")
    parser.add_argument("--list-checks", default=None, metavar="FILE",
                        help="The list-checks JSON the tool outputs' enabled check ids must equal.")
    parser.add_argument("--pair", action="store_true",
                        help="Also compare the tool outputs with each other (same target, statuses, "
                             "facts file, inputs, as_of), reporting yes/no only.")
    parser.add_argument("--ledger", default=None, metavar="FILE",
                        help="With --host: also check each tool output against that host's ledger rows "
                             "(input files, facts file, worksheet hashed before the run), yes/no only.")
    parser.add_argument("--host", default=None, metavar="H",
                        help="The host code whose ledger rows the tool outputs must match (with --ledger).")
    parser.add_argument("--inputs", action="store_true",
                        help="The files are attestation and inventory-record files, checked before the study: "
                             "report only whether every date the checks read from them is readable.")
    parser.add_argument("--as-of", default=None, metavar="YYYY-MM-DD",
                        help="With --inputs: the reference date to run the checks with (the session date).")
    parser.add_argument("paths", nargs="+", metavar="PATH",
                        help="Facts files and tool outputs to check (with --inputs: input files).")


def run(args: argparse.Namespace) -> int:
    if args.inputs:
        others = [flag for flag, value in (("--expect-as-of", args.expect_as_of),
                                           ("--expect-commit", args.expect_commit),
                                           ("--list-checks", args.list_checks), ("--pair", args.pair),
                                           ("--ledger", args.ledger), ("--host", args.host)) if value]
        if others:
            raise StudyError(f"--inputs checks input files only; it cannot be combined with {', '.join(others)}")
        results = check_input_files(args.paths, as_of=args.as_of)
    else:
        if args.as_of is not None:
            raise StudyError("--as-of is only used with --inputs (for tool outputs and facts use --expect-as-of)")
        results = run_health(args.paths, expect_as_of=args.expect_as_of, expect_commit=args.expect_commit,
                             list_checks=args.list_checks, pair=args.pair, ledger=args.ledger, host=args.host)
    for result in results:
        print(result.line())
    return 0 if all(result.ok for result in results) else 1
