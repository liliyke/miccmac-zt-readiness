"""Shared formats for the study instruments: folder layout, file names, CSV
columns, the study configuration, the tool-output loader, and lenient parsing
of what a person types into a spreadsheet.

Plain CSV (UTF-8) and JSON only, with the standard library plus PyYAML
(already a miccmac dependency), so every study file stays readable without
this code. Change a format only before the protocol is frozen.

Study folder layout (keep it outside the public repository):

    <study>/study.yaml                      study configuration (see StudyConfig)
    <study>/ledger.csv                      SHA-256 ledger (LEDGER_COLUMNS)
    <study>/inputs/                         attestation / inventory / list-checks files
    <study>/worksheets/<H>-worksheet.csv    filled manual worksheet, hashed before the tool run
    <study>/outputs/<H>-<methodology>.json  tool output (sealed until every worksheet is hashed)
    <study>/outputs/<H>-facts.json          saved facts from --save-facts
    <study>/register/<H>-register-review.csv, <H>-missed-gaps.csv
    <study>/analysis/                       agreement outputs
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Union

import yaml

from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY
from miccmac.model import PROPERTY_KEYS


class StudyError(RuntimeError):
    """A problem with study files or options that the user must fix."""


# ------------------------------------------------------------------ layout
CONFIG_FILE = "study.yaml"
LEDGER_FILE = "ledger.csv"
INPUTS_DIR = "inputs"
WORKSHEETS_DIR = "worksheets"
OUTPUTS_DIR = "outputs"
REGISTER_DIR = "register"
ANALYSIS_DIR = "analysis"

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


def validate_host_code(host: str) -> str:
    """Host codes are opaque labels such as H1 (protocol section 3)."""
    if not isinstance(host, str) or not _HOST_RE.match(host):
        raise StudyError(
            f"invalid host code {host!r}: use 1-32 letters, digits, '-' or '_' (for example H1)"
        )
    return host


def worksheet_name(host: str) -> str:
    return f"{validate_host_code(host)}-worksheet.csv"


def tool_output_name(host: str, methodology: str) -> str:
    return f"{validate_host_code(host)}-{methodology}.json"


def facts_name(host: str) -> str:
    return f"{validate_host_code(host)}-facts.json"


def register_review_name(host: str) -> str:
    return f"{validate_host_code(host)}-register-review.csv"


def missed_gaps_name(host: str) -> str:
    return f"{validate_host_code(host)}-missed-gaps.csv"


# ------------------------------------------------------------------ checks and verdicts
# Statuses the tool writes (miccmac.model.Status values).
TOOL_STATUSES = ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "ERROR", "NOT_IMPLEMENTED")
# Verdicts the assessor may enter (protocol section 6). UNASSESSED checks are
# left out on both sides of every comparison.
MANUAL_VERDICTS = ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "UNASSESSED")
UNASSESSED = "UNASSESSED"

_VERDICT_ALIASES = {
    "PASS": "PASS",
    "PARTIAL": "PARTIAL",
    "FAIL": "FAIL",
    "N/A": "NOT_APPLICABLE",
    "NA": "NOT_APPLICABLE",
    "N.A.": "NOT_APPLICABLE",
    "NOT APPLICABLE": "NOT_APPLICABLE",
    "NOT_APPLICABLE": "NOT_APPLICABLE",
    "UNASSESSED": "UNASSESSED",
    "NOT ASSESSED": "UNASSESSED",
    "NOT_ASSESSED": "UNASSESSED",
}


def normalize_verdict(raw: Optional[str]) -> Optional[str]:
    """Canonical manual verdict, or None for a blank cell. Case and repeated
    spaces are ignored; anything else unrecognized raises StudyError."""
    text = " ".join((raw or "").split()).upper()
    if not text:
        return None
    try:
        return _VERDICT_ALIASES[text]
    except KeyError:
        raise StudyError(
            f"unrecognized verdict {raw!r}; use PASS, PARTIAL, FAIL, N/A or UNASSESSED"
        ) from None


# The 10 checks that read the organizational input files (protocol section 4);
# the other enabled checks are device-observable.
DEFAULT_INPUT_DRIVEN_CHECKS = (
    "INV-01", "INV-04", "CTL-03", "CLM-01", "CLM-02", "CLM-03",
    "ASM-01", "ASM-02", "ASM-03", "CUR-03",
)
# Properties that are fully input-driven (protocol sections 4 and 8).
DEFAULT_INPUT_DRIVEN_PROPERTIES = ("claimed", "assessed")


def check_ids_fingerprint(ids: Sequence[str]) -> str:
    """Short, order-sensitive fingerprint of an enabled check-id list: the
    first 16 hex characters of SHA-256 over the ids joined by ','. miccmac's
    provenance block uses the same formula, so the two can be compared."""
    return hashlib.sha256(",".join(ids).encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------------------ worksheet format
WORKSHEET_FORMAT = "miccmac-worksheet/1"
# One CSV per host. `value` holds the assessor's entry: the meta value, the
# check verdict, or the manual level.
WORKSHEET_COLUMNS = (
    "row_type", "item", "property", "description", "control_refs", "value",
    "pass_criterion", "evidence_procedure", "procedure_source",
    "evidence_notes", "unassessed_reason",
)
ROW_META = "meta"
ROW_CHECK = "check"
ROW_LEVEL = "level"
# Meta rows: item = field name, value = field value.
META_FIELDS = (
    "worksheet_format",            # WORKSHEET_FORMAT
    "host_code",                   # opaque code, e.g. H1
    "session_date",                # reference date, YYYY-MM-DD; the tool's --as-of uses the same date
    "assessor",                    # who filled it in
    "level_rule",                  # the manual level rule used (protocol section 6 decision)
    "methodologies",               # e.g. "cmmi;cisa-ztmm", the level rows provided
    "enabled_checks_fingerprint",  # check_ids_fingerprint() of the check rows
    "generated_at_utc",            # when the blank sheet was generated
    "synthetic",                   # "yes" only for pipeline-test data
)
# Level rows: item = methodology name, property = one of LEVEL_SCOPES,
# value = the manual level (an integer, or UNASSESSED).
OVERALL = "overall"
OVERALL_EXCL = "overall_excl_input_driven"
LEVEL_SCOPES = tuple(PROPERTY_KEYS) + (OVERALL, OVERALL_EXCL)

_LEVEL_UNASSESSED = {"UNASSESSED", "N/A", "NA", "NOT ASSESSED", "NOT_ASSESSED"}
_LEVEL_RE = re.compile(r"(?:L|LEVEL|S|STAGE)?\s*([0-9]+)(?:\.0+)?")


def parse_level(raw: Optional[str], max_level: int) -> Union[int, str, None]:
    """A manual level: an int in 1..max_level, UNASSESSED, or None if blank.
    Accepts '3', 'L3', 'Level 3', 'S2', '3.0'."""
    text = " ".join((raw or "").split()).upper()
    if not text:
        return None
    if text in _LEVEL_UNASSESSED:
        return UNASSESSED
    match = _LEVEL_RE.fullmatch(text)
    if not match:
        raise StudyError(f"unrecognized level {raw!r}; enter a number from 1 to {max_level} or UNASSESSED")
    level = int(match.group(1))
    if not 1 <= level <= max_level:
        raise StudyError(f"level {raw!r} is outside 1-{max_level}")
    return level


# ------------------------------------------------------------------ register review format
# One row per register entry, in the tool's order. The tool's columns first:
#   recommended_fix     the action to take now: the fix for a finding; for a
#                       missing-data entry, how to supply the data, then the fix
#                       (the entry's sp800_30.response; its remediation in an
#                       output that predates it)
#   entry_type          finding (FAIL, PARTIAL) or missing-data (ERROR, or an
#                       input not supplied)
#   rating_basis        what cis_ig, the FAIR bands and risk_rating apply to:
#                       "finding", or "if the control is absent" for missing data
#   missing_data, how_to_supply   what is missing and how to supply it
#                       (missing-data entries only)
#   next_level          the next-level hint of the primary methodology (blank in
#                       sheets forced before the seal opened)
#   threat_source_type, threat_event, sp800_30_review   the SP 800-30 fields
#                       drafted per check, and their review state
# Then the judgment columns, which only the researcher fills in:
#   accurate, actionable        Y or N (H2)
#   prioritized                 Y, N or UNSURE (secondary)
#   next_level_accurate         Y or N, optional and descriptive: is the hint right?
#   threat_plausible            Y or N, optional and descriptive: do the drafted
#                               threat source type and event fit the entry?
#   reason                      one line
REGISTER_REVIEW_COLUMNS = (
    "host_code", "entry_no", "check_id", "property", "name", "tool_status",
    "cis_ig", "fair_frequency", "fair_magnitude", "risk_rating", "detail",
    "recommended_fix", "entry_type", "rating_basis", "missing_data", "how_to_supply",
    "next_level", "threat_source_type", "threat_event", "sp800_30_review",
    "accurate", "actionable", "prioritized", "next_level_accurate", "threat_plausible", "reason",
)
MISSED_GAPS_COLUMNS = ("host_code", "gap_no", "check_id", "description", "evidence")

# Register entry types (miccmac.risk_register): a finding is a FAIL or PARTIAL
# check, a missing-data entry a check the tool could not evaluate.
ENTRY_FINDING = "finding"
ENTRY_MISSING_DATA = "missing-data"
ENTRY_TYPES = (ENTRY_FINDING, ENTRY_MISSING_DATA)


def register_entry_type(entry: Mapping[str, object]) -> str:
    """A register entry's type: its entry_type, or, in an output written
    before entry types existed (FAIL and PARTIAL entries only), the one its
    status gives."""
    kind = entry.get("entry_type")
    if kind in ENTRY_TYPES:
        return str(kind)
    return ENTRY_FINDING if entry.get("status") in ("FAIL", "PARTIAL") else ENTRY_MISSING_DATA


def normalize_yes_no(raw: Optional[str], allow_unsure: bool = False) -> Optional[str]:
    """'Y', 'N' (or 'UNSURE' when allowed), or None for a blank cell."""
    text = " ".join((raw or "").split()).upper()
    if not text:
        return None
    if text in ("Y", "YES"):
        return "Y"
    if text in ("N", "NO"):
        return "N"
    if allow_unsure and text in ("UNSURE", "U", "?", "NOT SURE"):
        return "UNSURE"
    allowed = "Y, N or UNSURE" if allow_unsure else "Y or N"
    raise StudyError(f"unrecognized answer {raw!r}; use {allowed}")


# ------------------------------------------------------------------ ledger format
LEDGER_COLUMNS = ("recorded_at_utc", "host_code", "kind", "path", "sha256", "bytes", "note")
LEDGER_KINDS = (
    "worksheet", "tool-output", "facts", "input", "list-checks",
    "register-review", "missed-gaps", "protocol", "other",
)


@dataclass(frozen=True)
class LedgerRow:
    recorded_at_utc: str
    host_code: str
    kind: str
    path: str      # relative to the ledger's folder (forward slashes) when inside it, else absolute
    sha256: str
    bytes: int
    note: str


def plain_path(path: Path) -> Path:
    """`path` without a Windows extended-length prefix (\\\\?\\C:\\x -> C:\\x,
    \\\\?\\UNC\\server\\share -> \\\\server\\share), which Path.resolve() keeps,
    so that both spellings of one file compare equal. Unchanged elsewhere."""
    if os.name != "nt":
        return path
    text = str(path)
    if text[:8].upper() == "\\\\?\\UNC\\":
        return Path("\\\\" + text[8:])
    # Only a drive-letter path: \\?\Volume{GUID}\... has no other spelling and stays as it is.
    if text.startswith("\\\\?\\") and len(text) > 5 and text[4].isalpha() and text[5] == ":":
        return Path(text[4:])
    return path


def ledger_relpath(ledger_file: Union[str, Path], file_path: Union[str, Path]) -> str:
    """How a file is recorded in the ledger: relative to the ledger's folder
    with forward slashes when it is inside that folder, else absolute."""
    base = plain_path(Path(ledger_file).resolve().parent)
    target = plain_path(Path(file_path).resolve())
    try:
        return target.relative_to(base).as_posix()
    except ValueError:
        return str(target)


def resolve_ledger_path(ledger_file: Union[str, Path], recorded: str) -> Path:
    """The file a ledger row refers to, as an absolute path (plain_path)."""
    path = Path(recorded)
    if not path.is_absolute():
        path = Path(ledger_file).resolve().parent / path
    return plain_path(path.resolve())


def read_ledger(ledger_file: Union[str, Path]) -> List[LedgerRow]:
    """All ledger rows in file order; an absent ledger is an empty list."""
    ledger_file = Path(ledger_file)
    if not ledger_file.exists():
        return []
    rows = []
    for raw in read_csv(ledger_file, LEDGER_COLUMNS):
        try:
            size = int(raw["bytes"] or 0)
        except ValueError:
            raise StudyError(f"{ledger_file}: bad byte count {raw['bytes']!r}") from None
        rows.append(LedgerRow(
            recorded_at_utc=raw["recorded_at_utc"], host_code=raw["host_code"], kind=raw["kind"],
            path=raw["path"], sha256=raw["sha256"].lower(), bytes=size, note=raw["note"],
        ))
    return rows

# ------------------------------------------------------------------ formats written by miccmac
FACTS_FORMAT = "miccmac-facts/1"            # --save-facts envelope
PROVENANCE_FORMAT = "miccmac-provenance/1"  # assessment["provenance"]

SYNTHETIC_BANNER = "SYNTHETIC DATA: pipeline test only, not study results"


# ------------------------------------------------------------------ helpers
def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc_timestamp(raw: str) -> dt.datetime:
    """Parse '2026-11-23T19:05:00Z' (or with +00:00) into an aware datetime."""
    text = (raw or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        value = dt.datetime.fromisoformat(text)
    except ValueError:
        raise StudyError(f"not an ISO 8601 timestamp: {raw!r}") from None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


def sha256_file(path: Union[str, Path]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


_US_DATE_RE = re.compile(r"(\d{1,2})/(\d{1,2})/(\d{2}|\d{4})")


def parse_date(raw: Optional[str]) -> dt.date:
    """A calendar date as typed or as Excel re-saves it: 2026-11-23,
    2026-11-23 00:00:00, 11/23/2026 or 11/23/26 (US month/day order)."""
    text = (raw or "").strip()
    if not text:
        raise StudyError("missing date")
    iso = text[:10]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", iso) and (len(text) == 10 or text[10] in " T"):
        try:
            return dt.date.fromisoformat(iso)
        except ValueError:
            raise StudyError(f"invalid date {raw!r}") from None
    match = _US_DATE_RE.fullmatch(text.split(" ")[0])
    if match:
        month, day, year = (int(g) for g in match.groups())
        if year < 100:
            year += 2000
        try:
            return dt.date(year, month, day)
        except ValueError:
            raise StudyError(f"invalid date {raw!r}") from None
    raise StudyError(f"unrecognized date {raw!r}; use YYYY-MM-DD")


def read_csv(path: Union[str, Path], required_columns: Iterable[str]) -> List[Dict[str, str]]:
    """Read a CSV as saved by this code or by Excel (UTF-8 with or without a
    BOM, or Windows-1252). Header names and cell values are stripped; fully
    blank rows are skipped. Missing required columns raise StudyError."""
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise StudyError(f"cannot read {path}: {exc}") from exc
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("cp1252")
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = [h.strip() for h in next(reader)]
    except StopIteration:
        raise StudyError(f"{path} is empty") from None
    missing = [c for c in required_columns if c not in header]
    if missing:
        raise StudyError(f"{path} is missing column(s): {', '.join(missing)}")
    rows: List[Dict[str, str]] = []
    for cells in reader:
        row = {name: (cells[i].strip() if i < len(cells) else "") for i, name in enumerate(header) if name}
        if any(row.values()):
            rows.append(row)
    return rows


def write_csv(path: Union[str, Path], columns: Sequence[str], rows: Iterable[Mapping[str, object]],
              overwrite: bool = False) -> Path:
    """Write a UTF-8 (with BOM, so Excel opens it cleanly) CSV. Refuses to
    replace an existing file unless overwrite=True, so a filled-in sheet is
    never clobbered by regenerating it."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise StudyError(f"{path} already exists; refusing to overwrite it")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(columns), extrasaction="raise")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: "" if row.get(c) is None else row.get(c) for c in columns})
    return path


def write_json(path: Union[str, Path], payload: object, overwrite: bool = False) -> Path:
    path = Path(path)
    if path.exists() and not overwrite:
        raise StudyError(f"{path} already exists; refusing to overwrite it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


# ------------------------------------------------------------------ study configuration
_CONFIG_KEYS = {
    "hosts", "threshold", "primary_methodology", "secondary_methodologies",
    "manual_max_level", "input_driven_checks", "input_driven_properties",
    "bootstrap", "weighted_kappa", "synthetic", "level_rule", "h2_unit",
}
# study.yaml h2_unit: which register entries the H2 threshold is tested on.
# all-entries (the default): every entry, findings and missing-data entries
# alike, as every entry is judged; findings: the findings only. agreement
# reports both either way; this names the pre-registered test.
H2_ALL_ENTRIES = "all-entries"
H2_FINDINGS = "findings"
H2_UNITS = (H2_ALL_ENTRIES, H2_FINDINGS)
_BOOTSTRAP_KEYS = {"iterations", "seed", "exact_limit"}

# study.yaml `level_rule` (protocol decision 4): how levels are derived on
# each side of the comparison.
#   manual:    the rule the assessor uses to turn verdicts into levels
#              (None = not declared).
#   tool_side: how the tool's levels are computed for the comparison
#              (default tool-cutoffs: miccmac's own scoring, as before).
#   overall:   the overall-level rule wherever an overall level is derived
#              under the approved rule (None = not declared).
LEVEL_RULE_APPROVED = "approved"          # approved Step 2 buckets on the pass ratio, levels 1-4
LEVEL_RULE_TOOL_CUTOFFS = "tool-cutoffs"  # miccmac's own scoring and methodology cutoffs
OVERALL_MEAN_OF_PROPERTY_RATIOS = "mean-of-property-ratios"
OVERALL_POOLED_CHECKS = "pooled-checks"
OVERALL_STEP4_BUCKETS = "step4-buckets"
OVERALL_STEP4_ROUNDED = "step4-rounded"
LEVEL_RULE_VALUES = {
    "manual": (LEVEL_RULE_APPROVED, LEVEL_RULE_TOOL_CUTOFFS),
    "tool_side": (LEVEL_RULE_TOOL_CUTOFFS, LEVEL_RULE_APPROVED),
    "overall": (OVERALL_MEAN_OF_PROPERTY_RATIOS, OVERALL_POOLED_CHECKS, OVERALL_STEP4_BUCKETS,
                OVERALL_STEP4_ROUNDED),
}
# The approved rule never assigns Level 5 (approved Step 2), for either methodology.
APPROVED_MAX_LEVEL = 4


def level_rule_value(key: str, value: object, label: Optional[str] = None) -> Optional[str]:
    """The canonical value for level_rule.<key> ("manual", "tool_side" or
    "overall"), or None for null or a blank value (not declared). Case and
    surrounding spaces are ignored; anything else unrecognized raises
    StudyError naming `label` (default "level_rule.<key>")."""
    allowed = LEVEL_RULE_VALUES[key]
    name = label or f"level_rule.{key}"
    if value is None:
        return None
    if not isinstance(value, str):
        raise StudyError(f"{name} must be one of {', '.join(allowed)} (or null), not {value!r}")
    text = value.strip().lower()
    if not text:
        return None
    if text not in allowed:
        raise StudyError(f"{name} {value!r} is not recognized; use one of {', '.join(allowed)}")
    return text


def methodology_level_count(name: str) -> int:
    try:
        return len(METHODOLOGY_REGISTRY[name].levels)
    except KeyError:
        raise StudyError(f"unknown methodology {name!r}; use one of {sorted(METHODOLOGY_REGISTRY)}") from None


@dataclass
class StudyConfig:
    """Settings the analysis reads from study.yaml. Defaults follow the
    protocol: threshold 0.80 (approved as a configurable default), CMMI
    primary, the 10 input-driven checks of section 4. The level_rule
    defaults (manual and overall not declared, tool side tool-cutoffs) give
    the same analysis as before level_rule existed."""
    hosts: List[str]
    threshold: Fraction = Fraction(4, 5)
    primary_methodology: str = "cmmi"
    secondary_methodologies: List[str] = field(default_factory=list)
    # Highest level the manual rule can assign, per methodology: 4 under the
    # approved rule (Level 5 never assigned from one run), or the tool's own
    # maximum (5 for CMMI, 4 for CISA ZTMM) if the tool's cutoffs are used.
    manual_max_level: Dict[str, int] = field(default_factory=dict)
    input_driven_checks: List[str] = field(default_factory=lambda: list(DEFAULT_INPUT_DRIVEN_CHECKS))
    input_driven_properties: List[str] = field(default_factory=lambda: list(DEFAULT_INPUT_DRIVEN_PROPERTIES))
    bootstrap_iterations: int = 10000
    bootstrap_seed: int = 20261122
    bootstrap_exact_limit: int = 1_000_000
    weighted_kappa: bool = False
    synthetic: bool = False
    # study.yaml level_rule (protocol decision 4); see LEVEL_RULE_VALUES.
    # Without a level_rule block: manual and overall not declared, tool side
    # tool-cutoffs, which gives the same results as before the block existed.
    manual_level_rule: Optional[str] = None
    tool_side_rule: str = LEVEL_RULE_TOOL_CUTOFFS
    overall_rule: Optional[str] = None
    # study.yaml h2_unit (H2_UNITS): the entries the H2 threshold applies to.
    h2_unit: str = H2_ALL_ENTRIES

    @property
    def methodologies(self) -> List[str]:
        return [self.primary_methodology] + list(self.secondary_methodologies)

    @property
    def level_rule(self) -> Dict[str, Optional[str]]:
        """The level_rule settings as {"manual", "tool_side", "overall"}."""
        return {"manual": self.manual_level_rule, "tool_side": self.tool_side_rule,
                "overall": self.overall_rule}

    def tool_max_level(self, methodology: str) -> int:
        """The top of the tool-side level scale used in the comparison: the
        methodology's own level count under tool-cutoffs (5 for CMMI, 4 for
        CISA ZTMM), and 4 under the approved rule, which never assigns L5."""
        native = methodology_level_count(methodology)
        if self.tool_side_rule == LEVEL_RULE_APPROVED:
            return min(APPROVED_MAX_LEVEL, native)
        return native

    def manual_max(self, methodology: str) -> int:
        """The manual cap: manual_max_level, or the methodology's own level
        count when it is not set (whatever the tool-side rule)."""
        return self.manual_max_level.get(methodology, methodology_level_count(methodology))


def _as_fraction(value: object) -> Fraction:
    try:
        fraction = Fraction(str(value).strip())
    except (ValueError, ZeroDivisionError):
        raise StudyError(f"threshold {value!r} is not a number") from None
    if not 0 < fraction <= 1:
        raise StudyError(f"threshold {value!r} must be greater than 0 and at most 1")
    return fraction


def study_config_from_dict(data: Mapping[str, object]) -> StudyConfig:
    if not isinstance(data, Mapping):
        raise StudyError("study configuration must be a mapping")
    unknown = set(data) - _CONFIG_KEYS
    if unknown:
        raise StudyError(f"unknown study configuration key(s): {', '.join(sorted(unknown))}")

    hosts = data.get("hosts")
    if not isinstance(hosts, list) or not hosts:
        raise StudyError("study configuration needs a non-empty 'hosts' list")
    hosts = [validate_host_code(str(h)) for h in hosts]
    if len(set(hosts)) != len(hosts):
        raise StudyError("duplicate host codes in 'hosts'")

    config = StudyConfig(hosts=hosts)
    if "threshold" in data:
        config.threshold = _as_fraction(data["threshold"])

    primary = str(data.get("primary_methodology", config.primary_methodology))
    methodology_level_count(primary)
    config.primary_methodology = primary
    secondary = data.get("secondary_methodologies") or []
    if not isinstance(secondary, list):
        raise StudyError("'secondary_methodologies' must be a list")
    secondary = [str(m) for m in secondary]
    for name in secondary:
        methodology_level_count(name)
    if primary in secondary or len(set(secondary)) != len(secondary):
        raise StudyError("'secondary_methodologies' must not repeat the primary or itself")
    config.secondary_methodologies = secondary

    max_levels = data.get("manual_max_level") or {}
    if not isinstance(max_levels, Mapping):
        raise StudyError("'manual_max_level' must map a methodology to a number")
    for name, value in max_levels.items():
        top = methodology_level_count(str(name))
        if not isinstance(value, int) or isinstance(value, bool) or not 2 <= value <= top:
            raise StudyError(f"manual_max_level for {name} must be a whole number from 2 to {top}")
        config.manual_max_level[str(name)] = value

    for key in ("input_driven_checks", "input_driven_properties"):
        if key in data:
            value = data[key]
            if not isinstance(value, list):
                raise StudyError(f"'{key}' must be a list")
            setattr(config, key, [str(v) for v in value])
    bad_props = set(config.input_driven_properties) - set(PROPERTY_KEYS)
    if bad_props:
        raise StudyError(f"unknown property key(s) in input_driven_properties: {sorted(bad_props)}")

    bootstrap = data.get("bootstrap") or {}
    if not isinstance(bootstrap, Mapping) or set(bootstrap) - _BOOTSTRAP_KEYS:
        raise StudyError(f"'bootstrap' may only set {sorted(_BOOTSTRAP_KEYS)}")
    for key, attr, low in (("iterations", "bootstrap_iterations", 100),
                           ("seed", "bootstrap_seed", 0),
                           ("exact_limit", "bootstrap_exact_limit", 0)):
        if key in bootstrap:
            value = bootstrap[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < low:
                raise StudyError(f"bootstrap {key} must be a whole number of at least {low}")
            setattr(config, attr, value)

    for key in ("weighted_kappa", "synthetic"):
        if key in data:
            if not isinstance(data[key], bool):
                raise StudyError(f"'{key}' must be true or false")
            setattr(config, key, data[key])

    if "h2_unit" in data:
        unit = data["h2_unit"]
        text = unit.strip().lower() if isinstance(unit, str) else unit
        if text not in H2_UNITS:
            raise StudyError(f"h2_unit must be one of {', '.join(H2_UNITS)}, not {unit!r}")
        config.h2_unit = text

    rule = data.get("level_rule")
    if rule is not None:
        if not isinstance(rule, Mapping):
            raise StudyError("'level_rule' must be a mapping with the keys manual, tool_side and overall")
        unknown_rule_keys = set(map(str, rule)) - set(LEVEL_RULE_VALUES)
        if unknown_rule_keys:
            raise StudyError(f"unknown level_rule key(s): {', '.join(sorted(unknown_rule_keys))}; "
                             f"use {', '.join(LEVEL_RULE_VALUES)}")
        config.manual_level_rule = level_rule_value("manual", rule.get("manual"))
        config.tool_side_rule = level_rule_value("tool_side", rule.get("tool_side")) or LEVEL_RULE_TOOL_CUTOFFS
        config.overall_rule = level_rule_value("overall", rule.get("overall"))
    _check_level_rule(config)
    return config


def _check_level_rule(config: StudyConfig) -> None:
    """Combinations of level_rule and manual_max_level that cannot both hold."""
    if config.tool_side_rule == LEVEL_RULE_APPROVED and config.overall_rule is None:
        raise StudyError(
            "level_rule.tool_side approved needs level_rule.overall: the approved rule defines no overall level "
            f"by itself; choose one of {', '.join(LEVEL_RULE_VALUES['overall'])}")
    rule = config.manual_level_rule
    if rule is None:
        return
    # The cap a declared manual rule implies: 4 under the approved rule; the
    # methodology's own level count (CMMI 5, CISA ZTMM 4) under tool-cutoffs.
    named = list(config.methodologies) + [m for m in config.manual_max_level if m not in config.methodologies]
    for methodology in named:
        native = methodology_level_count(methodology)
        cap = min(APPROVED_MAX_LEVEL, native) if rule == LEVEL_RULE_APPROVED else native
        actual = config.manual_max(methodology)
        if actual != cap:
            how = "" if methodology in config.manual_max_level else ", the default when it is not set"
            raise StudyError(
                f"level_rule.manual {rule} assigns manual {methodology} levels 1-{cap}, so manual_max_level must "
                f"set {methodology}: {cap} (it is {actual}{how})")


def _study_config_text(path: Path, data: bytes) -> str:
    """The text of a study configuration as an editor or PowerShell may save
    it: UTF-8 with or without a byte-order mark, UTF-16 with one, or else
    Windows-1252 (ANSI). Anything that cannot be decoded, and NUL characters
    (UTF-16 without a byte-order mark), raise StudyError asking for UTF-8.
    The ledger hashes the bytes, so decoding never affects a hash."""
    ask = f"cannot read study configuration {path}: save {path.name} as UTF-8"
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16")
        elif data.startswith(b"\xef\xbb\xbf"):
            text = data.decode("utf-8-sig")
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("cp1252")
    except UnicodeDecodeError as exc:
        raise StudyError(f"{ask} ({exc})") from None
    if "\x00" in text:
        raise StudyError(f"{ask} (it holds NUL characters, as a UTF-16 file without a byte-order mark does)")
    return text


def load_study_config(path: Union[str, Path]) -> StudyConfig:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StudyError(f"cannot read study configuration {path}: {exc}") from exc
    try:
        data = yaml.safe_load(_study_config_text(path, raw))
    except yaml.YAMLError as exc:
        raise StudyError(f"invalid YAML in {path}: {exc}") from exc
    return study_config_from_dict(data or {})


def config_template(hosts: Sequence[str], synthetic: bool = False) -> str:
    """A commented study.yaml to start from. Decisions still open in the
    protocol are marked; the defaults run, but are not those decisions."""
    host_list = ", ".join(validate_host_code(h) for h in hosts)
    return (
        "# Study configuration read by `python -m miccmac_study agreement`.\n"
        f"hosts: [{host_list}]\n"
        "# Approved success threshold (a configurable default).\n"
        "threshold: 0.80\n"
        "# Protocol decision 2: CMMI only, or CMMI primary with CISA ZTMM secondary.\n"
        "primary_methodology: cmmi\n"
        "secondary_methodologies: []\n"
        "# Protocol decision 4: the highest level your manual rule can assign.\n"
        "# 4 = approved rule (Level 5 never assigned from one run); 5 = tool cutoffs.\n"
        "manual_max_level: {cmmi: 5, cisa-ztmm: 4}\n"
        "# Protocol decision 4: how levels are derived on each side. The defaults below\n"
        "# reproduce the analysis as it was before this block existed.\n"
        "level_rule:\n"
        "  # DECISION (needs the advisor): the rule the assessor uses to turn verdicts into levels.\n"
        "  #   approved     = pass ratio (PASS + 0.5 x PARTIAL) / scorable checks; 0 -> 1,\n"
        "  #                  under 0.5 -> 2, 0.5 to under 1 -> 3, 1 -> 4 (needs manual_max_level cmmi: 4)\n"
        "  #   tool-cutoffs = the tool's own level cutoffs (needs manual_max_level cmmi: 5)\n"
        "  #   null         = not declared yet\n"
        "  manual: null\n"
        "  # DECISION (needs the advisor): how the tool's levels are computed for the comparison.\n"
        "  #   tool-cutoffs = the levels the tool reports (its own scoring and cutoffs); the default\n"
        "  #   approved     = the tool's check statuses scored with the approved rule (levels 1-4);\n"
        "  #                  needs an overall rule below\n"
        "  tool_side: tool-cutoffs\n"
        "  # DECISION (needs the advisor): the overall-level rule wherever an overall level is\n"
        "  # derived under the approved rule (also for overall_excl_input_driven):\n"
        "  #   mean-of-property-ratios = approved buckets on the mean of the property pass ratios\n"
        "  #   pooled-checks           = approved buckets on the pass ratio over all scorable checks\n"
        "  #   step4-buckets           = approved buckets on the mean of (level - 1) / 3 (Step 3 and 4)\n"
        "  #   step4-rounded           = 1 + the mean of (level - 1), rounded half up\n"
        "  #   null                    = not declared yet\n"
        "  overall: null\n"
        "# Protocol section 4: checks that read the attestation / inventory files.\n"
        "input_driven_checks: [" + ", ".join(DEFAULT_INPUT_DRIVEN_CHECKS) + "]\n"
        "input_driven_properties: [" + ", ".join(DEFAULT_INPUT_DRIVEN_PROPERTIES) + "]\n"
        "# Bootstrap over hosts for pooled agreement (exact enumeration when small).\n"
        "bootstrap: {iterations: 10000, seed: 20261122, exact_limit: 1000000}\n"
        "# Linear-weighted kappa is optional in the protocol.\n"
        "weighted_kappa: false\n"
        "# DECISION (protocol section 7): the register entries the H2 threshold is tested on.\n"
        "#   all-entries = every entry, findings and missing-data entries (the default)\n"
        "#   findings    = findings (FAIL, PARTIAL) only; agreement reports both either way\n"
        "h2_unit: all-entries\n"
        f"synthetic: {'true' if synthetic else 'false'}\n"
    )


# ------------------------------------------------------------------ tool output loader
@dataclass
class ToolOutput:
    """One `miccmac assess --format json` file, with or without --risk-register."""
    path: Path
    assessment: dict
    risk_register: Optional[List[dict]]

    @property
    def provenance(self) -> Optional[dict]:
        return self.assessment.get("provenance")

    @property
    def methodology_name(self) -> Optional[str]:
        return (self.assessment.get("methodology") or {}).get("name")

    def checks(self) -> List[dict]:
        """Every check, in report order, with its property key added."""
        out = []
        for prop in self.assessment.get("properties", []):
            for check in prop.get("checks", []):
                out.append(dict(check, property_key=prop.get("key")))
        return out

    def check_ids(self) -> List[str]:
        return [c["check_id"] for c in self.checks()]

    def statuses(self) -> Dict[str, str]:
        return {c["check_id"]: c["status"] for c in self.checks()}

    def property_scores(self) -> Dict[str, Optional[float]]:
        return {p.get("key"): p.get("score") for p in self.assessment.get("properties", [])}

    def levels(self) -> Dict[str, Optional[int]]:
        """Methodology level per property key plus OVERALL; empty without a methodology."""
        methodology = self.assessment.get("methodology") or {}
        levels = {key: (value or {}).get("level") for key, value in (methodology.get("properties") or {}).items()}
        if methodology:
            levels[OVERALL] = (methodology.get("overall") or {}).get("level")
        return levels


def methodology_in_name(path: Union[str, Path]) -> Optional[str]:
    """The methodology a tool output's file name names, as the study names
    them (tool_output_name: <H>-<methodology>.json, any letter case), or None
    for any other name."""
    name = Path(path).name
    for methodology in sorted(METHODOLOGY_REGISTRY, key=len, reverse=True):
        suffix = f"-{methodology}.json"
        if name.lower().endswith(suffix) and _HOST_RE.match(name[:-len(suffix)]):
            return methodology
    return None


def methodology_name_problem(path: Union[str, Path]) -> str:
    """Why the tool output at `path` does not hold the methodology its name
    names ('' when it does, when the name names none, or when the file is not
    a readable miccmac assessment). The methodology block and the provenance
    must both name it. CMMI is the tool's default lens, so a command that lost
    its --methodology gives CMMI levels under another methodology's name."""
    named = methodology_in_name(path)
    if named is None:
        return ""
    try:
        output = load_tool_output(path)
    except StudyError:
        return ""
    found = output.methodology_name
    provenance = output.provenance if isinstance(output.provenance, dict) else {}
    recorded = provenance.get("methodology", found) if provenance else found
    if found != named:
        held = f"{found} levels" if isinstance(found, str) and found in METHODOLOGY_REGISTRY else "no methodology levels"
        return (f"holds {held}, but its name says {named} (was --methodology {named} left out of the command, or "
                f"another one typed?)")
    if recorded != named:
        return f"holds {named} levels, but its provenance names {recorded!r}, not {named}"
    return ""


def load_tool_output(path: Union[str, Path]) -> ToolOutput:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StudyError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StudyError(f"{path} is not valid JSON: {exc}") from exc
    if isinstance(data, dict) and "assessment" in data:
        assessment, register = data["assessment"], data.get("risk_register")
    else:
        assessment, register = data, None
    if not isinstance(assessment, dict) or not isinstance(assessment.get("properties"), list):
        raise StudyError(f"{path} is not a miccmac assessment JSON file")
    if register is not None and not isinstance(register, list):
        raise StudyError(f"{path}: risk_register is not a list")
    return ToolOutput(path=path, assessment=assessment, risk_register=register)
