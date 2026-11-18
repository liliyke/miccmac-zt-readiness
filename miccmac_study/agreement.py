"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Agreement analysis (protocol section 8): ``python -m miccmac_study agreement``.

    python -m miccmac_study agreement --study-dir DIR [--config FILE]
        [--threshold X] [--tool-side-rule RULE] [--overall-rule RULE]
        [--out DIR] [--overwrite]

--threshold, --tool-side-rule and --overall-rule override study.yaml for a
sensitivity run; every output records the override. A configuration that
differs from the pre-registered one (DIR/study.yaml as recorded in the
ledger when the seal first opened) is a sensitivity run too: CRITICAL, and
labelled in every summary with each difference.

Level rules (study.yaml level_rule, protocol decision 4). The tool's levels
used in the comparison come from its check statuses, with the checks the
assessor marked UNASSESSED left out, under the tool-side rule:
tool-cutoffs (miccmac's own scoring and cutoffs, the default) or approved
(the approved pass-ratio buckets, levels 1-4, with the declared overall
rule). derive_levels_from_verdicts() applies the same definitions to a
worksheet's own verdicts: the rule_only flag uses it, and it is exported
for a pre-hash worksheet lint (it reads no tool output).

Run after unsealing. For every host of the study configuration that is not
withdrawn in the ledger it reads

    worksheets/<H>-worksheet.csv         the blind manual worksheet (hashed)
    outputs/<H>-<methodology>.json       one tool output per configured methodology
    outputs/<H>-facts.json               the saved facts (only its connector, for the synthetic markers)
    register/<H>-register-review.csv     register review (optional; H2)
    register/<H>-missed-gaps.csv         missed gaps (optional)
    ledger.csv                           the SHA-256 ledger

checks the integrity of those files, compares the tool's levels and check
statuses with the manual worksheet, and writes descriptive tables to
DIR/analysis (or --out). Existing output files are never replaced unless
--overwrite is given, and even then never a disagreements.csv in which the
researcher has filled in root_cause, action or assessor_error_note.

Blinding: tool outputs stay sealed until every worksheet is hashed. Before
anything else is read, the command asks ledger.seal_status whether the seal
may open, the same gate register-sheet uses: every host of the study (in
the configuration, in DIR/study.yaml, in a ledger row, or named by a
worksheet or tool-output file) needs its worksheets/<H>-worksheet.csv hashed
and unchanged, unless 'ledger withdraw' took it out. There is no exemption
for synthetic data (the synthetic kit hashes every worksheet first), and a
--config listing fewer hosts never opens the seal. Once every check that can
still refuse has passed (the seal, the refusal to replace outputs), and
before the first tool output is read, the run appends its seal-opening row
to the ledger (ledger.record_seal_opened: "seal opened by agreement: ...");
a run that cannot write it refuses. Until then only the worksheets and each
facts file's connector name are read.

Integrity checks then compare the tool's inputs (by role: the versions the
assessor had), facts file and enabled checks with the files hashed in the
ledger; compare the configuration used with the pre-registered one; report
worksheets hashed, and hosts withdrawn, after the seal first opened,
worksheets recorded with --force despite lint findings, typed levels that do
not follow the declared manual level rule, every ledger row that no longer
verifies, and register sheets forced before the seal opened.

lint_worksheet() is the pre-hash check that `ledger record --kind worksheet`
runs on a filled worksheet: it reads only that worksheet and the study
configuration, never a tool output.

Nothing here fills a judgment field: root causes, actions, assessor-error
notes and every interpretation are left blank for the researcher.

Exit codes: 0 = outputs written, no CRITICAL integrity problem; 3 = outputs
written, with CRITICAL problem(s) flagged in every summary; 2 = usage or
input error (nothing written).
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import hashlib
import json
import math
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

import miccmac
import miccmac_study
from miccmac.engine import overall_score, score_property
from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY
from miccmac.methodology import get_methodology
from miccmac.model import PROPERTY_KEYS, CheckResult, PropertyResult, Status
from miccmac_study import ledger as study_ledger
from miccmac_study import stats
from miccmac_study.formats import (
    ANALYSIS_DIR,
    APPROVED_MAX_LEVEL,
    CONFIG_FILE,
    LEDGER_FILE,
    LEVEL_RULE_APPROVED,
    LEVEL_RULE_TOOL_CUTOFFS,
    LEVEL_RULE_VALUES,
    LEVEL_SCOPES,
    OUTPUTS_DIR,
    OVERALL,
    OVERALL_EXCL,
    OVERALL_MEAN_OF_PROPERTY_RATIOS,
    OVERALL_POOLED_CHECKS,
    OVERALL_STEP4_BUCKETS,
    OVERALL_STEP4_ROUNDED,
    PROVENANCE_FORMAT,
    REGISTER_DIR,
    ROW_CHECK,
    ROW_LEVEL,
    ROW_META,
    SYNTHETIC_BANNER,
    TOOL_STATUSES,
    UNASSESSED,
    WORKSHEET_FORMAT,
    WORKSHEETS_DIR,
    LedgerRow,
    StudyConfig,
    StudyError,
    ToolOutput,
    check_ids_fingerprint,
    facts_name,
    level_rule_value,
    load_study_config,
    load_tool_output,
    methodology_level_count,
    missed_gaps_name,
    normalize_verdict,
    normalize_yes_no,
    parse_date,
    parse_level,
    parse_utc_timestamp,
    read_csv,
    read_ledger,
    register_review_name,
    resolve_ledger_path,
    sha256_file,
    tool_output_name,
    utc_now_iso,
    worksheet_name,
    write_csv,
    write_json,
)
from miccmac_study.worksheet import read_list_checks

# ------------------------------------------------------------------ constants
OK = "OK"
WARNING = "WARNING"
CRITICAL = "CRITICAL"
_SEVERITY = {OK: 0, WARNING: 1, CRITICAL: 2}

INTEGRITY_BANNER = "INTEGRITY PROBLEMS: see section 2"
SUMMARY_FORMAT = "miccmac-agreement/1"
SYNTHETIC_PREFIX = "SYNTHETIC-"

# The researcher's root-cause categories for disagreements.csv (protocol).
ROOT_CAUSES = ("check-logic gap", "missing or ambiguous fact", "genuine judgment difference")

MEASURES = ("within_one", "exact")
SUBSETS = ("all_properties", "excl_input_driven")
CHECK_GROUPS = ("device", "input", "all")
H1_SCOPES = tuple(PROPERTY_KEYS) + (OVERALL,)
TOOL_UNASSESSED = "unassessed"   # the tool computed no level (nothing scorable)
MANUAL_MISSING = "missing"       # no usable manual verdict on a compared check

# The connector a synthetic facts envelope names (miccmac_study.synthetic).
SYNTHETIC_CONNECTOR = "synthetic"
# Ledger kind of the enabled-check list recorded at setup (formats.LEDGER_KINDS).
LIST_CHECKS_KIND = "list-checks"
# Note of a worksheet row recorded with `ledger record --kind worksheet --force`
# although the pre-hash lint (lint_worksheet) found problems; the findings follow it.
LINT_NOTE_PREFIX = study_ledger.LINT_NOTE_PREFIX
# The worksheet cells the assessor fills in for each check besides the verdict
# (protocol section 6), checked by the lint unless the check is UNASSESSED,
# with what each blank cell asks for.
PROCEDURE_COLUMNS = (
    ("pass_criterion", "write what had to be true for a pass"),
    ("evidence_procedure", "write the steps you followed"),
    ("procedure_source", "write NONE when no external procedure exists"),
)
# Meta values the assessor fills in, checked by the lint, with what a blank one asks for.
ASSESSOR_META = (
    ("assessor", "write who filled in this sheet"),
    ("level_rule", "write the manual level rule you applied (protocol section 6)"),
)
# The lint findings for an undeclared manual level rule (decision 4).
NO_MANUAL_RULE = ("levels not checked: the study configuration declares no level_rule.manual (decision 4); declare "
                  "it before hashing a worksheet")
NO_OVERALL_RULE = ("overall levels not checked: level_rule.overall is not declared, and the approved rule defines "
                   "no overall level (decision 4)")
# Note on a level comparison whose typed manual level differs from the level the
# worksheet's own verdicts give under the declared manual rule (rule_only is left blank).
OFF_RULE_NOTE = "typed level does not follow the declared manual rule"

# Integrity checks in report order: key -> title.
INTEGRITY_CHECKS = (
    ("hosts", "Hosts analysed (study configuration, withdrawals and when they were made, hosts outside the "
              "configuration)"),
    ("files", "Worksheet and tool outputs present and readable"),
    ("worksheet", "Worksheet format, host code and session date; no worksheet recorded with --force despite lint "
                  "findings"),
    ("verdicts", "Manual verdicts complete"),
    ("levels", "Manual levels complete and following the declared manual level rule"),
    ("synthetic", "Synthetic markers agree (study configuration, worksheets, facts files)"),
    ("provenance", "Provenance present; methodology matches the file name"),
    ("check_set", "Same check-id set on worksheet and tool output, on every host"),
    ("list_checks", "Tool's enabled checks equal the list-checks file hashed at setup"),
    ("as_of", "Tool --as-of equals the worksheet session date"),
    ("consistency", "Methodology outputs of a host agree (statuses, facts file, inputs)"),
    ("inputs", "Tool inputs are the files the assessor had, each in its own role; facts file is the one hashed "
               "for the host"),
    ("build", "One tool commit, clean working tree"),
    ("analysis_code", "Analysis code committed (no uncommitted or untracked file in miccmac_study)"),
    ("tool_status", "No ERROR or NOT_IMPLEMENTED tool statuses"),
    ("reproduce", "Reported tool levels reproduce from the check statuses"),
    ("config", "Study configuration matches its latest ledger row and the pre-registered study.yaml (as in force "
               "at the first tool run and when the seal first opened)"),
    ("seal", "Register sheets issued only after every worksheet was hashed (no forced run)"),
    ("ledger_row", "Each worksheet has a ledger row"),
    ("ledger_hash", "Hashed worksheets, tool outputs, facts files and register sheets unchanged"),
    ("ledger_order", "Worksheet hashed before the tool run and before the seal first opened; ledger rows in time "
                     "order"),
    ("ledger_rows", "Other hashed files unchanged (inputs, list-checks, protocol and other rows)"),
    ("register", "Register review sheets match the register"),
)

HOST_LEVELS_COLUMNS = (
    "host", "methodology", "scope", "tool_level_reported", "tool_level_used", "manual_level",
    "diff", "exact", "within_one", "l5_rule_only", "rule_only", "note",
)
AGREEMENT_H1_COLUMNS = (
    "methodology", "scope", "measure", "k", "n", "rate", "wilson_low", "wilson_high",
    "threshold", "meets_threshold",
)
POOLED_COLUMNS = (
    "methodology", "measure", "subset", "k", "n", "rate", "wilson_low", "wilson_high",
    "boot_low", "boot_high", "boot_method", "boot_resamples", "boot_hosts",
)
CHECK_VERDICTS_COLUMNS = (
    "host", "check_id", "property", "group", "tool_status", "manual_verdict", "compared", "agree", "note",
)
CHECK_AGREEMENT_COLUMNS = (
    "group", "k", "n", "rate", "wilson_low", "wilson_high", "boot_low", "boot_high", "boot_method",
    "boot_resamples", "boot_hosts", "kappa", "kappa_note",
)
REGISTER_H2_COLUMNS = (
    "host", "entries", "judged", "not_judged", "accurate_y", "actionable_y", "k", "n", "rate", "wilson_low",
    "wilson_high", "meets_threshold", "boot_low", "boot_high", "boot_method", "boot_resamples", "boot_hosts",
    "prioritized_y", "prioritized_n", "prioritized_unsure", "prioritization_k", "prioritization_n",
    "prioritization_rate", "prioritization_wilson_low", "prioritization_wilson_high", "missed_gaps",
)
DISAGREEMENT_COLUMNS = (
    "kind", "host", "methodology", "item", "tool_value", "manual_value", "diff", "within_one",
    "l5_rule_only", "rule_only", "root_cause", "action", "assessor_error_note",
)
CONFUSION_VERDICT_COLUMNS = ("tool_status",) + tuple(
    f"manual_{v}" for v in ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", MANUAL_MISSING)
)

LevelValue = Union[int, str, None]


# ------------------------------------------------------------------ data classes
@dataclass
class Finding:
    """One integrity observation: which check, how serious, which host
    ('' for the whole study) and what was found. No interpretation."""
    check: str
    level: str
    host: str
    detail: str


@dataclass
class Worksheet:
    """A parsed manual worksheet. Blank cells are None. Problems found while
    parsing are collected in `findings` instead of raised, because a hashed
    worksheet can no longer be corrected; the analysis reports them."""
    path: Path
    host: str
    meta: Dict[str, str] = field(default_factory=dict)
    session_date: Optional[dt.date] = None
    synthetic: Optional[bool] = False   # None when the flag could not be read
    check_ids: List[str] = field(default_factory=list)
    check_properties: Dict[str, str] = field(default_factory=dict)
    verdicts: Dict[str, Optional[str]] = field(default_factory=dict)
    raw_verdicts: Dict[str, str] = field(default_factory=dict)
    reasons: Dict[str, str] = field(default_factory=dict)
    levels: Dict[str, Dict[str, LevelValue]] = field(default_factory=dict)
    raw_levels: Dict[str, Dict[str, str]] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    # check id -> the procedure cells of its row (PROCEDURE_COLUMNS), stripped; "" when blank or absent.
    procedure: Dict[str, Dict[str, str]] = field(default_factory=dict)

    @property
    def unassessed(self) -> List[str]:
        """Check ids marked UNASSESSED, in worksheet order."""
        return [c for c in self.check_ids if self.verdicts.get(c) == UNASSESSED]


@dataclass
class LevelComparison:
    """Tool level against manual level for one host x methodology x scope."""
    host: str
    methodology: str
    scope: str
    tool_reported: Optional[int]
    tool_reported_known: bool      # False for scopes the tool does not report
    tool_used: Optional[int]
    manual: LevelValue
    counted: bool                  # included in n
    diff: Optional[int] = None
    exact: Optional[bool] = None
    within_one: Optional[bool] = None
    l5_rule_only: Optional[bool] = None
    # On an exact mismatch: True when the worksheet's own verdicts, leveled
    # with the tool-side rule, give tool_used (the difference comes from how
    # the levels were derived); None when it cannot be decided (a verdict of
    # the scope or the manual level is blank or unreadable, or the typed
    # manual level does not follow the declared manual rule) or on no mismatch.
    rule_only: Optional[bool] = None
    note: str = ""


@dataclass
class CheckComparison:
    """Tool status against manual verdict for one host x check."""
    host: str
    check_id: str
    property_key: str
    group: str
    tool_status: Optional[str]
    manual_verdict: Optional[str]
    compared: bool
    agree: Optional[bool]
    note: str = ""


@dataclass
class RegisterHost:
    """Register-review counts for one host (H2)."""
    host: str
    entries: int = 0
    judged: int = 0
    not_judged: int = 0
    accurate_y: int = 0
    actionable_y: int = 0
    k: int = 0
    prioritized: Counter = field(default_factory=Counter)
    missed_gaps: int = 0


@dataclass
class Study:
    """Everything read from the study folder, plus the findings so far."""
    study_dir: Path
    config_path: Path
    config: StudyConfig
    threshold_source: str
    config_threshold: Fraction
    findings: List[Finding] = field(default_factory=list)
    notes: List[Tuple[str, str]] = field(default_factory=list)   # (host, text)
    checked: Dict[str, str] = field(default_factory=dict)
    worksheets: Dict[str, Worksheet] = field(default_factory=dict)
    outputs: Dict[str, Dict[str, ToolOutput]] = field(default_factory=dict)
    ledger: List[LedgerRow] = field(default_factory=list)
    ledger_present: bool = False
    # Every ledger row with its `ledger verify` state and order flag (ledger.row_states).
    row_states: List[study_ledger.RowState] = field(default_factory=list)
    synthetic: bool = False
    # The seal (ledger.seal_status) once it opened: the hosts the configuration
    # lists, those withdrawn in the ledger (host -> (recorded_at_utc, reason)),
    # and the hosts of the study folder that the configuration does not list.
    # config.hosts holds the hosts analysed: the configuration's, minus withdrawn ones.
    config_hosts: List[str] = field(default_factory=list)
    withdrawn: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    extra_hosts: List[str] = field(default_factory=list)
    # The analysis code's commit, files and working-tree state (_analysis_code), read once per run.
    analysis_code: Dict[str, object] = field(default_factory=dict)
    # Level rule as study.yaml has it, where the values used come from, and
    # every sensitivity override given on the command line.
    config_tool_side_rule: str = LEVEL_RULE_TOOL_CUTOFFS
    config_overall_rule: Optional[str] = None
    tool_side_source: str = "the study configuration"
    overall_source: str = "the study configuration"
    overrides: List[str] = field(default_factory=list)
    # The configuration file as loaded: before command-line overrides and before
    # withdrawn hosts are left out (compared with the pre-registered study.yaml).
    loaded_config: Optional[StudyConfig] = None
    # How the configuration used differs from the pre-registered one (one item per
    # difference; empty when it does not), and what that reference is
    # (_check_preregistered).
    config_differences: List[str] = field(default_factory=list)
    config_reference: str = ""
    # Hosts withdrawn after the seal first opened (post-hoc exclusions), one text each.
    post_hoc_exclusions: List[str] = field(default_factory=list)

    @property
    def sensitivity_run(self) -> bool:
        """A command-line override, a configuration that differs from the
        pre-registered one, or a host withdrawn after the seal opened."""
        return bool(self.overrides or self.config_differences or self.post_hoc_exclusions)

    def add(self, check: str, level: str, host: str, detail: str) -> None:
        self.findings.append(Finding(check, level, host, detail))

    def note(self, host: str, text: str) -> None:
        self.notes.append((host, text))

    def sorted_notes(self) -> List[str]:
        """Notes as 'H: text', in host order, then in the order made."""
        order = {host: i for i, host in enumerate(self.config.hosts)}
        ranked = sorted(self.notes, key=lambda item: order.get(item[0], len(order)))
        return [f"{host}: {text}" if host else text for host, text in ranked]

    def facts_path(self, host: str) -> Path:
        return self.study_dir / OUTPUTS_DIR / facts_name(host)

    def worksheet_path(self, host: str) -> Path:
        return self.study_dir / WORKSHEETS_DIR / worksheet_name(host)

    def output_path(self, host: str, methodology: str) -> Path:
        return self.study_dir / OUTPUTS_DIR / tool_output_name(host, methodology)

    def review_path(self, host: str) -> Path:
        return self.study_dir / REGISTER_DIR / register_review_name(host)

    def gaps_path(self, host: str) -> Path:
        return self.study_dir / REGISTER_DIR / missed_gaps_name(host)

    @property
    def ledger_path(self) -> Path:
        return self.study_dir / LEDGER_FILE

    def rel(self, path: Path) -> str:
        """A path as shown in outputs: relative to the study folder, or just
        the file name for a file outside it (no private absolute paths in
        files that may be shared)."""
        try:
            return Path(path).resolve().relative_to(self.study_dir).as_posix()
        except ValueError:
            return Path(path).name

    def clean(self, message: str) -> str:
        """An error message with the study folder's absolute prefix removed."""
        for prefix in (str(self.study_dir) + os.sep, str(self.study_dir) + "/"):
            message = message.replace(prefix, "")
        return message

    def reference(self, host: str) -> Optional[ToolOutput]:
        """The output used for check statuses and the register: the primary
        methodology's, or else the first secondary one that was read."""
        outputs = self.outputs.get(host, {})
        for methodology in self.config.methodologies:
            if methodology in outputs:
                return outputs[methodology]
        return None


@dataclass
class Analysis:
    """Comparisons and aggregates computed from a Study."""
    levels: List[LevelComparison]
    checks: List[CheckComparison]
    register: Optional[List[RegisterHost]]
    h1: List[Dict[str, object]]
    pooled: List[Dict[str, object]]
    check_agreement: List[Dict[str, object]]
    level_confusion: Dict[str, List[Dict[str, object]]]
    verdict_confusion: List[Dict[str, object]]
    chance: List[Dict[str, object]]
    l5: List[Dict[str, object]]
    kappa: Optional[List[Dict[str, object]]]


# ------------------------------------------------------------------ command line
def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--study-dir", required=True,
                        help="Study folder holding study.yaml, ledger.csv, worksheets/, outputs/, register/.")
    parser.add_argument("--config", default=None,
                        help="Study configuration (default: STUDY_DIR/study.yaml).")
    parser.add_argument("--threshold", default=None,
                        help="Override the success threshold for a sensitivity check, e.g. 0.75 or 3/4. "
                             "The override is recorded in every output.")
    parser.add_argument("--tool-side-rule", default=None, metavar="RULE",
                        help="Override level_rule.tool_side for a sensitivity run: "
                             f"{' or '.join(LEVEL_RULE_VALUES['tool_side'])}. The override is recorded in "
                             "every output.")
    parser.add_argument("--overall-rule", default=None, metavar="RULE",
                        help="Override level_rule.overall for a sensitivity run (used only when the tool side "
                             f"uses the approved rule): {', '.join(LEVEL_RULE_VALUES['overall'])}. The override "
                             "is recorded in every output.")
    parser.add_argument("--out", default=None,
                        help="Output folder (default: STUDY_DIR/analysis).")
    parser.add_argument("--overwrite", action="store_true",
                        help="Replace existing output files (they are never replaced otherwise), except a "
                             "disagreements.csv in which root_cause, action or assessor_error_note is filled in.")


def run(args: argparse.Namespace) -> int:
    study = _open_study(args)
    status = _require_unsealed(study)      # the seal: nothing else of the study is read before it opens
    _read_ledger(study)
    _read_worksheets(study)
    _decide_synthetic(study)

    out_dir = Path(args.out) if args.out else study.study_dir / ANALYSIS_DIR
    planned = _planned_files(study)
    _refuse_existing(out_dir, planned, args.overwrite)
    _record_seal_opening(study, status)    # in the ledger before the first tool output is read

    _read_outputs(study)
    _run_integrity_checks(study)
    analysis = _analyse(study)
    generated_at = utc_now_iso()
    try:
        _write_outputs(study, analysis, out_dir, planned, generated_at, args.overwrite)
    except OSError as exc:
        raise StudyError(f"writing the outputs failed ({exc}); {out_dir} may now hold a mix of old and new "
                         "files: fix the problem and run again with --overwrite") from None

    critical = _worst(study.findings) == CRITICAL
    print(f"agreement: wrote {len(planned)} files to {out_dir}")
    if critical:
        print("agreement: CRITICAL integrity problems; see section 2 of the summary")
    return 3 if critical else 0


# ------------------------------------------------------------------ opening the study
def _parse_threshold(text: str) -> Fraction:
    try:
        value = Fraction(str(text).strip())
    except (ValueError, ZeroDivisionError):
        raise StudyError(f"--threshold {text!r} is not a number (for example 0.75 or 3/4)") from None
    if not 0 < value <= 1:
        raise StudyError(f"--threshold {text!r} must be greater than 0 and at most 1")
    return value


def _open_study(args: argparse.Namespace) -> Study:
    study_dir = Path(args.study_dir)
    if not study_dir.is_dir():
        raise StudyError(f"study folder not found: {study_dir}")
    study_dir = study_dir.resolve()
    config_path = Path(args.config) if args.config else study_dir / CONFIG_FILE
    if not config_path.is_file():
        raise StudyError(f"study configuration not found: {config_path}")
    config = load_study_config(config_path)
    loaded = config
    config_threshold = config.threshold
    in_config = f"the study configuration ({config_path.name})"
    source = in_config
    overrides: List[str] = []
    if args.threshold is not None:
        config = dataclasses.replace(config, threshold=_parse_threshold(args.threshold))
        source = "--threshold (sensitivity check)"
        overrides.append(f"--threshold {str(args.threshold).strip()}")
    study = Study(study_dir=study_dir, config_path=config_path.resolve(), config=config,
                  threshold_source=source, config_threshold=config_threshold,
                  config_tool_side_rule=config.tool_side_rule, config_overall_rule=config.overall_rule,
                  tool_side_source=in_config, overall_source=in_config, loaded_config=loaded)
    _apply_rule_overrides(study, getattr(args, "tool_side_rule", None), getattr(args, "overall_rule", None))
    study.overrides = overrides + study.overrides
    return study


def _apply_rule_overrides(study: Study, tool_side: Optional[str], overall: Optional[str]) -> None:
    """--tool-side-rule and --overall-rule: sensitivity runs of the level rule,
    checked before any study file is read."""
    config = study.config
    if tool_side is not None:
        value = level_rule_value("tool_side", tool_side, label="--tool-side-rule")
        if value is None:
            raise StudyError(f"--tool-side-rule needs a value: {' or '.join(LEVEL_RULE_VALUES['tool_side'])}")
        config = dataclasses.replace(config, tool_side_rule=value)
        study.tool_side_source = "--tool-side-rule (sensitivity check)"
        study.overrides.append(f"--tool-side-rule {value}")
    if overall is not None:
        value = level_rule_value("overall", overall, label="--overall-rule")
        if value is None:
            raise StudyError(f"--overall-rule needs a value: {', '.join(LEVEL_RULE_VALUES['overall'])}")
        config = dataclasses.replace(config, overall_rule=value)
        study.overall_source = "--overall-rule (sensitivity check)"
        study.overrides.append(f"--overall-rule {value}")
    if config.tool_side_rule == LEVEL_RULE_APPROVED and config.overall_rule is None:
        raise StudyError("the approved tool-side rule needs an overall rule, and the study configuration declares "
                         "none (level_rule.overall is null): add --overall-rule "
                         f"({', '.join(LEVEL_RULE_VALUES['overall'])})")
    if overall is not None and config.tool_side_rule != LEVEL_RULE_APPROVED:
        raise StudyError("--overall-rule changes nothing while the tool side uses tool-cutoffs (miccmac derives "
                         "its own overall level); add --tool-side-rule approved, or leave --overall-rule out")
    study.config = config


def _declared_manual_rule(study: Study) -> Optional[StudyConfig]:
    """The configuration with the manual level rule as the study configuration
    declares it (level_rule.manual with its own level_rule.overall, never an
    --overall-rule override, which changes only the tool side), or None when
    level_rule.manual is not declared."""
    if study.config.manual_level_rule is None:
        return None
    return dataclasses.replace(study.config, overall_rule=study.config_overall_rule)


def _read_worksheets(study: Study) -> None:
    """Parse every analysed host's worksheet. When level_rule.manual is
    declared, each typed level that differs from the level the sheet's own
    verdicts give under that rule is a 'levels' WARNING (the lint's level
    findings, for a sheet hashed with --force or before the rule was set)."""
    declared = _declared_manual_rule(study)
    for host in study.config.hosts:
        path = study.worksheet_path(host)
        if not path.exists():
            study.add("files", CRITICAL, host, f"worksheet missing: {study.rel(path)}")
            continue
        try:
            worksheet = parse_worksheet(path, study.config, expected_host=host)
        except StudyError as exc:
            study.add("files", CRITICAL, host, f"cannot read the worksheet: {study.clean(str(exc))}")
            continue
        study.worksheets[host] = worksheet
        study.findings.extend(worksheet.findings)
        if declared is not None:
            for _, message in _lint_levels(worksheet, declared):
                study.add("levels", WARNING, host, message)
        for note in worksheet.notes:
            study.note(host, note)


def _facts_connector(path: Path) -> Optional[str]:
    """The connector a saved facts envelope names, or None when the file is
    missing, unreadable or names none. Nothing else of the file is used."""
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    connector = envelope.get("connector") if isinstance(envelope, dict) else None
    return connector.strip() if isinstance(connector, str) and connector.strip() else None


def _decide_synthetic(study: Study) -> None:
    """The synthetic markers are study.yaml's synthetic setting, each
    worksheet's meta synthetic flag and each facts envelope's connector
    ("synthetic" for the synthetic kit). Labelling is fail-safe: any marker
    gives SYNTHETIC- file names and the banner. Gating never depends on them
    (see _require_unsealed). Every marker that disagrees with the study
    configuration, in either direction, is CRITICAL: study data must carry no
    synthetic marker at all, and synthetic data must carry it everywhere."""
    declared = bool(study.config.synthetic)
    said = "true" if declared else "false"
    name = study.config_path.name
    sheets = {host: ws.synthetic for host, ws in study.worksheets.items()}
    connectors = {host: _facts_connector(study.facts_path(host)) for host in study.config.hosts}
    study.synthetic = (declared or any(flag is True for flag in sheets.values())
                       or any(connector == SYNTHETIC_CONNECTOR for connector in connectors.values()))
    labelled = "every output is labelled SYNTHETIC, because any synthetic marker labels the whole study"
    for host in study.config.hosts:
        flag = sheets.get(host)
        if flag is not None and flag != declared:
            study.add("synthetic", CRITICAL, host,
                      f"worksheet says synthetic={'yes' if flag else 'no'}, but {name} says synthetic: {said}; "
                      f"{labelled}")
        connector = connectors.get(host)
        if connector is not None and (connector == SYNTHETIC_CONNECTOR) != declared:
            kind = "synthetic" if connector == SYNTHETIC_CONNECTOR else "not synthetic"
            study.add("synthetic", CRITICAL, host,
                      f"{study.rel(study.facts_path(host))} names connector {connector!r} ({kind}), but {name} "
                      f"says synthetic: {said}; {labelled}")
    markers = 1 + sum(1 for flag in sheets.values() if flag is not None) + sum(1 for c in connectors.values() if c)
    study.checked["synthetic"] = (f"{'synthetic' if study.synthetic else 'not synthetic'}: all {markers} markers "
                                  "agree (study configuration, worksheets, facts files)")


def _read_ledger(study: Study) -> None:
    """The ledger rows and their `ledger verify` states. The seal has
    already made sure the ledger exists."""
    if study.ledger_path.exists():
        study.ledger = read_ledger(study.ledger_path)
        study.row_states = study_ledger.row_states(study.ledger_path)
        study.ledger_present = True


def _require_unsealed(study: Study) -> study_ledger.SealStatus:
    """Blinding gate (protocol section 5: tool outputs stay sealed until
    every worksheet is hashed). ledger.seal_status decides, exactly as for
    register-sheet: every host of the study, from every source, must have its
    worksheet hashed and unchanged, unless a withdrawal row took it out. No
    exemption for synthetic data, and a configuration listing fewer hosts
    never opens it. Refuses before anything else is read. Once open, the
    analysis covers the configuration's hosts minus the withdrawn ones.
    Returns the open seal, for the seal-opening row (_record_seal_opening)."""
    status = study_ledger.seal_status(study.study_dir, study.config, ledger_path=study.ledger_path)
    if not status.ok:
        raise StudyError(_sealed_message(status, study.ledger_path))
    study.config_hosts = list(study.config.hosts)
    study.withdrawn = dict(status.withdrawn)
    study.extra_hosts = [host for host in status.hosts if host not in study.config_hosts]
    analysed = [host for host in study.config_hosts if host not in study.withdrawn]
    if not analysed:
        raise StudyError(f"every host in {study.config_path.name} is withdrawn in the ledger; there is nothing "
                         "to analyse")
    study.config = dataclasses.replace(study.config, hosts=analysed)
    return status


def _record_seal_opening(study: Study, status: study_ledger.SealStatus) -> None:
    """Append this run's seal-opening row (ledger.record_seal_opened: one
    STUDY row of kind protocol for the configuration used, archived like any
    row, noted "seal opened by agreement: hosts ...; withdrawn: ..."), so the
    ledger shows every time tool results became available. Runs after every
    check that can still refuse and before the first tool output is read;
    when the row cannot be written, the run stops there (StudyError, exit 2)
    with no tool output read and no analysis file written. The ledger is
    then read again, so the integrity checks see the row."""
    try:
        study_ledger.record_seal_opened(study.ledger_path, "agreement", study.config_path, status)
    except (StudyError, OSError) as exc:
        raise StudyError(f"cannot record the seal opening in the ledger ({study.clean(str(exc))}); no tool output "
                         "was read and no analysis file was written: fix the problem and run again") from None
    _read_ledger(study)


def _sealed_message(status: study_ledger.SealStatus, ledger: Path) -> str:
    """The refusal: each host still sealed with its reason and advice, then
    the commands that fit. Host codes, file names and hashes only."""
    details = "; ".join(f"{host} ({why})" for host, why in status.problems)
    reasons = [why for host, why in status.problems if host != study_ledger.STUDY_HOST_CODE]
    commands = []
    if any(why.startswith(study_ledger.WORKSHEET_NOT_HASHED) for why in reasons):
        commands.append(f"python -m miccmac_study ledger record --ledger {ledger} --host H --kind worksheet "
                        "worksheets/H-worksheet.csv")
    if any(why.startswith((study_ledger.NO_WORKSHEET_YET, study_ledger.WORKSHEET_NOT_HASHED)) for why in reasons):
        commands.append(f"python -m miccmac_study ledger withdraw --ledger {ledger} --host H --reason TEXT")
    listed = f" Commands: {'; '.join(commands)}." if commands else ""
    return ("tool outputs stay sealed until every worksheet is hashed and unchanged; not yet done for: "
            f"{details}.{listed} A host that will not be assessed leaves the study only through 'ledger "
            "withdraw'; a configuration that lists fewer hosts does not open the seal.")


def _planned_files(study: Study) -> List[str]:
    """Names of the files this run writes, prefixed when synthetic."""
    names = ["summary.md", "summary.json", "host_levels.csv", "agreement_h1.csv", "pooled.csv",
             "check_verdicts.csv", "check_agreement.csv"]
    names += [f"confusion_levels_{m}.csv" for m in study.config.methodologies]
    names.append("confusion_verdicts.csv")
    if _register_available(study):
        names.append("register_h2.csv")
    names.append("disagreements.csv")
    prefix = SYNTHETIC_PREFIX if study.synthetic else ""
    return [prefix + name for name in names]


def _refuse_existing(out_dir: Path, planned: Sequence[str], overwrite: bool) -> None:
    """Never replace outputs without --overwrite. With it, never replace a
    disagreement log the researcher has started to fill in (root_cause,
    action, assessor_error_note), and make sure every file can be replaced
    before writing any (a CSV open in Excel is locked on Windows), so a run
    never leaves a mix of old and new files."""
    existing = [name for name in planned if (out_dir / name).exists()]
    if existing and not overwrite:
        raise StudyError(
            f"{out_dir} already holds {', '.join(existing)}; refusing to replace analysis outputs "
            "(use --out for a new folder, or --overwrite)"
        )
    for name in existing:
        if name.endswith("disagreements.csv"):
            entry = _disagreement_entry(out_dir / name)
            if entry:
                raise StudyError(
                    f"{out_dir / name} holds the researcher's entries ({entry}); refusing to replace it, even "
                    "with --overwrite. Use --out for a new folder and copy the entries across by hand"
                )
    for name in existing:
        try:
            with open(out_dir / name, "a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise StudyError(f"cannot replace {out_dir / name} ({exc}); close it, for example in Excel, "
                             "and run again") from None


# The disagreements.csv columns only the researcher fills in.
RESEARCHER_COLUMNS = ("root_cause", "action", "assessor_error_note")


def _disagreement_entry(path: Path) -> Optional[str]:
    """Why an existing disagreements.csv counts as filled in (a non-blank
    root_cause, action or assessor_error_note), or None while those cells
    are all blank. A file that cannot be read counts as filled in: it might
    hold entries."""
    try:
        rows = read_csv(path, ())
    except (StudyError, UnicodeDecodeError, csv.Error) as exc:
        return f"it cannot be read to check for entries: {exc}"
    for number, row in enumerate(rows, start=1):
        for column in RESEARCHER_COLUMNS:
            if (row.get(column) or "").strip():
                return f"data row {number}: {column} is filled in"
    return None


def _read_outputs(study: Study) -> None:
    for host in study.config.hosts:
        study.outputs[host] = {}
        for methodology in study.config.methodologies:
            path = study.output_path(host, methodology)
            if not path.exists():
                study.add("files", CRITICAL, host, f"tool output missing: {study.rel(path)}")
                continue
            try:
                study.outputs[host][methodology] = load_tool_output(path)
            except StudyError as exc:
                study.add("files", CRITICAL, host, f"cannot read the tool output: {study.clean(str(exc))}")
    worksheets = len(study.worksheets)
    outputs = sum(len(v) for v in study.outputs.values())
    study.checked["files"] = f"{worksheets} worksheets and {outputs} tool outputs read"


# ------------------------------------------------------------------ worksheet parsing
_WORKSHEET_NAME_RE = re.compile(r"^(?P<host>.+)-worksheet\.csv$", re.IGNORECASE)
_FLAG_VALUES = {"Y": True, "YES": True, "TRUE": True, "1": True,
                "N": False, "NO": False, "FALSE": False, "0": False}


def parse_worksheet(path: Union[str, Path], config: StudyConfig,
                    expected_host: Optional[str] = None) -> Worksheet:
    """Parse a filled manual worksheet (formats.WORKSHEET_COLUMNS layout).

    Raises StudyError only when the file cannot be read as a worksheet at
    all (missing file or columns). Everything else is returned as findings
    on the Worksheet: a blank verdict or a blank level of a configured
    methodology (the seven properties and overall) is CRITICAL, an
    unrecognized value is CRITICAL, UNASSESSED without a reason is a
    WARNING. A blank overall_excl_input_driven level is allowed and noted.
    The host code is checked against `expected_host` (default: taken from
    the file name, <H>-worksheet.csv)."""
    path = Path(path)
    if expected_host is None:
        match = _WORKSHEET_NAME_RE.match(path.name)
        expected_host = match.group("host") if match else None
    rows = read_csv(path, ("row_type", "item", "property", "value", "unassessed_reason"))
    sheet = Worksheet(path=path, host=expected_host or "")

    def add(check: str, level: str, detail: str) -> None:
        sheet.findings.append(Finding(check, level, sheet.host, detail))

    unreadable_levels: Set[Tuple[str, str]] = set()
    for row in rows:
        kind = row["row_type"].strip().lower()
        if kind == ROW_META:
            _parse_meta_row(sheet, row, add)
        elif kind == ROW_CHECK:
            _parse_check_row(sheet, row, add)
        elif kind == ROW_LEVEL:
            _parse_level_row(sheet, row, config, add, unreadable_levels)
        else:
            add("worksheet", WARNING, f"row with unknown row_type {row['row_type']!r} ignored "
                                      f"(item {row['item']!r})")

    _check_meta(sheet, expected_host, add)
    for methodology in config.methodologies:
        given = sheet.levels.get(methodology, {})
        missing = [scope for scope in H1_SCOPES
                   if given.get(scope) is None and (methodology, scope) not in unreadable_levels]
        if missing:
            add("levels", CRITICAL, f"missing level(s) for {methodology}: {', '.join(missing)}")
        if given.get(OVERALL_EXCL) is None and (methodology, OVERALL_EXCL) not in unreadable_levels:
            sheet.notes.append(f"{methodology} {OVERALL_EXCL}: no manual level entered; that secondary "
                               "comparison is skipped for this host")
    return sheet


def _parse_meta_row(sheet: Worksheet, row: Dict[str, str], add) -> None:
    key = row["item"].strip().lower()
    if not key:
        add("worksheet", WARNING, "meta row without a field name ignored")
    elif key in sheet.meta:
        add("worksheet", WARNING, f"meta field {key!r} appears more than once; the first value is used")
    else:
        sheet.meta[key] = row["value"].strip()


def _parse_check_row(sheet: Worksheet, row: Dict[str, str], add) -> None:
    check_id = row["item"].strip()
    if not check_id:
        add("verdicts", CRITICAL, "check row without a check id")
        return
    if check_id in sheet.verdicts:
        add("verdicts", CRITICAL, f"{check_id}: more than one check row; the first is used")
        return
    raw = row["value"]
    reason = row["unassessed_reason"].strip()
    sheet.check_ids.append(check_id)
    sheet.check_properties[check_id] = row["property"].strip()
    sheet.raw_verdicts[check_id] = raw.strip()
    sheet.reasons[check_id] = reason
    sheet.procedure[check_id] = {column: (row.get(column) or "").strip() for column, _ in PROCEDURE_COLUMNS}
    try:
        verdict = normalize_verdict(raw)
    except StudyError:
        verdict = None
        add("verdicts", CRITICAL, f"{check_id}: unrecognized verdict {raw.strip()!r}")
    else:
        if verdict is None:
            add("verdicts", CRITICAL, f"{check_id}: missing verdict")
        elif verdict == UNASSESSED and not reason:
            add("verdicts", WARNING, f"{check_id}: UNASSESSED without an unassessed_reason")
    sheet.verdicts[check_id] = verdict


def _parse_level_row(sheet: Worksheet, row: Dict[str, str], config: StudyConfig, add,
                     unreadable: Set[Tuple[str, str]]) -> None:
    methodology = row["item"].strip().lower()
    scope = row["property"].strip().lower()
    if methodology not in METHODOLOGY_REGISTRY:
        add("levels", WARNING, f"level row for unknown methodology {row['item']!r} ignored")
        return
    if scope not in LEVEL_SCOPES:
        add("levels", WARNING, f"level row {methodology} {row['property']!r}: unknown scope, ignored")
        return
    # Rows for a methodology the study does not analyse cannot affect results.
    severity = CRITICAL if methodology in config.methodologies else WARNING
    given = sheet.levels.setdefault(methodology, {})
    if scope in given:
        add("levels", severity, f"{methodology} {scope}: more than one level row; the first is used")
        return
    sheet.raw_levels.setdefault(methodology, {})[scope] = row["value"].strip()
    try:
        given[scope] = parse_level(row["value"], config.manual_max(methodology))
    except StudyError as exc:
        given[scope] = None
        unreadable.add((methodology, scope))
        add("levels", severity, f"{methodology} {scope}: {exc}")


def _check_meta(sheet: Worksheet, expected_host: Optional[str], add) -> None:
    fmt = sheet.meta.get("worksheet_format", "")
    if fmt != WORKSHEET_FORMAT:
        add("worksheet", CRITICAL, f"worksheet_format is {fmt!r}, expected {WORKSHEET_FORMAT!r}")
    code = sheet.meta.get("host_code", "")
    if expected_host is not None and code != expected_host:
        add("worksheet", CRITICAL, f"host_code is {code!r}, expected {expected_host!r}")
    if not sheet.host:
        sheet.host = code
    try:
        sheet.session_date = parse_date(sheet.meta.get("session_date"))
    except StudyError as exc:
        add("worksheet", CRITICAL, f"session_date: {exc}")
    flag = sheet.meta.get("synthetic", "")
    if not flag:
        sheet.synthetic = False
    elif flag.upper() in _FLAG_VALUES:
        sheet.synthetic = _FLAG_VALUES[flag.upper()]
    else:
        sheet.synthetic = None
        add("worksheet", WARNING, f"synthetic flag {flag!r} not understood (use yes or no)")


# ------------------------------------------------------------------ pre-hash worksheet lint
def lint_worksheet(path: Union[str, Path], config: StudyConfig,
                   expected_host: Optional[str]) -> List[Tuple[str, str]]:
    """Check a filled worksheet before it is hashed, while it can still be
    corrected (a hashed worksheet never changes). Returns (severity,
    message) findings, empty when nothing was found:

    - everything parse_worksheet reports (blank or unrecognized verdicts and
      levels, a level outside the study's range, the worksheet format, host
      code and session date), with the severity agreement would give it;
    - a synthetic flag that differs from the study configuration's (CRITICAL
      in agreement, for good, once the sheet is hashed);
    - an enabled_checks_fingerprint that does not match the check rows;
    - a blank assessor or level_rule meta value (WARNING each);
    - on every check row whose verdict is not UNASSESSED, a blank
      pass_criterion, evidence_procedure or procedure_source: one WARNING
      per column, listing the check ids (protocol section 6: procedure_source
      is NONE when no external procedure exists);
    - when level_rule.manual is not declared, a WARNING that no level was
      checked (decision 4); when it is approved and level_rule.overall is not
      declared, a WARNING that the overall levels were not checked;
    - when level_rule.manual is declared: every level entered that differs
      from the level this worksheet's own verdicts give under that rule
      (UNASSESSED entered where nothing can be scored agrees). The overall
      levels are checked only when level_rule.overall is declared or the
      manual rule is tool-cutoffs, which defines its own overall level.

    Every finding stops `ledger record --kind worksheet` unless --force is
    given. A file that cannot be read as a worksheet is one CRITICAL
    finding. Reads only the worksheet and the configuration given: never a
    tool output, so it is safe before the worksheet is hashed; every message
    comes from the sheet's own cells and the configuration."""
    path = Path(path)
    try:
        sheet = parse_worksheet(path, config, expected_host=expected_host)
    except StudyError as exc:
        return [(CRITICAL, f"not a worksheet this command can read: {_without_folder(str(exc), path)}")]
    findings = [(finding.level, finding.detail) for finding in sheet.findings]
    if sheet.synthetic is not None and sheet.synthetic != bool(config.synthetic):
        findings.append((CRITICAL, f"synthetic is {'yes' if sheet.synthetic else 'no'}, but the study configuration "
                                   f"says synthetic: {'true' if config.synthetic else 'false'}"))
    recorded = sheet.meta.get("enabled_checks_fingerprint", "")
    if recorded and recorded != check_ids_fingerprint(sheet.check_ids):
        findings.append((WARNING, "enabled_checks_fingerprint does not match the check rows (rows edited, removed "
                                  "or reordered?)"))
    for key, advice in ASSESSOR_META:
        if not sheet.meta.get(key, ""):
            findings.append((WARNING, f"meta {key} is blank: {advice}"))
    for column, advice in PROCEDURE_COLUMNS:
        blank = [check_id for check_id in sheet.check_ids if sheet.verdicts.get(check_id) != UNASSESSED
                 and not sheet.procedure.get(check_id, {}).get(column)]
        if blank:
            findings.append((WARNING, f"{column} is blank for {', '.join(blank)}: {advice}"))
    if config.manual_level_rule is None:
        findings.append((WARNING, NO_MANUAL_RULE))
    elif config.manual_level_rule == LEVEL_RULE_APPROVED and config.overall_rule is None:
        findings.append((WARNING, NO_OVERALL_RULE))
    findings.extend(_lint_levels(sheet, config))
    return findings


def _without_folder(message: str, path: Path) -> str:
    """A message with the file's folder left out (only its name stays)."""
    for spelled in {str(path), str(path.resolve())}:
        message = message.replace(spelled, path.name)
    return message


def _off_rule(typed: LevelValue, expected: LevelValue) -> bool:
    """Whether a typed manual level differs from the level the worksheet's
    own verdicts give under the declared manual rule. Never for a scope with
    a blank or unreadable verdict (expected "missing") or a blank or
    unreadable typed level (None); UNASSESSED typed where nothing can be
    scored (expected None) agrees."""
    if expected == MANUAL_MISSING or typed is None or typed == expected:
        return False
    return not (typed == UNASSESSED and expected is None)


def _lint_levels(sheet: Worksheet, config: StudyConfig) -> List[Tuple[str, str]]:
    """Levels entered against the levels the sheet's own verdicts give under
    the declared manual rule (derive_worksheet_levels). Skipped: scopes with
    a blank or unreadable verdict ("missing"; parse_worksheet reports it),
    blank or unreadable levels (reported too, or an optional scope left
    blank), and the overall scopes when the rule defines no overall level."""
    rule = config.manual_level_rule
    if rule is None:
        return []
    if rule == LEVEL_RULE_APPROVED and config.overall_rule is not None:
        named = f"{rule}, overall {config.overall_rule}"
    else:
        named = rule
    findings: List[Tuple[str, str]] = []
    for methodology in config.methodologies:
        try:
            derived = derive_worksheet_levels(sheet, methodology, rule, config.overall_rule, config)
        except (ValueError, StudyError) as exc:
            findings.append((WARNING, f"{methodology} levels not checked against the declared manual rule ({rule}): "
                                      f"{exc}"))
            continue
        entered = sheet.levels.get(methodology, {})
        for scope in LEVEL_SCOPES:
            if scope not in derived:
                continue
            expected, typed = derived[scope], entered.get(scope)
            if not _off_rule(typed, expected):
                continue
            where = f"{methodology} {scope}"
            if expected is None:
                findings.append((WARNING, f"{where}: level {typed} entered, but no verdict of this scope can be scored "
                                          f"(all N/A or UNASSESSED), so the declared manual rule ({named}) gives no "
                                          "level; enter UNASSESSED"))
            else:
                shown = "UNASSESSED" if typed == UNASSESSED else f"level {typed}"
                findings.append((WARNING, f"{where}: {shown} entered, but this worksheet's verdicts give level "
                                          f"{expected} under the declared manual rule ({named})"))
    return findings


# ------------------------------------------------------------------ tool levels
def _status(value: object) -> Optional[Status]:
    try:
        return Status(value)
    except ValueError:
        return None


# ------------------------------------------------------------------ level rules
# The definitions behind level_rule (formats.LEVEL_RULE_VALUES), implemented
# once and used for the tool side, the rule_only flag and the worksheet lint.
#
# Scorable statuses are PASS, PARTIAL, FAIL and ERROR (ERROR scores 0).
# NOT_APPLICABLE, NOT_IMPLEMENTED and checks dropped as UNASSESSED are left
# out; a property with no scorable check has no level.
#
# tool-cutoffs: exactly miccmac's own scoring (engine.score_property,
#   engine.overall_score) and the methodology's cutoffs.
# approved, in exact arithmetic (fractions.Fraction):
#   property pass ratio r = (PASS + PARTIAL / 2) / scorable checks, and
#   approved_level(r): 0 -> 1; 0 < r < 1/2 -> 2; 1/2 <= r < 1 -> 3; 1 -> 4.
#   The overall level (and overall_excl_input_driven, over the properties
#   that are not input-driven) follows the overall rule, over the properties
#   that have a level:
#     mean-of-property-ratios  approved_level(mean of the property ratios)
#     pooled-checks            approved_level(ratio over every scorable check of the scope)
#     step4-buckets            approved_level(mean of (L - 1) / 3)
#     step4-rounded            1 + round-half-up(mean of (L - 1))
_SCORABLE = (Status.PASS, Status.PARTIAL, Status.FAIL, Status.ERROR)
_NO_OVERALL = object()   # approved rule without an overall rule: overall scopes undefined


def approved_level(ratio: Union[Fraction, int]) -> int:
    """The approved Step 2 level for a pass ratio 0 <= ratio <= 1, compared
    exactly: 0 -> 1; 0 < ratio < 1/2 -> 2; 1/2 <= ratio < 1 -> 3; 1 -> 4.
    Level 5 is never assigned."""
    ratio = Fraction(ratio)
    if not 0 <= ratio <= 1:
        raise ValueError(f"a pass ratio must be from 0 to 1, got {ratio}")
    if ratio == 0:
        return 1
    if ratio < Fraction(1, 2):
        return 2
    if ratio < 1:
        return 3
    return APPROVED_MAX_LEVEL


@dataclass(frozen=True)
class _PropertyTally:
    """A property's scorable-check counts under the approved rule."""
    key: str
    passed: int
    partial: int
    scorable: int

    @classmethod
    def of(cls, key: str, statuses: Iterable[Status]) -> "_PropertyTally":
        statuses = list(statuses)
        return cls(key=key, passed=sum(1 for s in statuses if s == Status.PASS),
                   partial=sum(1 for s in statuses if s == Status.PARTIAL),
                   scorable=sum(1 for s in statuses if s in _SCORABLE))

    @property
    def ratio(self) -> Optional[Fraction]:
        """(PASS + PARTIAL / 2) / scorable, or None with nothing scorable."""
        return Fraction(2 * self.passed + self.partial, 2 * self.scorable) if self.scorable else None

    @property
    def level(self) -> Optional[int]:
        ratio = self.ratio
        return None if ratio is None else approved_level(ratio)


def _approved_overall(tallies: Sequence[_PropertyTally], overall_rule: str) -> Optional[int]:
    """The overall level of `tallies` under the approved rule and
    `overall_rule`, over the properties that have a level; None when none
    has one."""
    scored = [t for t in tallies if t.scorable]
    if not scored:
        return None
    count = len(scored)
    if overall_rule == OVERALL_MEAN_OF_PROPERTY_RATIOS:
        return approved_level(sum((t.ratio for t in scored), Fraction(0)) / count)
    if overall_rule == OVERALL_POOLED_CHECKS:
        return approved_level(Fraction(sum(2 * t.passed + t.partial for t in scored),
                                       sum(2 * t.scorable for t in scored)))
    steps = sum(t.level - 1 for t in scored)          # each L - 1 is 0..3
    if overall_rule == OVERALL_STEP4_BUCKETS:
        return approved_level(Fraction(steps, (APPROVED_MAX_LEVEL - 1) * count))
    if overall_rule == OVERALL_STEP4_ROUNDED:
        return 1 + math.floor(Fraction(steps, count) + Fraction(1, 2))
    raise ValueError(f"unknown overall rule {overall_rule!r}; use one of {', '.join(LEVEL_RULE_VALUES['overall'])}")


def _levels_for_groups(groups: Sequence[Tuple[str, Sequence[Optional[Status]]]], methodology: str, rule: str,
                       overall_rule: Optional[str], input_driven_properties: Iterable[str]) -> Dict[str, LevelValue]:
    """Levels per scope from (property key, statuses) groups in property
    order. Statuses must already exclude dropped (UNASSESSED) checks; None
    stands for a blank or unreadable verdict, which makes its property, the
    overall and (unless the property is input-driven) overall_excl
    MANUAL_MISSING. Under the approved rule without an overall rule the two
    overall scopes are left out of the result."""
    excluded = set(input_driven_properties)
    levels: Dict[str, LevelValue] = {key: None for key in PROPERTY_KEYS}
    missing = {key for key, statuses in groups if any(s is None for s in statuses)}
    overall: object
    overall_excl: object
    if rule == LEVEL_RULE_TOOL_CUTOFFS:
        method = get_methodology(methodology)
        properties: List[PropertyResult] = []
        for key, statuses in groups:
            result = PropertyResult(key=key, letter="", title="",
                                    checks=[CheckResult(check_id="", name="", status=s)
                                            for s in statuses if s is not None])
            result.score = score_property(result)
            properties.append(result)
            levels[key] = method.score_property(result).level
        kept = [p for p in properties if p.key not in excluded]
        overall = method.score_overall(overall_score(properties)).level
        overall_excl = method.score_overall(overall_score(kept)).level
    elif rule == LEVEL_RULE_APPROVED:
        methodology_level_count(methodology)          # an unknown methodology is a StudyError
        tallies = [_PropertyTally.of(key, (s for s in statuses if s is not None)) for key, statuses in groups]
        for tally in tallies:
            levels[tally.key] = tally.level
        if overall_rule is None:
            overall = overall_excl = _NO_OVERALL
        else:
            overall = _approved_overall(tallies, overall_rule)
            overall_excl = _approved_overall([t for t in tallies if t.key not in excluded], overall_rule)
    else:
        raise ValueError(f"unknown level rule {rule!r}; use {' or '.join(LEVEL_RULE_VALUES['manual'])}")
    for key in missing:
        levels[key] = MANUAL_MISSING
    if overall is not _NO_OVERALL:
        levels[OVERALL] = MANUAL_MISSING if missing else overall
        levels[OVERALL_EXCL] = MANUAL_MISSING if missing - excluded else overall_excl
    return levels


def _output_groups(output: ToolOutput, drop: Iterable[str]) -> List[Tuple[str, List[Optional[Status]]]]:
    """A tool output's statuses per property, in report order, without the
    checks in `drop`; an unknown status is treated as not scorable."""
    dropped = set(drop)
    groups: List[Tuple[str, List[Optional[Status]]]] = []
    for prop in output.assessment.get("properties", []):
        statuses: List[Optional[Status]] = []
        for check in prop.get("checks", []):
            status = _status(check.get("status"))
            if check.get("check_id") in dropped or status is None:
                continue
            statuses.append(status)
        groups.append((prop.get("key"), statuses))
    return groups


def recompute_levels(output: ToolOutput, methodology: str, drop: Iterable[str] = (),
                     input_driven_properties: Iterable[str] = ()) -> Dict[str, Optional[int]]:
    """Tool levels per scope (seven properties, overall, overall excluding
    the input-driven properties), recomputed from the output's per-check
    statuses after leaving out the checks in `drop`, with miccmac's own
    scoring (engine.score_property / overall_score) and the methodology's
    cutoffs. An unknown status is treated as not scorable. This is the
    tool-cutoffs rule; it reproduces the levels the tool reports."""
    return rule_levels(output, methodology, LEVEL_RULE_TOOL_CUTOFFS, None, drop, input_driven_properties)


def rule_levels(output: ToolOutput, methodology: str, rule: str, overall_rule: Optional[str],
                drop: Iterable[str] = (), input_driven_properties: Iterable[str] = ()) -> Dict[str, Optional[int]]:
    """Tool levels per scope from the output's per-check statuses, without
    the checks in `drop`, under `rule` ("tool-cutoffs" or "approved"; the
    approved rule needs an `overall_rule`)."""
    if rule == LEVEL_RULE_APPROVED and overall_rule is None:
        raise ValueError("the approved rule needs an overall rule for the tool side")
    return _levels_for_groups(_output_groups(output, drop), methodology, rule, overall_rule,
                              input_driven_properties)


def _tool_levels_used(output: ToolOutput, methodology: str, drop: Iterable[str],
                      config: StudyConfig) -> Dict[str, Optional[int]]:
    """The tool levels compared with the manual levels: the tool-side rule."""
    return rule_levels(output, methodology, config.tool_side_rule, config.overall_rule, drop,
                       config.input_driven_properties)


def derive_levels_from_verdicts(verdicts_by_check: Mapping[str, Optional[str]], methodology: str, rule: str,
                                overall_rule: Optional[str], config: StudyConfig, *,
                                check_properties: Mapping[str, str]) -> Dict[str, LevelValue]:
    """Levels derived from a worksheet's verdicts under a level rule.

    verdicts_by_check maps check id -> verdict, as Worksheet.verdicts holds
    them: PASS, PARTIAL, FAIL, NOT_APPLICABLE or UNASSESSED (tool statuses
    ERROR and NOT_IMPLEMENTED are accepted too), or None for a blank or
    unreadable cell. check_properties maps each check id to its property key
    (the worksheet's property column). rule is "approved" or "tool-cutoffs";
    overall_rule is one of formats.LEVEL_RULE_VALUES["overall"] or None; config
    supplies input_driven_properties for overall_excl_input_driven.

    UNASSESSED checks are dropped, NOT_APPLICABLE and NOT_IMPLEMENTED are not
    scored, ERROR scores 0. Returns scope -> value for the seven properties,
    overall and overall_excl_input_driven: an int level; None when the scope
    has no scorable check (no level, so the manual level is UNASSESSED); or
    MANUAL_MISSING ("missing") when a verdict the scope depends on is None.
    Under the approved rule with overall_rule None, the two overall scopes
    are left out. Reads only the verdicts given: no tool output is involved,
    so it is safe before a worksheet is hashed. Raises ValueError for an
    unknown rule, verdict or property, and StudyError for an unknown
    methodology."""
    if rule not in LEVEL_RULE_VALUES["manual"]:
        raise ValueError(f"unknown level rule {rule!r}; use {' or '.join(LEVEL_RULE_VALUES['manual'])}")
    if overall_rule is not None and overall_rule not in LEVEL_RULE_VALUES["overall"]:
        raise ValueError(f"unknown overall rule {overall_rule!r}; use one of "
                         f"{', '.join(LEVEL_RULE_VALUES['overall'])}")
    methodology_level_count(methodology)
    grouped: Dict[str, List[Optional[Status]]] = {key: [] for key in PROPERTY_KEYS}
    for check_id, verdict in verdicts_by_check.items():
        key = str(check_properties.get(check_id) or "").strip().lower()
        if key not in grouped:
            raise ValueError(f"{check_id}: property {check_properties.get(check_id)!r} is not one of "
                             f"{', '.join(PROPERTY_KEYS)}")
        if isinstance(verdict, Status):
            grouped[key].append(verdict)
            continue
        text = verdict.strip().upper() if isinstance(verdict, str) else verdict
        if text is None or text == "":
            grouped[key].append(None)
        elif text != UNASSESSED:
            status = _status(text)
            if status is None:
                raise ValueError(f"{check_id}: unrecognized verdict {verdict!r}")
            grouped[key].append(status)
    return _levels_for_groups([(key, grouped[key]) for key in PROPERTY_KEYS], methodology, rule, overall_rule,
                              config.input_driven_properties)


def derive_worksheet_levels(sheet: Worksheet, methodology: str, rule: str, overall_rule: Optional[str],
                            config: StudyConfig) -> Dict[str, LevelValue]:
    """derive_levels_from_verdicts() on a parsed worksheet's check rows."""
    return derive_levels_from_verdicts({c: sheet.verdicts.get(c) for c in sheet.check_ids}, methodology, rule,
                                       overall_rule, config, check_properties=sheet.check_properties)


def _worksheet_rule_levels(sheet: Worksheet, output: ToolOutput, methodology: str,
                           config: StudyConfig) -> Dict[str, LevelValue]:
    """The worksheet's verdicts leveled with the tool-side rule (for
    rule_only), each check under the property the tool output gives it (the
    worksheet's own property column when the tool output lacks the check).
    A check with no known property is left out; the check-set integrity
    check reports it."""
    tool_props = {c.get("check_id"): c.get("property_key") for c in output.checks()}
    verdicts: Dict[str, Optional[str]] = {}
    props: Dict[str, str] = {}
    for check_id in sheet.check_ids:
        key = str(tool_props.get(check_id) or sheet.check_properties.get(check_id) or "").strip().lower()
        if key in PROPERTY_KEYS:
            verdicts[check_id] = sheet.verdicts.get(check_id)
            props[check_id] = key
    return derive_levels_from_verdicts(verdicts, methodology, config.tool_side_rule, config.overall_rule, config,
                                       check_properties=props)


def _enabled_checks(output: ToolOutput) -> List[dict]:
    """The output's checks in report order, without checks excluded by the
    tool configuration (those are not on the enabled list or worksheet)."""
    excluded = set(output.assessment.get("excluded_check_ids") or [])
    return [c for c in output.checks() if c.get("check_id") not in excluded]


def _provenance(output: ToolOutput) -> Optional[dict]:
    value = output.provenance
    return value if isinstance(value, dict) else None


# ------------------------------------------------------------------ integrity checks
def _run_integrity_checks(study: Study) -> None:
    study.analysis_code = _analysis_code()
    _check_hosts(study)
    _check_provenance(study)
    _check_check_sets(study)
    _check_list_checks(study)
    _check_as_of(study)
    _check_consistency(study)
    _check_inputs(study)
    _check_build(study)
    _check_analysis_code(study)
    _check_tool_statuses(study)
    _check_reproduction(study)
    _check_config(study)
    _check_forced_unseal(study)
    _check_ledger(study)


def _first_seal_opening(study: Study) -> Optional[Tuple[int, LedgerRow]]:
    """O: the first seal opening in the ledger (ledger.first_seal_opening),
    with its 0-based index. After _record_seal_opening there always is one."""
    return study_ledger.first_seal_opening(study.ledger)


def _withdrawal_rows(study: Study) -> Dict[str, Tuple[int, LedgerRow]]:
    """host -> (0-based index, row) of its first withdrawal row, the one
    ledger.withdrawn_hosts takes the time and reason from."""
    found: Dict[str, Tuple[int, LedgerRow]] = {}
    for index, row in enumerate(study.ledger):
        code = (row.host_code or "").strip()
        if study_ledger.is_withdrawal(row) and code and not study_ledger.is_study_code(code) and code not in found:
            found[code] = (index, row)
    return found


def _check_hosts(study: Study) -> None:
    """Hosts left out of the analysis: withdrawn in the ledger (time and
    reason), or part of the study folder but not of the configuration.

    A withdrawal recorded after the seal first opened (or with --after-unseal)
    is a post-hoc exclusion: CRITICAL. One recorded before is a WARNING, which
    says so when the host's tool outputs or facts were already hashed then."""
    order = {host: i for i, host in enumerate(study.config_hosts)}
    opened = _first_seal_opening(study)
    rows = _withdrawal_rows(study)
    for host in sorted(study.withdrawn, key=lambda h: (order.get(h, len(order)), h)):
        when, reason = study.withdrawn[host]
        index = rows[host][0] if host in rows else None
        if opened is not None and index is not None and (
                index > opened[0] or reason.startswith(study_ledger.AFTER_UNSEAL_REASON_PREFIX)):
            study.add("hosts", CRITICAL, host,
                      f"{host} was withdrawn at {when}, after the seal was first opened at "
                      f"{opened[1].recorded_at_utc} (ledger line {opened[0] + 2}): a post-hoc exclusion; the "
                      f"pre-registered analysis includes {host}")
            study.post_hoc_exclusions.append(f"{host} withdrawn after the seal first opened (a post-hoc exclusion)")
            continue
        tool = study_ledger.first_tool_row(study.ledger, host)
        if tool is not None and index is not None and tool[0] < index:
            study.add("hosts", WARNING, host,
                      f"withdrawn after its tool outputs were hashed ({tool[1].recorded_at_utc}), in the ledger at "
                      f"{when}: {reason}; left out of the analysis")
        else:
            study.add("hosts", WARNING, host, f"withdrawn in the ledger at {when}: {reason}; left out of the analysis")
    for host in study.extra_hosts:
        study.add("hosts", WARNING, host, f"has study files but is not in {study.config_path.name}; left out")
    study.checked["hosts"] = (f"{len(study.config.hosts)} hosts analysed ({', '.join(study.config.hosts)}): every "
                              f"host of {study.config_path.name}; none withdrawn, no other host in the study folder")


def _outputs_in_order(study: Study) -> Iterable[Tuple[str, str, ToolOutput]]:
    for host in study.config.hosts:
        for methodology in study.config.methodologies:
            output = study.outputs.get(host, {}).get(methodology)
            if output is not None:
                yield host, methodology, output


def _check_provenance(study: Study) -> None:
    count = 0
    for host, methodology, output in _outputs_in_order(study):
        count += 1
        name = output.path.name
        found = output.methodology_name
        if found is None:
            study.add("provenance", CRITICAL, host,
                      f"{name}: no methodology levels (run with --methodology {methodology})")
        elif found != methodology:
            study.add("provenance", CRITICAL, host, f"{name}: methodology is {found!r}, not {methodology!r}")
        prov = _provenance(output)
        if prov is None:
            study.add("provenance", WARNING, host, f"{name}: no provenance block")
            continue
        if prov.get("provenance_format") != PROVENANCE_FORMAT:
            study.add("provenance", WARNING, host,
                      f"{name}: provenance_format {prov.get('provenance_format')!r}, expected {PROVENANCE_FORMAT!r}")
        if prov.get("methodology") != methodology:
            study.add("provenance", CRITICAL, host,
                      f"{name}: provenance methodology {prov.get('methodology')!r}, not {methodology!r}")
    study.checked["provenance"] = f"{count} tool outputs"


def _check_check_sets(study: Study) -> None:
    """The fairness control: the tool's enabled checks equal the worksheet's
    check rows on every host, and are the same set on every host."""
    tool_sets: Dict[str, List[str]] = {}
    for host in study.config.hosts:
        output = study.reference(host)
        if output is not None:
            tool_sets[host] = [c.get("check_id") for c in _enabled_checks(output)]
    reference_host = next(iter(tool_sets), None)
    reference_ids = set(tool_sets[reference_host]) if reference_host else set()
    for host in study.config.hosts:
        tool_ids = tool_sets.get(host)
        if tool_ids is not None:
            if host != reference_host and set(tool_ids) != reference_ids:
                study.add("check_set", CRITICAL, host,
                          f"tool check ids differ from {reference_host}'s: "
                          + _set_difference(set(tool_ids), reference_ids, host, reference_host))
            for other in study.outputs.get(host, {}).values():
                prov = _provenance(other)
                enabled = prov.get("enabled_check_ids") if prov else None
                if isinstance(enabled, list) and set(enabled) != set(tool_ids):
                    study.add("check_set", CRITICAL, host,
                              f"{other.path.name}: provenance enabled_check_ids differ from the checks in the "
                              "output: " + _set_difference(set(enabled), set(tool_ids), "provenance list", "output"))
        sheet = study.worksheets.get(host)
        if sheet is None:
            continue
        expected = set(tool_ids) if tool_ids is not None else (reference_ids if reference_host else None)
        if expected is not None and set(sheet.check_ids) != expected:
            study.add("check_set", CRITICAL, host,
                      "worksheet check rows differ from the tool's enabled checks: "
                      + _set_difference(set(sheet.check_ids), expected, "worksheet", "tool output"))
        recorded = sheet.meta.get("enabled_checks_fingerprint", "")
        if recorded and recorded != check_ids_fingerprint(sheet.check_ids):
            study.add("check_set", WARNING, host,
                      "worksheet enabled_checks_fingerprint does not match its check rows (rows edited or reordered?)")
        for other in study.outputs.get(host, {}).values():
            prov = _provenance(other)
            tool_print = prov.get("enabled_check_ids_fingerprint") if prov else None
            if recorded and tool_print and tool_print != recorded:
                study.add("check_set", WARNING, host,
                          f"{other.path.name}: enabled_check_ids_fingerprint {tool_print} differs from the "
                          f"worksheet's {recorded} (different list or order)")
    study.checked["check_set"] = (f"{len(reference_ids)} enabled checks on every worksheet and tool output"
                                  if reference_host else "no tool output read")


def _set_difference(first: Set[str], second: Set[str], first_name: str, second_name: str) -> str:
    only_first = sorted(first - second)
    only_second = sorted(second - first)
    parts = []
    if only_first:
        parts.append(f"only on the {first_name}: {', '.join(only_first)}")
    if only_second:
        parts.append(f"only on the {second_name}: {', '.join(only_second)}")
    return "; ".join(parts) or "same ids"


def _check_list_checks(study: Study) -> None:
    """The enabled check set the tool ran equals the list-checks file
    exported once at setup (protocol section 4), when the ledger holds a
    STUDY list-checks row: the latest such row, whose file must still have
    its recorded hash."""
    rows = [item for item in study.row_states if study_ledger.is_study_code(item.row.host_code)
            and study_ledger.row_kind(item.row) == LIST_CHECKS_KIND]
    if not rows:
        study.checked["list_checks"] = "no STUDY list-checks row in the ledger, so nothing to compare"
        return
    latest = rows[-1]
    path = resolve_ledger_path(study.ledger_path, latest.row.path)
    where = f"{study.rel(path)} (ledger line {latest.index + 2})"
    if latest.state != study_ledger.OK:
        study.add("list_checks", WARNING, "",
                  f"{where} is {latest.state}, so the tool's enabled checks are not compared with it")
        return
    try:
        listed = read_list_checks(path)
    except StudyError as exc:
        study.add("list_checks", WARNING, "", f"cannot read {where}: {study.clean(str(exc))}")
        return
    for host, methodology, output in _outputs_in_order(study):
        enabled = {check.get("check_id") for check in _enabled_checks(output)}
        if enabled != set(listed):
            study.add("list_checks", CRITICAL, host,
                      f"{output.path.name}: enabled checks differ from {study.rel(path)}, the list-checks file "
                      "hashed at setup: " + _set_difference(enabled, set(listed), "tool output", "list-checks file"))
    study.checked["list_checks"] = f"every tool output ran the {len(listed)} checks of {study.rel(path)}"


def _check_as_of(study: Study) -> None:
    for host, methodology, output in _outputs_in_order(study):
        sheet = study.worksheets.get(host)
        if sheet is None or sheet.session_date is None:
            continue
        name = output.path.name
        prov = _provenance(output)
        if prov is None:
            study.add("as_of", WARNING, host, f"{name}: no provenance, so --as-of cannot be verified")
            continue
        raw = prov.get("as_of")
        if raw is None:
            study.add("as_of", CRITICAL, host,
                      f"{name}: run without --as-of (as_of null); worksheet session_date is {sheet.session_date}")
            continue
        try:
            as_of = parse_date(str(raw))
        except StudyError:
            study.add("as_of", CRITICAL, host, f"{name}: as_of {raw!r} is not a date")
            continue
        if as_of != sheet.session_date:
            study.add("as_of", CRITICAL, host,
                      f"{name}: as_of {as_of} differs from the worksheet session_date {sheet.session_date}")
    study.checked["as_of"] = "every tool output's as_of equals its worksheet's session_date"


def _check_consistency(study: Study) -> None:
    for host in study.config.hosts:
        outputs = study.outputs.get(host, {})
        names = [m for m in study.config.methodologies if m in outputs]
        if len(names) < 2:
            continue
        first = outputs[names[0]]
        first_statuses = first.statuses()
        for methodology in names[1:]:
            other = outputs[methodology]
            label = f"{names[0]} and {methodology} outputs"
            statuses = other.statuses()
            differing = sorted(cid for cid in set(first_statuses) | set(statuses)
                               if first_statuses.get(cid) != statuses.get(cid))
            if differing:
                shown = ", ".join(f"{cid} ({first_statuses.get(cid) or 'absent'} vs "
                                  f"{statuses.get(cid) or 'absent'})" for cid in differing)
                study.add("consistency", CRITICAL, host, f"per-check statuses differ between {label}: {shown}")
            prov_a, prov_b = _provenance(first), _provenance(other)
            if prov_a is None or prov_b is None:
                continue
            sha_a = _nested(prov_a, "facts_file", "sha256")
            sha_b = _nested(prov_b, "facts_file", "sha256")
            if sha_a and sha_b and sha_a != sha_b:
                study.add("consistency", CRITICAL, host, f"facts_file sha256 differs between {label}")
            for key in ("attestation", "inventory_record", "config"):
                in_a = _nested(prov_a, "inputs", key, "sha256")
                in_b = _nested(prov_b, "inputs", key, "sha256")
                if in_a and in_b and in_a != in_b:
                    study.add("consistency", CRITICAL, host, f"{key} input sha256 differs between {label}")
            if prov_a.get("target") != prov_b.get("target"):
                study.add("consistency", CRITICAL, host, f"target differs between {label}")
    study.checked["consistency"] = "statuses, facts_file and input hashes compared per host"


def _nested(data: object, *keys: str) -> Optional[object]:
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


# Provenance inputs (miccmac provenance "inputs" block) and how messages name them.
_INPUT_LABELS = {"attestation": "attestation", "inventory_record": "inventory record", "config": "miccmac config"}
_FILE_INPUTS = ("attestation", "inventory_record")


def _provenance_sha(entry: object) -> Optional[str]:
    """The sha256 of a provenance file record, or None when there is none."""
    if not isinstance(entry, dict):
        return None
    value = entry.get("sha256")
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _given_inputs(prov: dict) -> Dict[str, str]:
    """Provenance input key -> sha256, for the inputs the run was given."""
    inputs = prov.get("inputs")
    if not isinstance(inputs, dict):
        return {}
    given = {}
    for key in _INPUT_LABELS:
        digest = _provenance_sha(inputs.get(key))
        if digest is not None:
            given[key] = digest
    return given


def _check_inputs(study: Study) -> None:
    """The identical-inputs control (protocol section 4), per host and tool
    output. Inputs are matched by sha256, never by path (provenance keeps
    paths as typed):

    - the attestation and inventory record the run was given must be the
      versions the assessor had, each in its own role: ledger.assessor_inputs
      and ledger.check_run_inputs, the rule `health --ledger` uses (the
      version of a host's input file is its latest input row recorded before
      the host's first worksheet row; the role comes from the recorded name,
      <H>-attestation.json or <H>-inventory-record.json). The same file given
      twice, swapped files, a version recorded only after the worksheet was
      hashed, a file not recorded for the host and, when an input-driven
      check is enabled, an input the ledger holds that the run was not given
      are CRITICAL; a file whose name gives no role is a WARNING (it cannot
      be checked for a swap);
    - the miccmac config the run was given has the hash of one of the
      host's input rows or of a STUDY row whose file still matches; CRITICAL
      otherwise;
    - with no input rows for the host, a WARNING (once) when the run had
      input files or input-driven checks: they cannot be checked;
    - a WARNING for each input row of the host recorded after its
      worksheet's generated_at_utc and before its first worksheet row: the
      file was recorded again during the blind pass (_check_inputs_in_pass);
    - provenance facts_file.sha256 is the hash of one of the host's facts
      rows (CRITICAL otherwise, also when it is null); a WARNING (once) when
      the host has no facts row.

    Only hashes and ledger times are compared; no input or facts file is read."""
    ledger = study.ledger_path
    current_study = {item.row.sha256 for item in study.row_states
                     if study_ledger.is_study_code(item.row.host_code) and item.state == study_ledger.OK}
    input_driven = set(study.config.input_driven_checks)
    checked = 0
    for host in study.config.hosts:
        mine = [item for item in study.row_states if item.row.host_code == host]
        input_rows = [item for item in mine if study_ledger.row_kind(item.row) == study_ledger.INPUT_KIND]
        current = {item.row.sha256 for item in input_rows if item.state == study_ledger.OK}
        facts = {item.row.sha256 for item in mine if study_ledger.row_kind(item.row) == study_ledger.FACTS_KIND}
        hashed_at, assessor = study_ledger.assessor_inputs(ledger, host)
        _check_inputs_in_pass(study, host)
        warned: Set[str] = set()
        for methodology in study.config.methodologies:
            output = study.outputs.get(host, {}).get(methodology)
            prov = _provenance(output) if output is not None else None
            if output is None or prov is None:
                continue        # the files and provenance checks report these
            checked += 1
            name = output.path.name
            given = _given_inputs(prov)
            enabled = {check.get("check_id") for check in _enabled_checks(output)} & input_driven
            if assessor:
                files = {key: digest for key, digest in given.items() if key in _FILE_INPUTS}
                for code, message in study_ledger.check_run_inputs(files, assessor, bool(enabled), host,
                                                                    worksheet_at_utc=hashed_at):
                    level = WARNING if code == study_ledger.INPUT_ROLE_UNKNOWN else CRITICAL
                    study.add("inputs", level, host, f"{name}: {message}")
                digest = given.get("config")
                if digest is not None and digest not in current | current_study:
                    study.add("inputs", CRITICAL, host,
                              f"{name}: the {_INPUT_LABELS['config']} the tool used (sha256 {digest[:12]}...) is not "
                              f"one of the input files recorded for {host} or as a STUDY row in the ledger, or that "
                              "file changed since")
            elif "inputs" not in warned and (enabled or any(
                    not (key == "config" and digest in current_study) for key, digest in given.items())):
                warned.add("inputs")
                study.add("inputs", WARNING, host,
                          f"no input rows for {host} in the ledger, so the input files the tool used cannot be "
                          "checked against the ones the assessor used")
            digest = _provenance_sha(prov.get("facts_file"))
            if facts:
                if digest is None:
                    study.add("inputs", CRITICAL, host,
                              f"{name}: provenance names no facts file, although the ledger holds a facts row for {host}")
                elif digest not in facts:
                    study.add("inputs", CRITICAL, host,
                              f"{name}: the facts file the tool used (sha256 {digest[:12]}...) is not the one recorded "
                              f"in {host}'s facts row")
            elif "facts" not in warned:
                warned.add("facts")
                study.add("inputs", WARNING, host,
                          f"no facts row for {host} in the ledger, so the facts file the tool used cannot be checked")
    study.checked["inputs"] = (f"{checked} tool outputs: every input file the tool used is the version the assessor "
                               "had, in its own role, and every facts file the one hashed for its host")


def _first_worksheet_row(study: Study, host: str) -> Optional[Tuple[int, LedgerRow]]:
    """The host's first worksheet row (kind worksheet, path resolving to
    DIR/worksheets/<H>-worksheet.csv, as ledger.worksheet_rows matches it),
    with its 0-based index, or None."""
    target = study_ledger.file_key(study.worksheet_path(host))
    for index, row in enumerate(study.ledger):
        if study_ledger.row_kind(row) == study_ledger.WORKSHEET_KIND and \
                study_ledger.path_key(study.ledger_path, row.path) == target:
            return index, row
    return None


def _check_inputs_in_pass(study: Study, host: str) -> None:
    """A WARNING for each of the host's input rows (kind input, its host
    code) recorded after the worksheet's generated_at_utc (the blank sheet of
    step 1) and before the host's first worksheet row: the assessor may have
    used another version during part of the pass. Ties in the same second
    are not reported."""
    sheet = study.worksheets.get(host)
    first = _first_worksheet_row(study, host)
    generated = _optional_timestamp(sheet.meta.get("generated_at_utc")) if sheet is not None else None
    if first is None or generated is None:
        return
    seen: Set[str] = set()
    for row in study.ledger[:first[0]]:
        if study_ledger.row_kind(row) != study_ledger.INPUT_KIND or (row.host_code or "").strip() != host:
            continue
        key = study_ledger.path_key(study.ledger_path, row.path)
        again = key in seen
        seen.add(key)
        when = _optional_timestamp(row.recorded_at_utc)
        if when is None or when <= generated:
            continue
        where = study.rel(resolve_ledger_path(study.ledger_path, row.path)) if row.path.strip() else "(no path)"
        study.add("inputs", WARNING, host,
                  f"{where} was recorded {'again ' if again else ''}at {row.recorded_at_utc}, during {host}'s blind "
                  f"pass (sheet generated {_iso(generated)}, hashed {first[1].recorded_at_utc}): check that the whole "
                  "pass used this version")


def _check_build(study: Study) -> None:
    commits: Counter = Counter()
    total = 0
    for host, methodology, output in _outputs_in_order(study):
        prov = _provenance(output)
        if prov is None:
            study.add("build", WARNING, host, f"{output.path.name}: no provenance, so the tool commit is unknown")
            continue
        total += 1
        commit = prov.get("tool_commit")
        commits[commit] += 1
        if commit is None:
            study.add("build", WARNING, host, f"{output.path.name}: tool_commit is null")
        if prov.get("tool_tree_clean") is not True:
            study.add("build", WARNING, host, f"{output.path.name}: tool_tree_clean is not true")
    known = sorted(c for c in commits if c is not None)
    if len(known) > 1:
        shown = ", ".join(f"{c} ({commits[c]} outputs)" for c in known)
        study.add("build", WARNING, "", f"tool outputs come from {len(known)} commits: {shown}")
    if total == 0:
        study.checked["build"] = "no tool output read"
    elif len(known) == 1:
        study.checked["build"] = f"{total} outputs from commit {known[0]}"
    else:
        study.checked["build"] = f"{total} outputs"


def _tool_commits(study: Study) -> List[Dict[str, object]]:
    commits: Counter = Counter()
    clean: Counter = Counter()
    for _, _, output in _outputs_in_order(study):
        prov = _provenance(output)
        if prov is None:
            commits["(no provenance)"] += 1
            continue
        commit = prov.get("tool_commit") or "(null)"
        commits[commit] += 1
        if prov.get("tool_tree_clean") is True:
            clean[commit] += 1
    return [{"commit": c, "outputs": commits[c], "clean_tree": clean[c]} for c in sorted(commits)]


def _check_analysis_code(study: Study) -> None:
    """Protocol section 2: the analysis code is frozen (committed) before
    the outputs are unsealed. A WARNING when miccmac_study has uncommitted
    changes or untracked files, and when git cannot tell (not installed,
    not a repository, an error or a timeout)."""
    clean = study.analysis_code.get("analysis_tree_clean")
    if clean is False:
        study.add("analysis_code", WARNING, "",
                  "miccmac_study has uncommitted changes or untracked files (git status --porcelain -- "
                  "miccmac_study), so the analysis code commit does not hold the code that ran")
    elif clean is None:
        study.add("analysis_code", WARNING, "",
                  "git is not available here, so it could not be checked that the analysis code is committed")
    study.checked["analysis_code"] = ("miccmac_study has no uncommitted or untracked file" if clean
                                      else "not determined: git is not available here")


def _check_tool_statuses(study: Study) -> None:
    for host in study.config.hosts:
        output = study.reference(host)
        if output is None:
            continue
        flagged = []
        for check in _enabled_checks(output):
            status = check.get("status")
            if status in ("ERROR", "NOT_IMPLEMENTED"):
                flagged.append(f"{check.get('check_id')} {status}")
            elif _status(status) is None:
                study.add("tool_status", CRITICAL, host,
                          f"{output.path.name}: {check.get('check_id')} has unknown status {status!r}")
        if flagged:
            study.add("tool_status", WARNING, host, ", ".join(flagged))
    study.checked["tool_status"] = "statuses of every enabled check"


def _check_reproduction(study: Study) -> None:
    for host, methodology, output in _outputs_in_order(study):
        reported = output.levels()
        if not reported:
            continue
        recomputed = recompute_levels(output, methodology, (), study.config.input_driven_properties)
        for scope in H1_SCOPES:
            if recomputed[scope] != reported.get(scope):
                study.add("reproduce", CRITICAL, host,
                          f"{output.path.name}: {scope} level recomputed from the statuses is "
                          f"{_tool_level_text(recomputed[scope])}, reported {_tool_level_text(reported.get(scope))}")
    study.checked["reproduce"] = "levels recomputed with miccmac's scoring equal the reported levels"


def _check_config(study: Study) -> None:
    """The study configuration (protocol: the threshold and the other
    settings are fixed before the first tool run; other values only as
    sensitivity checks). Seal-opening rows never count as a recording of a
    configuration.

    - The configuration file used must match its latest ledger row: CRITICAL
      otherwise (restore it from its archive copy; recording it again after
      the first tool run does not make it pre-registered); a WARNING when it
      was never recorded (_check_config_rows).
    - The pre-registered configuration is DIR/study.yaml as the ledger holds
      it: R, the latest version recorded before the first tool-output or
      facts row (in force at the first tool run), and U, the latest one
      recorded before the first seal opening (in force when tool results
      first became available). The configuration this run loaded (before
      command-line overrides and before withdrawn hosts are left out) must
      equal U in every setting: each difference is listed in one CRITICAL,
      and the run is labelled a sensitivity run. U must equal R: a
      difference is a WARNING, a deviation for the protocol log
      (_check_preregistered)."""
    parts = [text for text in (_check_config_rows(study), _check_preregistered(study)) if text]
    study.checked["config"] = "; ".join(parts) or "no problems found"


def _config_rows(study: Study, path: Path) -> List[study_ledger.RowState]:
    """The ledger rows that record the file at `path` (resolved), seal openings left out."""
    target = study_ledger.file_key(path)
    return [item for item in study.row_states
            if study_ledger.path_key(study.ledger_path, item.row.path) == target
            and not study_ledger.is_seal_opening(item.row)]


def _check_config_rows(study: Study) -> Optional[str]:
    """The configuration file used against its latest ledger row (whatever
    the row's kind: setup, a correction, a withdrawal). Returns the OK text,
    or None after a finding."""
    name = study.config_path.name
    rows = _config_rows(study, study.config_path)
    if not rows:
        # A copy of a recorded version (for example its ledger-archive copy) is that version.
        try:
            current_sha: Optional[str] = sha256_file(study.config_path)
        except OSError:
            current_sha = None
        versions = study_ledger.study_config_rows(study.ledger_path, study.ledger, study.study_dir)
        same = [index for index, row in versions if current_sha is not None and row.sha256 == current_sha]
        if same:
            return f"{name} has the bytes of {CONFIG_FILE} as recorded at ledger line {same[-1] + 2}"
        study.add("config", WARNING, "",
                  f"{name} was never recorded in the ledger, so the settings used cannot be shown to be the ones "
                  "fixed in advance")
        return None
    latest = rows[-1]
    try:
        current: Optional[str] = sha256_file(study.config_path)
    except OSError:
        current = None
    if current != latest.row.sha256:
        now = f"file now {current[:12]}..." if current else "file now unreadable"
        copy = study_ledger.archive_path(study.ledger_path, latest.row)
        source = study.rel(copy) if copy.is_file() else f"your commit (its archive copy {study.rel(copy)} is missing)"
        study.add("config", CRITICAL, "",
                  f"{name} changed after it was last recorded in the ledger (line {latest.index + 2}, "
                  f"{latest.row.recorded_at_utc}): ledger {latest.row.sha256[:12]}..., {now}; restore the recorded "
                  f"file from {source}; recording it again after the first tool run does not make it pre-registered")
        return None
    return f"{name} matches its latest ledger row (line {latest.index + 2}, {latest.row.recorded_at_utc})"


def _recorded_config(study: Study, row: LedgerRow) -> Tuple[Optional[StudyConfig], str]:
    """study.yaml as a ledger row recorded it: read from its ledger-archive
    copy once the copy has the row's hash, or from DIR/study.yaml when that
    has the row's hash. (config, "") or (None, why it cannot be read)."""
    copy = study_ledger.archive_path(study.ledger_path, row)
    why = "archive copy missing"
    if copy.is_file():
        try:
            matches = sha256_file(copy) == row.sha256
        except OSError:
            matches = False
        if matches:
            try:
                return load_study_config(copy), ""
            except (StudyError, UnicodeDecodeError) as exc:
                return None, f"its archive copy does not load: {study.clean(str(exc))}"
        why = "archive copy does not match its recorded hash"
    current = study.study_dir / CONFIG_FILE
    try:
        if current.is_file() and sha256_file(current) == row.sha256:
            return load_study_config(current), ""
    except OSError:
        pass
    except (StudyError, UnicodeDecodeError) as exc:
        return None, f"it does not load: {study.clean(str(exc))}"
    return None, why


def _load_version(study: Study, index: int, row: LedgerRow) -> Optional[StudyConfig]:
    """A recorded version of study.yaml (_recorded_config), or None after a
    CRITICAL saying it cannot be compared."""
    config, why = _recorded_config(study, row)
    if config is None:
        study.add("config", CRITICAL, "",
                  f"cannot load {CONFIG_FILE} as recorded at ledger line {index + 2} ({why}): the configuration used "
                  "cannot be compared with the pre-registered one")
    return config


def _check_preregistered(study: Study) -> Optional[str]:
    """R and U against the configuration used (see _check_config). Returns
    the OK text, or None when there is nothing to say or after a finding."""
    name = study.config_path.name
    versions = study_ledger.study_config_rows(study.ledger_path, study.ledger, study.study_dir)
    default = study.study_dir / CONFIG_FILE
    if not versions:
        if study_ledger.file_key(study.config_path) != study_ledger.file_key(default):
            study.add("config", WARNING, "",
                      f"{CONFIG_FILE} was never recorded in the ledger, so {name} cannot be compared with the "
                      "pre-registered configuration")
        return None
    opened = _first_seal_opening(study)
    tool = study_ledger.first_tool_row(study.ledger)
    before_opening = [item for item in versions if opened is None or item[0] < opened[0]]
    if not before_opening:
        study.add("config", WARNING, "",
                  f"{CONFIG_FILE} was first recorded at ledger line {versions[0][0] + 2}, after the seal was first "
                  f"opened (ledger line {opened[0] + 2 if opened else '?'}), so the settings used cannot be shown to "
                  "be the ones fixed in advance")
        return None
    u_index, u_row = before_opening[-1]
    if tool is None:
        at_tool: Optional[Tuple[int, LedgerRow]] = (u_index, u_row)
    else:
        before_tool = [item for item in versions if item[0] < tool[0]]
        at_tool = before_tool[-1] if before_tool else None
    quiet = True
    u_config = _load_version(study, u_index, u_row)
    r_config: Optional[StudyConfig] = None
    if at_tool is not None and at_tool[1].sha256 != u_row.sha256:
        r_config = _load_version(study, at_tool[0], at_tool[1])
        if r_config is None:
            quiet = False
    used = study.loaded_config or study.config
    labelled: List[str] = []
    critical: List[str] = []
    if u_config is None:
        quiet = False
    else:
        try:
            same_bytes = sha256_file(study.config_path) == u_row.sha256
        except OSError:
            same_bytes = False
        # After the seal opened: any difference from U, except a setting put back to its value in R.
        reference = _reverted(u_config, r_config, used) if r_config is not None else u_config
        critical = [] if same_bytes else _config_differences(reference, used)
        # The pre-registered analysis: R's settings (fixed before the first tool run, protocol section 6), with
        # U's hosts (host changes before unsealing were blind: the seal keeps R's hosts in any case).
        if r_config is not None:
            labelled = _config_differences(dataclasses.replace(r_config, hosts=list(u_config.hosts)), used)
            study.config_reference = (f"the pre-registered settings ({CONFIG_FILE} as recorded at ledger line "
                                      f"{at_tool[0] + 2}, in force at the first tool run)")
        else:
            labelled = critical
            study.config_reference = f"{CONFIG_FILE} as recorded at ledger line {u_index + 2}, when the seal first opened"
        if labelled:
            quiet = False
            study.config_differences = labelled
        if critical:
            study.add("config", CRITICAL, "",
                      f"the configuration used ({name}) differs from {CONFIG_FILE} as it was when the seal first "
                      f"opened (ledger line {u_index + 2}): {'; '.join(critical)}; this run is a sensitivity run, "
                      "not the pre-registered analysis")
    if at_tool is None:
        quiet = False
        study.add("config", WARNING, "",
                  f"{CONFIG_FILE} was first recorded at ledger line {versions[0][0] + 2}, after the first tool run "
                  f"(ledger line {tool[0] + 2 if tool else '?'}), so the version in force at the first tool run is "
                  "unknown; record this deviation in the protocol log")
    elif r_config is not None and u_config is not None:
        changed = _config_differences(r_config, u_config)
        if changed:
            quiet = False
            text = (f"{CONFIG_FILE} changed after the first tool run (version at the first tool run: ledger line "
                    f"{at_tool[0] + 2}; version when the seal opened: line {u_index + 2}): {'; '.join(changed)}; "
                    "record this deviation in the protocol log")
            settings_changed = any(not item.startswith("hosts:") for item in changed)
            if labelled and not critical:
                copy = study.rel(study_ledger.archive_path(study.ledger_path, at_tool[1]))
                hosts = (f", with the hosts of ledger line {u_index + 2}"
                         if set(r_config.hosts) != set(u_config.hosts) else "")
                text += (f"; this run uses the settings changed since then, so it is labelled a sensitivity run; "
                         f"the pre-registered analysis uses those of ledger line {at_tool[0] + 2} (--config {copy}"
                         f"{hosts})")
            elif settings_changed and not labelled:
                text += "; this run uses the settings in force at the first tool run, as pre-registered"
            study.add("config", WARNING, "", text)
    if not quiet:
        return None
    if at_tool[0] == u_index:
        return (f"the configuration used equals {CONFIG_FILE} as recorded at ledger line {u_index + 2}, in force at "
                "the first tool run and when the seal first opened")
    return (f"the configuration used equals {CONFIG_FILE} as in force when the seal first opened (ledger line "
            f"{u_index + 2}) and at the first tool run (ledger line {at_tool[0] + 2})")


def _reverted(current: StudyConfig, earlier: StudyConfig, used: StudyConfig) -> StudyConfig:
    """`current` with every setting (hosts aside) that `used` has at its value
    in `earlier` set to that value, compared as _config_differences compares
    it: putting a setting back to its pre-registered value is no change."""
    changes: Dict[str, object] = {}
    for item in dataclasses.fields(StudyConfig):
        if item.name == "hosts":
            continue
        value = getattr(used, item.name)
        if not _config_differences(earlier, dataclasses.replace(earlier, **{item.name: value})):
            changes[item.name] = getattr(earlier, item.name)
    return dataclasses.replace(current, **changes)


def _fraction_text(value: Fraction) -> str:
    """A threshold as study.yaml would write it: 0.80, 0.75, 0.801, or 2/3."""
    for places in range(2, 7):
        if (value * 10 ** places).denominator == 1:
            return f"{float(value):.{places}f}"
    return f"{value.numerator}/{value.denominator}"


def _yaml_text(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(str(v) for v in value) + "]"
    return str(value)


# StudyConfig fields _config_differences names one by one; any other field is compared generically.
_COMPARED_FIELDS = frozenset({
    "hosts", "threshold", "primary_methodology", "secondary_methodologies", "manual_max_level",
    "input_driven_checks", "input_driven_properties", "bootstrap_iterations", "bootstrap_seed",
    "bootstrap_exact_limit", "weighted_kappa", "synthetic", "manual_level_rule", "tool_side_rule", "overall_rule",
})


def _config_differences(reference: StudyConfig, used: StudyConfig) -> List[str]:
    """Every setting in which `used` differs from `reference`, one item per
    difference, for example "threshold 0.80 -> 0.60" or "hosts: H3 left
    out". Hosts and the input-driven lists compare as sets; manual_max_level
    compares the cap in force for each methodology (a cap left at its default
    equals the same cap written out)."""
    items: List[str] = []
    for key, gone, new in (("hosts", "left out", "added"),
                           ("input_driven_checks", "removed", "added"),
                           ("input_driven_properties", "removed", "added")):
        before, after = list(getattr(reference, key)), list(getattr(used, key))
        missing = [value for value in before if value not in set(after)]
        extra = [value for value in after if value not in set(before)]
        if missing:
            items.append(f"{key}: {', '.join(missing)} {gone}")
        if extra:
            items.append(f"{key}: {', '.join(extra)} {new}")
    if reference.threshold != used.threshold:
        items.append(f"threshold {_fraction_text(reference.threshold)} -> {_fraction_text(used.threshold)}")
    for key in ("primary_methodology", "secondary_methodologies"):
        before, after = getattr(reference, key), getattr(used, key)
        if before != after:
            items.append(f"{key} {_yaml_text(before)} -> {_yaml_text(after)}")
    named = sorted(set(reference.methodologies) | set(used.methodologies) | set(reference.manual_max_level)
                   | set(used.manual_max_level))
    for methodology in named:
        before, after = reference.manual_max(methodology), used.manual_max(methodology)
        if before != after:
            items.append(f"manual_max_level {methodology} {before} -> {after}")
    for key, attr in (("bootstrap.iterations", "bootstrap_iterations"), ("bootstrap.seed", "bootstrap_seed"),
                      ("bootstrap.exact_limit", "bootstrap_exact_limit"), ("weighted_kappa", "weighted_kappa"),
                      ("synthetic", "synthetic"), ("level_rule.manual", "manual_level_rule"),
                      ("level_rule.tool_side", "tool_side_rule"), ("level_rule.overall", "overall_rule")):
        before, after = getattr(reference, attr), getattr(used, attr)
        if before != after:
            items.append(f"{key} {_yaml_text(before)} -> {_yaml_text(after)}")
    for item in dataclasses.fields(StudyConfig):
        if item.name not in _COMPARED_FIELDS and getattr(reference, item.name) != getattr(used, item.name):
            items.append(f"{item.name} {getattr(reference, item.name)!r} -> {getattr(used, item.name)!r}")
    return items


def _check_forced_unseal(study: Study) -> None:
    """Protocol section 7 issues the register sheets only after unsealing:
    every STUDY row that register-sheet wrote for --force-before-unseal is
    CRITICAL, with its time and the reason given."""
    for item in study.row_states:
        row = item.row
        note = row.note or ""
        if study_ledger.is_study_code(row.host_code) and note.startswith(study_ledger.FORCE_NOTE_PREFIX):
            reason = note[len(study_ledger.FORCE_NOTE_PREFIX):].strip() or "(no reason given)"
            study.add("seal", CRITICAL, "",
                      f"register sheets were generated before every worksheet was hashed (--force-before-unseal, "
                      f"ledger line {item.index + 2}, recorded {row.recorded_at_utc}); reason given: {reason}")
    study.checked["seal"] = "no register sheets forced before every worksheet was hashed"


def _check_ledger(study: Study) -> None:
    """Order of each analysed host's worksheet hash against its tool runs,
    its sealed files and the first seal opening, worksheets recorded with
    --force (_check_forced_worksheets), then every ledger row's own state
    (_check_row_states). Worksheet rows are matched with
    ledger.worksheet_rows (the path must be DIR/worksheets/<H>-worksheet.csv),
    as the seal matches them."""
    if not study.ledger_present:
        for key in ("ledger_row", "ledger_hash", "ledger_order"):
            study.add(key, WARNING, "", "not run: no ledger.csv in the study folder")
        return
    _check_hashed_before_opening(study)
    _check_forced_worksheets(study)
    for host in study.config.hosts:
        sheet = study.worksheets.get(host)
        if sheet is None:
            continue
        rows = study_ledger.worksheet_rows(study.ledger_path, study.ledger, study.study_dir, host)
        if not rows:
            study.add("ledger_row", WARNING, host, f"no ledger row of kind worksheet for {study.rel(sheet.path)}")
            continue
        times = []
        for row in rows:
            try:
                times.append(parse_utc_timestamp(row.recorded_at_utc))
            except StudyError:
                pass            # reported once, as OUT OF ORDER, by _check_row_states
        if not times:
            continue
        hashed_at = min(times)
        for methodology in study.config.methodologies:
            output = study.outputs.get(host, {}).get(methodology)
            if output is not None:
                _check_run_order(study, host, output, hashed_at)
        _check_sealed_files(study, host, hashed_at)
    _check_row_states(study)
    study.checked["ledger_row"] = "every worksheet has a ledger row"
    study.checked["ledger_hash"] = ("every hashed worksheet, tool output, facts file and register sheet matches its "
                                    "recorded sha256")
    study.checked["ledger_order"] = ("every worksheet was hashed before its tool runs and before the seal first "
                                     "opened; every ledger row in time order")
    study.checked["ledger_rows"] = "every other ledger row matches its file (or was superseded in time)"


def _check_hashed_before_opening(study: Study) -> None:
    """CRITICAL for each analysed host whose first worksheet row comes after
    the first seal opening (O) in the ledger: tool results were available
    before its blind pass ended."""
    opened = _first_seal_opening(study)
    if opened is None:
        return
    for host in study.config.hosts:
        first = _first_worksheet_row(study, host)
        if first is not None and first[0] > opened[0]:
            study.add("ledger_order", CRITICAL, host,
                      f"{host}'s worksheet was hashed at {first[1].recorded_at_utc}, after the seal was first opened "
                      f"at {opened[1].recorded_at_utc} (ledger line {opened[0] + 2}): its blind pass may have seen "
                      "tool results")


_CRITICAL_ITEM = re.compile(r"(?:^|; )(?:[^;]*?: )?CRITICAL ")


def _check_forced_worksheets(study: Study) -> None:
    """Every worksheet row of an analysed host (kind worksheet, by host code
    or by its worksheet path) whose note holds LINT_NOTE_PREFIX, which
    `ledger record --kind worksheet --force` writes (after the --note text,
    when one was given): a 'worksheet' WARNING quoting the findings, or
    CRITICAL when one of them is CRITICAL."""
    ledger = study.ledger_path
    for host in study.config.hosts:
        target = study_ledger.file_key(study.worksheet_path(host))
        for index, row in enumerate(study.ledger):
            if study_ledger.row_kind(row) != study_ledger.WORKSHEET_KIND:
                continue
            if (row.host_code or "").strip() != host and study_ledger.path_key(ledger, row.path) != target:
                continue
            note = row.note or ""
            at = note.find(LINT_NOTE_PREFIX)
            if at < 0:
                continue
            listed = note[at + len(LINT_NOTE_PREFIX):].strip() or "(no finding listed)"
            level = CRITICAL if _CRITICAL_ITEM.search(listed) else WARNING
            where = study.rel(resolve_ledger_path(ledger, row.path)) if row.path.strip() else "(no path)"
            study.add("worksheet", level, host,
                      f"{where} was recorded with --force despite lint findings (ledger line {index + 2}, "
                      f"{row.recorded_at_utc}): {listed}")


def _sealed_keys(study: Study) -> Set[str]:
    """file_key of every analysed host's worksheet, tool outputs, facts file
    and register sheets: a row for one of them is frozen whatever kind it
    was given."""
    paths: List[Path] = []
    for host in study.config.hosts:
        paths.append(study.worksheet_path(host))
        paths.append(study.facts_path(host))
        paths.extend(study.output_path(host, m) for m in study.config.methodologies)
        paths.append(study.review_path(host))
        paths.append(study.gaps_path(host))
    return {study_ledger.file_key(path) for path in paths}


def _check_row_states(study: Study) -> None:
    """Every ledger row as `ledger verify` sees it (ledger.row_states):

    - a CHANGED or MISSING row of a frozen kind (worksheet, tool-output,
      facts, register-review, missed-gaps), or of an analysed host's
      worksheet, tool output, facts file or register sheet under any kind:
      CRITICAL (ledger_hash);
    - a CHANGED or MISSING row of another kind (input, list-checks,
      protocol, other): WARNING (ledger_rows);
    - a row OUT OF ORDER (dated earlier than a row above it, or not a
      timestamp): CRITICAL (ledger_order);
    - SUPERSEDED rows are information only: listed in section 2 with every
      other row that is not OK."""
    ledger = study.ledger_path
    sealed = _sealed_keys(study)
    latest: Optional[dt.datetime] = None
    for item in study.row_states:
        row = item.row
        kind = study_ledger.row_kind(row) or "no kind"
        line = item.index + 2
        host = "" if study_ledger.is_study_code(row.host_code) else row.host_code
        path = resolve_ledger_path(ledger, row.path) if row.path.strip() else None
        where = study.rel(path) if path is not None else "(no path)"
        frozen = kind in study_ledger.FROZEN_KINDS or (path is not None and study_ledger.file_key(path) in sealed)
        key, level = ("ledger_hash", CRITICAL) if frozen else ("ledger_rows", WARNING)
        if item.state == study_ledger.CHANGED:
            try:
                now = f"file now {sha256_file(path)[:12]}..." if path is not None else "file now unreadable"
            except OSError:
                now = "file now unreadable"
            study.add(key, level, host,
                      f"{where} changed after it was hashed ({kind}, ledger line {line}): ledger {row.sha256[:12]}... "
                      f"recorded {row.recorded_at_utc}, {now}")
        elif item.state == study_ledger.MISSING:
            study.add(key, level, host,
                      f"{where} is missing or unreadable ({kind}, ledger line {line}); it was hashed at "
                      f"{row.recorded_at_utc}")
        moment = _optional_timestamp(row.recorded_at_utc)
        if item.out_of_order:
            if moment is None:
                why = f"recorded_at_utc {row.recorded_at_utc!r} is not a timestamp"
            else:
                why = f"recorded {_iso(moment)}, earlier than {_iso(latest) if latest else '?'} above it"
            study.add("ledger_order", CRITICAL, host, f"ledger line {line} ({where}, {kind}) is out of order: {why}")
        if moment is not None and (latest is None or moment > latest):
            latest = moment


def _optional_timestamp(raw: object) -> Optional[dt.datetime]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return parse_utc_timestamp(raw)
    except StudyError:
        return None


def _ledger_not_ok(study: Study) -> List[Dict[str, object]]:
    """Every ledger row that is not OK or is out of order, for section 2 and
    summary.json (SUPERSEDED rows included, as information)."""
    rows = []
    for item in study.row_states:
        if item.state == study_ledger.OK and not item.out_of_order:
            continue
        row = item.row
        path = resolve_ledger_path(study.ledger_path, row.path) if row.path.strip() else None
        rows.append({"line": item.index + 2, "host_code": row.host_code, "kind": row.kind,
                     "path": study.rel(path) if path is not None else "", "state": item.state,
                     "out_of_order": item.out_of_order, "recorded_at_utc": row.recorded_at_utc})
    return rows


def _check_sealed_files(study: Study, host: str, hashed_at: dt.datetime) -> None:
    """When the ledger also records a host's tool outputs or facts file, it
    must have been recorded after the worksheet was hashed (a row in the
    same second is not proof of order). Whether the file is still the one
    recorded is checked with every other row (_check_row_states)."""
    paths = [study.output_path(host, m) for m in study.config.methodologies] + [study.facts_path(host)]
    for path in paths:
        target = study_ledger.file_key(path)
        rows = [row for row in study.ledger if study_ledger.row_kind(row) != study_ledger.WORKSHEET_KIND
                and study_ledger.path_key(study.ledger_path, row.path) == target]
        for row in rows:
            when = _optional_timestamp(row.recorded_at_utc)
            if when is None:
                continue        # reported once, as OUT OF ORDER, by _check_row_states
            if when < hashed_at:
                study.add("ledger_order", CRITICAL, host,
                          f"{study.rel(path)} was recorded in the ledger at {_iso(when)}, before the worksheet "
                          f"was hashed at {_iso(hashed_at)}")
            elif when == hashed_at:
                study.add("ledger_order", CRITICAL, host,
                          f"{study.rel(path)} was recorded in the ledger at {_iso(when)}, not after the worksheet "
                          f"hash (same second)")


def _check_run_order(study: Study, host: str, output: ToolOutput, hashed_at: dt.datetime) -> None:
    name = output.path.name
    prov = _provenance(output)
    if prov is None:
        study.add("ledger_order", WARNING, host, f"{name}: no provenance, so the run order cannot be verified")
        return
    stamp = _iso(hashed_at)
    for key, what in (("run_at_utc", "tool run"), ("facts_collected_at_utc", "facts collected")):
        raw = prov.get(key)
        if raw is None:
            if key == "run_at_utc":
                study.add("ledger_order", WARNING, host, f"{name}: no run_at_utc, so the run order cannot be verified")
            continue
        try:
            when = parse_utc_timestamp(str(raw))
        except StudyError:
            study.add("ledger_order", WARNING, host, f"{name}: {key} {raw!r} is not a timestamp")
            continue
        # Timestamps are whole seconds, so a tie is no proof of order: CRITICAL too, worded as a tie.
        if when < hashed_at:
            study.add("ledger_order", CRITICAL, host,
                      f"{what} before the worksheet was hashed: {name} {key} {_iso(when)}, worksheet hashed {stamp}")
        elif when == hashed_at:
            study.add("ledger_order", CRITICAL, host,
                      f"{what} not after the worksheet hash (same second): {name} {key} {_iso(when)}, worksheet "
                      f"hashed {stamp}")


def _iso(value: dt.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ comparisons
def _analyse(study: Study) -> Analysis:
    levels = _compare_levels(study)
    checks = _compare_checks(study)
    register = _collect_register(study)
    return Analysis(
        levels=levels,
        checks=checks,
        register=register,
        h1=_h1_rows(study, levels),
        pooled=_pooled_rows(study, levels),
        check_agreement=_check_agreement_rows(study, checks),
        level_confusion={m: _level_confusion(study, levels, m) for m in study.config.methodologies},
        verdict_confusion=_verdict_confusion(checks),
        chance=_chance_rows(study),
        l5=_l5_rows(study, levels),
        kappa=_kappa_rows(study, levels) if study.config.weighted_kappa else None,
    )


def _manual_rule_levels(sheet: Worksheet, methodology: str, declared: Optional[StudyConfig]) -> Dict[str, LevelValue]:
    """The levels the worksheet's own verdicts give under the declared manual
    rule (derive_worksheet_levels), or {} when no manual rule is declared or
    they cannot be derived (the 'levels' findings say why)."""
    if declared is None:
        return {}
    try:
        return derive_worksheet_levels(sheet, methodology, declared.manual_level_rule, declared.overall_rule, declared)
    except (ValueError, StudyError):
        return {}


def _compare_levels(study: Study) -> List[LevelComparison]:
    rows: List[LevelComparison] = []
    config = study.config
    declared = _declared_manual_rule(study)
    for host in config.hosts:
        sheet = study.worksheets.get(host)
        if sheet is None:
            continue
        drop = sheet.unassessed
        for methodology in config.methodologies:
            output = study.outputs.get(host, {}).get(methodology)
            if output is None:
                study.note(host, f"left out of the {methodology} level comparisons (no tool output)")
                continue
            reported = output.levels()
            used = _tool_levels_used(output, methodology, drop, config)
            # What the tool side gives without the drop, to note when the drop changed a level.
            undropped = (reported if config.tool_side_rule == LEVEL_RULE_TOOL_CUTOFFS
                         else _tool_levels_used(output, methodology, (), config))
            from_verdicts = _worksheet_rule_levels(sheet, output, methodology, config)
            by_rule = _manual_rule_levels(sheet, methodology, declared)
            manual = sheet.levels.get(methodology, {})
            raw = sheet.raw_levels.get(methodology, {})
            for scope in LEVEL_SCOPES:
                rows.append(_level_comparison(
                    host, methodology, scope, reported, used, manual.get(scope), raw.get(scope, ""),
                    top=config.tool_max_level(methodology), cap=config.manual_max(methodology), dropped=drop,
                    undropped=undropped, from_verdicts=from_verdicts.get(scope),
                    off_rule=scope in by_rule and _off_rule(manual.get(scope), by_rule[scope]),
                ))
        if drop:
            study.note(host, f"UNASSESSED check(s) left out on both sides: {', '.join(drop)}")
    return rows


def _level_comparison(host: str, methodology: str, scope: str, reported: Dict[str, Optional[int]],
                      used: Dict[str, Optional[int]], manual: LevelValue, raw: str, top: int, cap: int,
                      dropped: Sequence[str], undropped: Optional[Dict[str, Optional[int]]] = None,
                      from_verdicts: LevelValue = None, off_rule: bool = False) -> LevelComparison:
    """One comparison. `undropped` holds the tool-side levels without the
    UNASSESSED drop (default: the reported levels) and `from_verdicts` the
    level the worksheet's own verdicts give under the tool-side rule.
    `off_rule` says that the typed manual level differs from the level the
    verdicts give under the declared manual rule: rule_only and l5_rule_only
    are then left blank (not classified), with a note; every other column is
    unchanged."""
    known = scope in reported
    row = LevelComparison(host=host, methodology=methodology, scope=scope,
                          tool_reported=reported.get(scope), tool_reported_known=known,
                          tool_used=used[scope], manual=manual, counted=False)
    notes = []
    reference = reported if undropped is None else undropped
    if dropped and known and row.tool_used != reference.get(scope):
        notes.append(f"tool level recomputed without UNASSESSED {', '.join(dropped)}")
    tool_known = isinstance(row.tool_used, int)
    manual_known = isinstance(manual, int) and not isinstance(manual, bool)
    if scope == OVERALL_EXCL and manual is None and not raw:
        # Optional secondary scope: a blank cell skips it (an unreadable entry does not).
        notes.append("no manual level entered; comparison skipped for this host")
    elif tool_known and manual_known:
        row.counted = True
        row.diff = row.tool_used - manual
        row.exact = row.diff == 0
        row.within_one = abs(row.diff) <= 1
        # A typed level that does not follow the declared rule is not a Level 5 case either.
        row.l5_rule_only = None if off_rule else (row.tool_used == top and manual == cap and cap < top)
        if row.l5_rule_only:
            notes.append(f"Level 5 rule only: tool at top level {top}, manual at cap {cap}")
    elif not tool_known and not manual_known:
        notes.append(f"tool level unassessed and {_manual_state(manual, raw)}; not comparable (left out of n)")
    else:
        row.counted = True
        row.exact = False
        row.within_one = False
        side = "tool level unassessed" if not tool_known else _manual_state(manual, raw)
        notes.append(f"{side}; counted as a disagreement")
    if row.counted and row.exact is False and not off_rule:
        row.rule_only = _rule_only(row.tool_used, manual, from_verdicts)
        if row.rule_only is None and manual is not None:
            notes.append("rule_only not decided: a verdict of this scope is missing or unreadable")
    if off_rule:
        notes.append(OFF_RULE_NOTE)
    row.note = "; ".join(notes)
    return row


def _rule_only(tool_used: Optional[int], manual: LevelValue, from_verdicts: LevelValue) -> Optional[bool]:
    """On an exact mismatch: does the level the worksheet's own verdicts give
    under the tool-side rule equal the tool level used? None when that cannot
    be decided: a verdict of the scope is blank or unreadable, or the manual
    level itself is (then nothing was derived from the verdicts to compare)."""
    if manual is None or from_verdicts == MANUAL_MISSING:
        return None
    return from_verdicts == tool_used


def _manual_state(manual: LevelValue, raw: str) -> str:
    if manual == UNASSESSED:
        return "manual UNASSESSED"
    if raw:
        return f"manual level unrecognized ({raw!r})"
    return "manual level missing"


def _compare_checks(study: Study) -> List[CheckComparison]:
    rows: List[CheckComparison] = []
    input_checks = set(study.config.input_driven_checks)
    for host in study.config.hosts:
        sheet = study.worksheets.get(host)
        output = study.reference(host)
        if sheet is None or output is None:
            continue
        tool = _enabled_checks(output)
        statuses = {c.get("check_id"): c.get("status") for c in tool}
        properties = {c.get("check_id"): c.get("property_key") for c in tool}
        order = [c.get("check_id") for c in tool] + [c for c in sheet.check_ids if c not in statuses]
        for check_id in order:
            group = "input" if check_id in input_checks else "device"
            row = CheckComparison(
                host=host, check_id=check_id,
                property_key=properties.get(check_id) or sheet.check_properties.get(check_id, ""),
                group=group, tool_status=statuses.get(check_id),
                manual_verdict=sheet.verdicts.get(check_id), compared=False, agree=None,
            )
            if check_id not in sheet.verdicts:
                row.note = "not on the worksheet"
            elif check_id not in statuses:
                row.note = "not in the tool output"
            elif row.manual_verdict == UNASSESSED:
                reason = sheet.reasons.get(check_id) or "no reason given"
                row.note = f"UNASSESSED ({reason}); left out on both sides"
            else:
                row.compared = True
                row.agree = row.manual_verdict is not None and row.manual_verdict == row.tool_status
                if row.manual_verdict is None:
                    raw = sheet.raw_verdicts.get(check_id, "")
                    row.note = (f"manual verdict unrecognized ({raw!r})" if raw else "manual verdict missing") \
                        + "; counted as a disagreement"
            rows.append(row)
    return rows


# ------------------------------------------------------------------ register (H2)
def _register_available(study: Study) -> bool:
    return any(study.review_path(host).exists() for host in study.config.hosts)


def _collect_register(study: Study) -> Optional[List[RegisterHost]]:
    """Register-review counts per host, or None when no review sheet exists
    yet (H2 not yet available)."""
    if not _register_available(study):
        study.checked["register"] = "no register review sheets yet (H2 not yet available)"
        return None
    result = [_register_host(study, host) for host in study.config.hosts]
    study.checked["register"] = "every register entry has one review row and every row an entry"
    return result


def _register_host(study: Study, host: str) -> RegisterHost:
    counts = RegisterHost(host=host)
    review_path, gaps_path = study.review_path(host), study.gaps_path(host)
    if gaps_path.exists():
        try:
            gaps = read_csv(gaps_path, ("description",))
        except StudyError as exc:
            study.add("register", CRITICAL, host, f"cannot read the missed-gaps sheet: {study.clean(str(exc))}")
        else:
            counts.missed_gaps = sum(1 for row in gaps if row.get("description", "").strip())
    output = study.reference(host)
    if output is None:
        if review_path.exists():
            study.add("register", CRITICAL, host, f"{study.rel(review_path)} has no tool output to match")
        return counts
    entries = output.risk_register
    if entries is None:
        study.add("register", CRITICAL, host, f"{output.path.name} has no risk_register (run with --risk-register)")
        return counts
    entry_ids = [str(e.get("check_id")) for e in entries]
    counts.entries = len(entries)
    for methodology, other in study.outputs.get(host, {}).items():
        if other is output or other.risk_register is None:
            continue
        other_ids = [str(e.get("check_id")) for e in other.risk_register]
        if sorted(other_ids) != sorted(entry_ids):
            study.add("register", CRITICAL, host,
                      f"{other.path.name} register lists different checks than {output.path.name}: "
                      + _set_difference(set(other_ids), set(entry_ids), other.path.name, output.path.name))
    if not review_path.exists():
        counts.not_judged = len(entries)
        if entries:
            study.add("register", CRITICAL, host,
                      f"no register review sheet: {len(entries)} of {len(entries)} {_NOT_JUDGED_TEXT}")
        return counts
    if not gaps_path.exists():
        study.add("register", WARNING, host, f"no missed-gaps sheet ({study.rel(gaps_path)}); counted as 0")
    try:
        rows = read_csv(review_path, ("check_id", "accurate", "actionable", "prioritized"))
    except StudyError as exc:
        study.add("register", CRITICAL, host, f"cannot read the register review sheet: {study.clean(str(exc))}")
        counts.not_judged = len(entries)
        return counts
    reviews = _review_rows_by_check(study, host, rows, set(entry_ids))
    for entry_id in entry_ids:
        _count_review(study, host, counts, entry_id, reviews.get(entry_id))
    if counts.not_judged:
        study.add("register", CRITICAL, host, f"{counts.not_judged} of {counts.entries} {_NOT_JUDGED_TEXT}")
    return counts


# H2: an entry is judged when accurate and actionable are both answered, or
# when either is N (it cannot count as k whatever the other answer is).
_NOT_JUDGED_TEXT = ("entries not judged; every entry must be judged before the final analysis (judged = accurate "
                    "and actionable both answered, or either answered N); not-judged entries are left out of n")
_UNREADABLE = "unreadable"


def _review_rows_by_check(study: Study, host: str, rows: List[Dict[str, str]],
                          entry_ids: Set[str]) -> Dict[str, Dict[str, str]]:
    reviews: Dict[str, Dict[str, str]] = {}
    for row in rows:
        check_id = row.get("check_id", "").strip()
        code = row.get("host_code", "").strip()
        if code and code != host:
            study.add("register", CRITICAL, host, f"review row for {check_id or '?'} has host_code {code!r}")
        if not check_id:
            study.add("register", CRITICAL, host, "review row without a check_id")
        elif check_id in reviews:
            study.add("register", CRITICAL, host, f"more than one review row for {check_id}; the first is used")
        elif check_id not in entry_ids:
            study.add("register", CRITICAL, host, f"review row for {check_id} has no register entry")
        else:
            reviews[check_id] = row
    return reviews


def _count_review(study: Study, host: str, counts: RegisterHost, entry_id: str,
                  row: Optional[Dict[str, str]]) -> None:
    if row is None:
        study.add("register", CRITICAL, host, f"register entry {entry_id} has no review row")
        counts.not_judged += 1
        return
    try:
        prioritized = normalize_yes_no(row.get("prioritized"), allow_unsure=True)
    except StudyError as exc:
        study.add("register", CRITICAL, host, f"{entry_id} prioritized: {exc}")
        prioritized = None
    if prioritized is not None:
        counts.prioritized[prioritized] += 1
    answers: Dict[str, Optional[str]] = {}
    for column in ("accurate", "actionable"):
        try:
            answers[column] = normalize_yes_no(row.get(column))
        except StudyError as exc:
            study.add("register", CRITICAL, host, f"{entry_id} {column}: {exc}")
            answers[column] = _UNREADABLE
    accurate, actionable = answers["accurate"], answers["actionable"]
    if "N" not in (accurate, actionable) and not (accurate == "Y" and actionable == "Y"):
        counts.not_judged += 1      # Y + blank, blank + blank, or an unreadable answer without an N
        return
    counts.judged += 1
    counts.accurate_y += accurate == "Y"
    counts.actionable_y += actionable == "Y"
    counts.k += accurate == "Y" and actionable == "Y"


# ------------------------------------------------------------------ aggregates
def _rate_record(k: int, n: int, threshold: Optional[Fraction] = None) -> Dict[str, object]:
    interval = stats.wilson_interval(k, n)
    record: Dict[str, object] = {
        "k": k, "n": n, "rate": stats.proportion(k, n),
        "wilson_low": interval[0] if interval else None,
        "wilson_high": interval[1] if interval else None,
    }
    if threshold is not None:
        record["threshold"] = float(threshold)
        record["meets_threshold"] = stats.meets_threshold(k, n, threshold)
        record["needed"] = stats.minimum_successes(n, threshold)
    return record


def _host_bootstrap(clusters: Sequence[Tuple[int, int]], config: StudyConfig) -> Dict[str, object]:
    """stats.bootstrap_pooled over per-host (k, n) clusters, after leaving out
    hosts with n = 0: they hold no comparison, and keeping them would make
    the number of informative hosts in a resample random. Returns the
    boot_* fields of a record; boot_hosts is the number of hosts resampled."""
    informative = [(k, n) for k, n in clusters if n > 0]
    boot = stats.bootstrap_pooled(informative, config.bootstrap_iterations, config.bootstrap_seed,
                                  config.bootstrap_exact_limit)
    return {"boot_low": boot["low"], "boot_high": boot["high"], "boot_method": boot["method"],
            "boot_resamples": boot["resamples"], "boot_dropped": boot["dropped"], "boot_seed": boot["seed"],
            "boot_hosts": len(informative)}


def _kappa_note(pairs: Iterable[Tuple[object, object]]) -> str:
    """A note when either side of a kappa table uses a single category: then
    kappa is 0 (or undefined) by construction, whatever the agreement."""
    pairs = list(pairs)
    if not pairs:
        return ""
    sides = [name for name, labels in (("the tool side", {a for a, _ in pairs}),
                                       ("the manual side", {b for _, b in pairs})) if len(labels) == 1]
    if not sides:
        return ""
    return f"one category on {' and '.join(sides)}: kappa is 0 or undefined by construction"


def _select(levels: Sequence[LevelComparison], methodology: str, scopes: Iterable[str],
            host: Optional[str] = None) -> List[LevelComparison]:
    wanted = set(scopes)
    return [c for c in levels if c.methodology == methodology and c.scope in wanted and c.counted
            and (host is None or c.host == host)]


def _h1_rows(study: Study, levels: Sequence[LevelComparison]) -> List[Dict[str, object]]:
    rows = []
    for methodology in study.config.methodologies:
        for scope in LEVEL_SCOPES:
            compared = _select(levels, methodology, [scope])
            for measure in MEASURES:
                k = sum(1 for c in compared if getattr(c, measure))
                threshold = study.config.threshold if measure == "within_one" else None
                rows.append(dict({"methodology": methodology, "scope": scope, "measure": measure},
                                 **_rate_record(k, len(compared), threshold)))
    return rows


def _subset_scopes(study: Study, subset: str) -> List[str]:
    if subset == "all_properties":
        return list(PROPERTY_KEYS)
    excluded = set(study.config.input_driven_properties)
    return [p for p in PROPERTY_KEYS if p not in excluded]


def _hosts_with_levels(levels: Sequence[LevelComparison], methodology: str, hosts: Sequence[str]) -> List[str]:
    present = {c.host for c in levels if c.methodology == methodology}
    return [h for h in hosts if h in present]


def _pooled_rows(study: Study, levels: Sequence[LevelComparison]) -> List[Dict[str, object]]:
    config = study.config
    rows = []
    for methodology in config.methodologies:
        hosts = _hosts_with_levels(levels, methodology, config.hosts)
        for measure in MEASURES:
            for subset in SUBSETS:
                scopes = _subset_scopes(study, subset)
                clusters = []
                for host in hosts:
                    compared = _select(levels, methodology, scopes, host)
                    clusters.append((sum(1 for c in compared if getattr(c, measure)), len(compared)))
                k = sum(c[0] for c in clusters)
                n = sum(c[1] for c in clusters)
                record = {"methodology": methodology, "measure": measure, "subset": subset}
                record.update(_rate_record(k, n))
                record.update({"hosts": len(clusters), "clusters": [list(c) for c in clusters]})
                record.update(_host_bootstrap(clusters, config))
                rows.append(record)
    return rows


def _check_agreement_rows(study: Study, checks: Sequence[CheckComparison]) -> List[Dict[str, object]]:
    """Check-verdict agreement per group, with the protocol's Wilson interval
    and a host-cluster bootstrap interval as a secondary check."""
    rows = []
    for group in CHECK_GROUPS:
        compared = [c for c in checks if c.compared and (group == "all" or c.group == group)]
        k = sum(1 for c in compared if c.agree)
        record: Dict[str, object] = {"group": group, "checks": len({c.check_id for c in compared})}
        record.update(_rate_record(k, len(compared)))
        clusters = [(sum(1 for c in compared if c.host == host and c.agree),
                     sum(1 for c in compared if c.host == host)) for host in study.config.hosts]
        record["clusters"] = [list(c) for c in clusters]
        record.update(_host_bootstrap(clusters, study.config))
        pairs = [(c.tool_status, c.manual_verdict or MANUAL_MISSING) for c in compared]
        record["kappa"] = stats.cohen_kappa(pairs)
        record["kappa_note"] = _kappa_note(pairs)
        rows.append(record)
    return rows


def _level_label(value: LevelValue) -> str:
    return str(value) if isinstance(value, int) and not isinstance(value, bool) else TOOL_UNASSESSED


def _manual_label(value: LevelValue) -> str:
    """A manual level as a confusion-matrix label: the level, unassessed
    (UNASSESSED entered) or missing (blank or unreadable)."""
    if value is None:
        return MANUAL_MISSING
    return _level_label(value)


def _level_confusion(study: Study, levels: Sequence[LevelComparison], methodology: str) -> List[Dict[str, object]]:
    """Tool level by manual level over every host x property row, including
    comparisons left out of n (unassessed on both sides)."""
    top = study.config.tool_max_level(methodology)
    cap = study.config.manual_max(methodology)
    tool_labels = [str(i) for i in range(1, top + 1)] + [TOOL_UNASSESSED]
    manual_labels = [str(i) for i in range(1, cap + 1)] + [TOOL_UNASSESSED, MANUAL_MISSING]
    counts: Counter = Counter()
    for c in levels:
        if c.methodology == methodology and c.scope in PROPERTY_KEYS:
            counts[(_level_label(c.tool_used), _manual_label(c.manual))] += 1
    return [dict({"tool_level": t}, **{f"manual_{m}": counts[(t, m)] for m in manual_labels}) for t in tool_labels]


def _confusion_level_columns(study: Study, methodology: str) -> Tuple[str, ...]:
    cap = study.config.manual_max(methodology)
    return (("tool_level",) + tuple(f"manual_{i}" for i in range(1, cap + 1))
            + (f"manual_{TOOL_UNASSESSED}", f"manual_{MANUAL_MISSING}"))


def _verdict_confusion(checks: Sequence[CheckComparison]) -> List[Dict[str, object]]:
    counts: Counter = Counter()
    for c in checks:
        if c.compared:
            counts[(c.tool_status, c.manual_verdict or MANUAL_MISSING)] += 1
    statuses = list(TOOL_STATUSES) + sorted({str(c.tool_status) for c in checks
                                             if c.compared and c.tool_status not in TOOL_STATUSES})
    manual = [col[len("manual_"):] for col in CONFUSION_VERDICT_COLUMNS[1:]]
    return [dict({"tool_status": s}, **{f"manual_{m}": counts[(s, m)] for m in manual}) for s in statuses]


def _chance_rows(study: Study) -> List[Dict[str, object]]:
    rows = []
    for methodology in study.config.methodologies:
        top = study.config.tool_max_level(methodology)
        cap = study.config.manual_max(methodology)
        within = stats.uniform_chance(top, cap, within=1)
        exact = stats.uniform_chance(top, cap, within=0)
        rows.append({"methodology": methodology, "tool_levels": top, "manual_levels": cap,
                     "within_one": float(within), "within_one_fraction": f"{within.numerator}/{within.denominator}",
                     "exact": float(exact), "exact_fraction": f"{exact.numerator}/{exact.denominator}"})
    return rows


def _l5_applies(study: Study, methodology: str) -> bool:
    """The Level 5 rule can cause a mismatch only when the tool's top level
    is above the manual cap."""
    return study.config.manual_max(methodology) < study.config.tool_max_level(methodology)


def _l5_rows(study: Study, levels: Sequence[LevelComparison]) -> List[Dict[str, object]]:
    """Per scope: exact mismatches, those caused only by the Level 5 rule
    (l5_rule_only, unchanged) and those caused by how the levels were
    derived at all (rule_only; rule_only_blank = mismatches not classified)."""
    rows = []
    for methodology in study.config.methodologies:
        applies = _l5_applies(study, methodology)
        for scope in LEVEL_SCOPES:
            compared = _select(levels, methodology, [scope])
            mismatches = [c for c in compared if not c.exact]
            rows.append({"methodology": methodology, "scope": scope, "comparisons": len(compared),
                         "exact_mismatches": len(mismatches),
                         "l5_rule_only": sum(1 for c in compared if c.l5_rule_only),
                         "l5_rule_applies": applies,
                         "rule_only": sum(1 for c in mismatches if c.rule_only),
                         "rule_only_blank": sum(1 for c in mismatches if c.rule_only is None)})
    return rows


def _kappa_rows(study: Study, levels: Sequence[LevelComparison]) -> List[Dict[str, object]]:
    rows = []
    for methodology in study.config.methodologies:
        top = max(study.config.tool_max_level(methodology), study.config.manual_max(methodology))
        categories = list(range(1, top + 1))
        for label, scopes in (("pooled_all_properties", _subset_scopes(study, "all_properties")),
                              ("pooled_excl_input_driven", _subset_scopes(study, "excl_input_driven")),
                              (OVERALL, [OVERALL])):
            pairs = [(c.tool_used, c.manual) for c in _select(levels, methodology, scopes)
                     if isinstance(c.tool_used, int) and isinstance(c.manual, int)]
            rows.append({"methodology": methodology, "subset": label, "pairs": len(pairs), "categories": top,
                         "linear_weighted_kappa": stats.linear_weighted_kappa(pairs, categories),
                         "kappa_note": _kappa_note(pairs)})
    return rows


def _register_records(study: Study, register: Sequence[RegisterHost]) -> List[Dict[str, object]]:
    """register_h2 rows: one per host (descriptive) plus TOTAL (the H2 test),
    which also carries a host-cluster bootstrap interval (secondary)."""
    rows = []
    total = RegisterHost(host="TOTAL")
    clusters = []
    for counts in register:
        rows.append(_register_record(counts, None))
        for name in ("entries", "judged", "not_judged", "accurate_y", "actionable_y", "k", "missed_gaps"):
            setattr(total, name, getattr(total, name) + getattr(counts, name))
        total.prioritized.update(counts.prioritized)
        clusters.append((counts.k, counts.judged))
    record = _register_record(total, study.config.threshold)
    record["clusters"] = [list(c) for c in clusters]
    record.update(_host_bootstrap(clusters, study.config))
    rows.append(record)
    return rows


def _register_record(counts: RegisterHost, threshold: Optional[Fraction]) -> Dict[str, object]:
    """H2 counts of one host or the TOTAL, with the prioritization rate:
    k = entries answered Y, n = entries answered Y or N (UNSURE left out of
    n and counted separately), Wilson interval, no threshold."""
    record: Dict[str, object] = {"host": counts.host, "entries": counts.entries, "judged": counts.judged,
                                 "not_judged": counts.not_judged, "accurate_y": counts.accurate_y,
                                 "actionable_y": counts.actionable_y}
    record.update(_rate_record(counts.k, counts.judged, threshold))
    yes, no = counts.prioritized["Y"], counts.prioritized["N"]
    prioritization = _rate_record(yes, yes + no)
    record.update({"prioritized_y": yes, "prioritized_n": no, "prioritized_unsure": counts.prioritized["UNSURE"],
                   "prioritization_k": prioritization["k"], "prioritization_n": prioritization["n"],
                   "prioritization_rate": prioritization["rate"],
                   "prioritization_wilson_low": prioritization["wilson_low"],
                   "prioritization_wilson_high": prioritization["wilson_high"],
                   "missed_gaps": counts.missed_gaps})
    return record


# ------------------------------------------------------------------ formatting helpers
def _worst(findings: Iterable[Finding]) -> str:
    worst = OK
    for finding in findings:
        if _SEVERITY[finding.level] > _SEVERITY[worst]:
            worst = finding.level
    return worst


def _fmt(value: Optional[float]) -> str:
    return "" if value is None else f"{value:.4f}"


def _yes_no(value: Optional[bool]) -> str:
    return "" if value is None else ("yes" if value else "no")


def _tool_level_text(value: Optional[int]) -> str:
    return TOOL_UNASSESSED if value is None else str(value)


def _manual_level_text(value: LevelValue) -> str:
    return "" if value is None else str(value)


def _threshold_text(value: Fraction) -> str:
    return f"{float(value):.4f} (= {value.numerator}/{value.denominator})"


def _kn(record: Dict[str, object]) -> str:
    return f"{record['k']}/{record['n']}"


def _ci(record: Dict[str, object], low: str = "wilson_low", high: str = "wilson_high") -> str:
    if record.get(low) is None:
        return "n/a"
    return f"{record[low]:.4f} to {record[high]:.4f}"


def _md_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _md_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> List[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(_md_cell(cell) for cell in row) + " |")
    return lines + [""]


# ------------------------------------------------------------------ CSV rows
def _host_level_rows(analysis: Analysis) -> List[Dict[str, object]]:
    return [{
        "host": c.host, "methodology": c.methodology, "scope": c.scope,
        "tool_level_reported": _tool_level_text(c.tool_reported) if c.tool_reported_known else "",
        "tool_level_used": _tool_level_text(c.tool_used),
        "manual_level": _manual_level_text(c.manual),
        "diff": "" if c.diff is None else c.diff,
        "exact": _yes_no(c.exact), "within_one": _yes_no(c.within_one),
        "l5_rule_only": _yes_no(c.l5_rule_only), "rule_only": _yes_no(c.rule_only), "note": c.note,
    } for c in analysis.levels]


def _h1_csv_rows(analysis: Analysis) -> List[Dict[str, object]]:
    return [{
        "methodology": r["methodology"], "scope": r["scope"], "measure": r["measure"], "k": r["k"], "n": r["n"],
        "rate": _fmt(r["rate"]), "wilson_low": _fmt(r["wilson_low"]), "wilson_high": _fmt(r["wilson_high"]),
        "threshold": _fmt(r.get("threshold")), "meets_threshold": _yes_no(r.get("meets_threshold")),
    } for r in analysis.h1]


def _pooled_csv_rows(analysis: Analysis) -> List[Dict[str, object]]:
    return [{
        "methodology": r["methodology"], "measure": r["measure"], "subset": r["subset"], "k": r["k"], "n": r["n"],
        "rate": _fmt(r["rate"]), "wilson_low": _fmt(r["wilson_low"]), "wilson_high": _fmt(r["wilson_high"]),
        "boot_low": _fmt(r["boot_low"]), "boot_high": _fmt(r["boot_high"]),
        "boot_method": r["boot_method"], "boot_resamples": r["boot_resamples"], "boot_hosts": r["boot_hosts"],
    } for r in analysis.pooled]


def _check_verdict_rows(analysis: Analysis) -> List[Dict[str, object]]:
    return [{
        "host": c.host, "check_id": c.check_id, "property": c.property_key, "group": c.group,
        "tool_status": c.tool_status or "", "manual_verdict": c.manual_verdict or "",
        "compared": _yes_no(c.compared), "agree": _yes_no(c.agree), "note": c.note,
    } for c in analysis.checks]


def _check_agreement_csv_rows(analysis: Analysis) -> List[Dict[str, object]]:
    return [{
        "group": r["group"], "k": r["k"], "n": r["n"], "rate": _fmt(r["rate"]),
        "wilson_low": _fmt(r["wilson_low"]), "wilson_high": _fmt(r["wilson_high"]),
        "boot_low": _fmt(r["boot_low"]), "boot_high": _fmt(r["boot_high"]), "boot_method": r["boot_method"],
        "boot_resamples": r["boot_resamples"], "boot_hosts": r["boot_hosts"],
        "kappa": _fmt(r["kappa"]), "kappa_note": r["kappa_note"],
    } for r in analysis.check_agreement]


_REGISTER_FLOATS = ("rate", "wilson_low", "wilson_high", "boot_low", "boot_high", "prioritization_rate",
                    "prioritization_wilson_low", "prioritization_wilson_high")


def _register_csv_rows(records: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    """register_h2.csv rows; the boot_* columns are filled on the TOTAL row only."""
    rows = []
    for r in records:
        row = {key: r.get(key) for key in REGISTER_H2_COLUMNS}
        row.update({key: _fmt(r.get(key)) for key in _REGISTER_FLOATS})
        row["meets_threshold"] = _yes_no(r.get("meets_threshold"))
        rows.append(row)
    return rows


def _disagreement_rows(analysis: Analysis, hosts: Sequence[str]) -> List[Dict[str, object]]:
    """Every exact level mismatch and every verdict mismatch. root_cause,
    action and assessor_error_note stay blank: the researcher fills them.
    A manual value that is absent or unreadable is shown as "missing"."""
    rows = []
    for host in hosts:
        for c in analysis.levels:
            if c.host == host and c.counted and not c.exact:
                rows.append({
                    "kind": "level", "host": host, "methodology": c.methodology, "item": c.scope,
                    "tool_value": _tool_level_text(c.tool_used),
                    "manual_value": MANUAL_MISSING if c.manual is None else str(c.manual),
                    "diff": "" if c.diff is None else c.diff, "within_one": _yes_no(c.within_one),
                    "l5_rule_only": _yes_no(c.l5_rule_only), "rule_only": _yes_no(c.rule_only),
                    "root_cause": "", "action": "", "assessor_error_note": "",
                })
        for c in analysis.checks:
            if c.host == host and c.compared and not c.agree:
                rows.append({
                    "kind": "check", "host": host, "methodology": "", "item": c.check_id,
                    "tool_value": c.tool_status or "", "manual_value": c.manual_verdict or MANUAL_MISSING,
                    "diff": "", "within_one": "", "l5_rule_only": "", "rule_only": "",
                    "root_cause": "", "action": "", "assessor_error_note": "",
                })
    return rows


# ------------------------------------------------------------------ provenance of this analysis
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _git_commit(start: Path) -> Optional[str]:
    """The commit checked out in the repository that holds this code, read
    from .git without running git; None when it cannot be determined."""
    try:
        for folder in [start] + list(start.parents):
            dot_git = folder / ".git"
            if dot_git.is_dir():
                return _read_head(dot_git)
            if dot_git.is_file():
                text = dot_git.read_text(encoding="utf-8").strip()
                if not text.startswith("gitdir:"):
                    return None
                return _read_head((folder / text[len("gitdir:"):].strip()).resolve())
    except (OSError, ValueError):
        return None
    return None


def _read_head(git_dir: Path) -> Optional[str]:
    head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    if not head.startswith("ref:"):
        return head.lower() if _HEX40.match(head.lower()) else None
    ref = head[len("ref:"):].strip()
    bases = [git_dir]
    common = git_dir / "commondir"
    if common.is_file():
        bases.append((git_dir / common.read_text(encoding="utf-8").strip()).resolve())
    for base in bases:
        ref_file = base / ref
        if ref_file.is_file():
            value = ref_file.read_text(encoding="utf-8").strip().lower()
            return value if _HEX40.match(value) else None
    for base in bases:
        packed = base / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split(" ")
                if len(parts) == 2 and parts[1] == ref and _HEX40.match(parts[0].lower()):
                    return parts[0].lower()
    return None


def _analysis_tree_clean(package_dir: Path) -> Optional[bool]:
    """True when `git status --porcelain -- miccmac_study` lists nothing
    (untracked files count), False when it lists something, None when git
    cannot tell (not installed, not a repository, an error or a timeout).
    Runs with GIT_OPTIONAL_LOCKS=0, so it never writes to the repository."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=normal", "--", package_dir.name],
            cwd=str(package_dir.parent), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=60, check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return not result.stdout.strip()


# How _analysis_code hashes each file (named in summary.json and summary.md).
CODE_HASH_METHOD = "sha256 of each file with CRLF line endings read as LF (the bytes git commits)"


def code_sha256(path: Path) -> str:
    """sha256 of a source file with every CRLF read as LF: the same value on
    a Windows checkout (core.autocrlf) as on Linux, and equal to the sha256
    of the committed file (`git show <commit>:<path>`)."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _analysis_code() -> Dict[str, object]:
    """The analysis code that ran: its commit, whether miccmac_study is
    committed, and the code_sha256 of every .py file of the miccmac_study
    package (the seal, the ledger and the readers as well as the statistics),
    sorted by name; None for a file that cannot be read."""
    here = Path(__file__).resolve().parent
    files: Dict[str, Optional[str]] = {}
    for path in sorted(here.glob("*.py"), key=lambda p: p.name):
        try:
            files[f"miccmac_study/{path.name}"] = code_sha256(path)
        except OSError:
            files[f"miccmac_study/{path.name}"] = None
    return {"git_commit": _git_commit(here), "analysis_tree_clean": _analysis_tree_clean(here),
            "files_sha256": files, "files_sha256_method": CODE_HASH_METHOD}


# ------------------------------------------------------------------ summaries
def _config_echo(study: Study) -> Dict[str, object]:
    config = study.config
    try:
        config_sha = sha256_file(study.config_path)
    except OSError:
        config_sha = None
    echo: Dict[str, object] = {
        "path": study.rel(study.config_path),
        "sha256": config_sha,
        # The hosts analysed: the configuration's hosts minus those withdrawn in the ledger.
        "hosts": list(config.hosts),
        "config_hosts": list(study.config_hosts or config.hosts),
        "withdrawn": {host: {"recorded_at_utc": when, "reason": reason}
                      for host, (when, reason) in sorted(study.withdrawn.items())},
        "other_hosts": list(study.extra_hosts),
        "threshold": float(config.threshold),
        "threshold_fraction": f"{config.threshold.numerator}/{config.threshold.denominator}",
        "threshold_source": study.threshold_source,
        "config_threshold": float(study.config_threshold),
        "primary_methodology": config.primary_methodology,
        "secondary_methodologies": list(config.secondary_methodologies),
        "tool_max_level": {m: config.tool_max_level(m) for m in config.methodologies},
        "manual_max_level": {m: config.manual_max(m) for m in config.methodologies},
        "input_driven_checks": list(config.input_driven_checks),
        "input_driven_properties": list(config.input_driven_properties),
        "bootstrap": {"iterations": config.bootstrap_iterations, "seed": config.bootstrap_seed,
                      "exact_limit": config.bootstrap_exact_limit},
        "weighted_kappa": config.weighted_kappa,
        "synthetic": config.synthetic,
        # The level rule used in this run, and the study configuration's own values.
        "level_rule": config.level_rule,
        "level_rule_source": {"tool_side": study.tool_side_source, "overall": study.overall_source},
        "config_level_rule": {"manual": config.manual_level_rule, "tool_side": study.config_tool_side_rule,
                              "overall": study.config_overall_rule},
        # A sensitivity run: command-line overrides, a configuration that differs from the
        # pre-registered one (one item per difference, against config_reference), or a host
        # withdrawn after the seal first opened.
        "sensitivity_run": study.sensitivity_run,
        "overrides": list(study.overrides),
        "config_differences": list(study.config_differences),
        "config_reference": study.config_reference if study.config_differences else "",
        "post_hoc_exclusions": list(study.post_hoc_exclusions),
    }
    return echo


def _rule_value_text(value: Optional[str]) -> str:
    return value if value is not None else "not declared"


def _tool_side_text(study: Study, methodology: str) -> str:
    """How the tool levels used in the comparison were computed."""
    config = study.config
    if config.tool_side_rule == LEVEL_RULE_APPROVED:
        return (f"the tool's check statuses scored with the approved rule (pass-ratio buckets, levels "
                f"1-{APPROVED_MAX_LEVEL}; overall levels by {config.overall_rule}), not the levels the tool "
                f"reported; tool-side rule approved, from {study.tool_side_source}. tool_level_reported in "
                "host_levels.csv keeps the reported levels")
    return (f"miccmac's own scoring and the {methodology} cutoffs, as the tool reports them; tool-side rule "
            f"tool-cutoffs, from {study.tool_side_source}")


def _level_rules(study: Study) -> List[str]:
    """Distinct level_rule meta values with their hosts (worksheet order)."""
    rules: Dict[str, List[str]] = {}
    for host in study.config.hosts:
        sheet = study.worksheets.get(host)
        if sheet is not None:
            rules.setdefault(sheet.meta.get("level_rule", "") or "(blank)", []).append(host)
    return [f"{rule} ({', '.join(hosts)})" for rule, hosts in rules.items()]


def _integrity_rows(study: Study) -> List[Dict[str, str]]:
    rows = []
    for key, title in INTEGRITY_CHECKS:
        found = [f for f in study.findings if f.check == key]
        if not found:
            rows.append({"check": key, "title": title, "result": OK, "host": "",
                         "detail": study.checked.get(key, "no problems found")})
        for finding in found:
            rows.append({"check": key, "title": title, "result": finding.level, "host": finding.host,
                         "detail": finding.detail})
    return rows


def _summary_json(study: Study, analysis: Analysis, register_records: Optional[List[Dict[str, object]]],
                  files: Sequence[str], generated_at: str) -> Dict[str, object]:
    critical = _worst(study.findings) == CRITICAL
    payload: Dict[str, object] = {}
    if study.synthetic:
        payload["banner"] = SYNTHETIC_BANNER
    if critical:
        payload["integrity_banner"] = INTEGRITY_BANNER
    payload.update({
        "summary_format": SUMMARY_FORMAT,
        "run": {
            "generated_at_utc": generated_at,
            "miccmac_study_version": miccmac_study.__version__,
            "miccmac_version": miccmac.__version__,
            "analysis_code": study.analysis_code or _analysis_code(),
            "tool_commits": _tool_commits(study),
            "level_rules": _level_rules(study),
            "synthetic": study.synthetic,
        },
        "config": _config_echo(study),
        "integrity": {"status": _worst(study.findings), "checks": _integrity_rows(study)},
        "ledger": {"rows": len(study.row_states), "not_ok": _ledger_not_ok(study)},
        "h1": {"methodology": study.config.primary_methodology, "unit": "hosts", "rows": analysis.h1},
        "h2": _h2_json(study, register_records),
        "pooled": analysis.pooled,
        "check_agreement": analysis.check_agreement,
        "chance_baselines": analysis.chance,
        "l5_rule_only": analysis.l5,
        "weighted_kappa": analysis.kappa,
        "notes": study.sorted_notes(),
        "files": list(files),
    })
    return payload


def _h2_json(study: Study, records: Optional[List[Dict[str, object]]]) -> Dict[str, object]:
    if records is None:
        return {"available": False, "reason": "no register review sheets in register/"}
    return {"available": True, "methodology": study.config.primary_methodology, "unit": "register entries",
            "total": records[-1], "per_host": records[:-1]}


def _summary_md(study: Study, analysis: Analysis, register_records: Optional[List[Dict[str, object]]],
                files: Sequence[str], generated_at: str) -> str:
    config = study.config
    primary = config.primary_methodology
    critical = _worst(study.findings) == CRITICAL
    out: List[str] = []
    if study.synthetic:
        out += [SYNTHETIC_BANNER, ""]
    if critical:
        out += [INTEGRITY_BANNER, ""]
    out += ["# MICCMAC agreement analysis", "",
            "Counts, rates and intervals from `python -m miccmac_study agreement` (protocol section 8). "
            "Descriptive only: interpretation, root causes and actions are left to the researcher.", ""]
    out += _md_run_information(study, files, generated_at)
    out += _md_integrity(study)
    out += _md_h1(study, analysis, primary, f"## 3. H1 (primary): within-one-level agreement, {primary}")
    out += _md_h2(study, register_records)
    out += _md_secondary(study, analysis, register_records)
    out += ["## 6. Secondary methodologies: H1 table (secondary)", ""]
    if not config.secondary_methodologies:
        out += ["None configured.", ""]
    for number, methodology in enumerate(config.secondary_methodologies, start=1):
        out += _md_h1(study, analysis, methodology,
                      f"### 6.{number} {methodology} (secondary): within-one-level agreement")
    out += _md_hand_check(study, analysis, files)
    return "\n".join(out).rstrip("\n") + "\n"


def _md_run_information(study: Study, files: Sequence[str], generated_at: str) -> List[str]:
    config = study.config
    echo = _config_echo(study)
    code = study.analysis_code or _analysis_code()
    clean = code.get("analysis_tree_clean")
    commit_text = str(code["git_commit"] or "null")
    if clean is False:
        commit_text += " (miccmac_study has uncommitted changes or untracked files)"
    clean_text = {True: "yes", False: "no: uncommitted changes or untracked files in miccmac_study",
                  None: "unknown (git not available)"}[clean]
    withdrawn = "; ".join(f"{host} (withdrawn {when}: {reason})" for host, (when, reason)
                          in sorted(study.withdrawn.items())) or "none"
    threshold = _threshold_text(config.threshold) + f", from {study.threshold_source}"
    if study.threshold_source.startswith("--threshold"):
        threshold += f"; the study configuration has {_threshold_text(study.config_threshold)}"
    scales = "; ".join(f"{m}: tool levels 1-{config.tool_max_level(m)}, manual levels 1-{config.manual_max(m)}"
                       for m in config.methodologies)
    commits = "; ".join(f"{c['commit']} ({c['outputs']} outputs, {c['clean_tree']} with a clean tree)"
                        for c in _tool_commits(study)) or "none read"
    declared = (f"manual: {_rule_value_text(config.manual_level_rule)}; tool_side: {study.config_tool_side_rule}; "
                f"overall: {_rule_value_text(study.config_overall_rule)}")
    tool_side = f"{config.tool_side_rule}, from {study.tool_side_source}"
    if study.tool_side_source.startswith("--"):
        tool_side += f"; the study configuration has {study.config_tool_side_rule}"
    overall = f"{_rule_value_text(config.overall_rule)}, from {study.overall_source}"
    if study.overall_source.startswith("--"):
        overall += (f"; the study configuration has {study.config_overall_rule}" if study.config_overall_rule
                    else "; the study configuration declares none")
    if config.tool_side_rule != LEVEL_RULE_APPROVED:
        overall += "; not used for the tool side, which takes miccmac's own overall level"
    reasons = [", ".join(study.overrides)] if study.overrides else []
    if study.config_differences:
        reasons.append(f"{study.config_path.name} differs from {study.config_reference}: "
                       f"{'; '.join(study.config_differences)}")
    reasons.extend(study.post_hoc_exclusions)
    sensitivity = ("yes: " + "; ".join(reasons)) if reasons else "no"
    rows = [
        ("Study configuration", f"{echo['path']} (sha256 {echo['sha256']})"),
        ("Hosts", ", ".join(config.hosts)),
        ("Withdrawn hosts (ledger withdraw; left out)", withdrawn),
        ("Hosts outside the configuration (left out)", ", ".join(study.extra_hosts) or "none"),
        ("Threshold", threshold),
        ("Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions)", sensitivity),
        ("Primary methodology", config.primary_methodology),
        ("Secondary methodologies", ", ".join(config.secondary_methodologies) or "none"),
        ("Level scales", scales),
        ("Level rule (study.yaml level_rule)", declared),
        ("Tool-side level rule used", tool_side),
        ("Overall-level rule used", overall),
        ("Manual level rule (worksheets)", "; ".join(_level_rules(study)) or "no worksheets"),
        ("Input-driven checks", f"{', '.join(config.input_driven_checks)} ({len(config.input_driven_checks)})"),
        ("Input-driven properties", ", ".join(config.input_driven_properties)),
        ("Bootstrap", f"iterations {config.bootstrap_iterations}, seed {config.bootstrap_seed}, "
                      f"exact limit {config.bootstrap_exact_limit}"),
        ("Weighted kappa", "yes" if config.weighted_kappa else "no"),
        ("Synthetic data", "yes" if study.synthetic else "no"),
        ("Tool commits", commits),
        ("miccmac_study version", miccmac_study.__version__),
        ("Analysis code commit", commit_text),
        ("Analysis code committed (analysis_tree_clean)", clean_text),
        ("Analysis code files (sha256 with LF line endings, as committed; first 16 hex, full values in "
         "summary.json)",
         "; ".join(f"{name} {(sha or 'missing')[:16]}" for name, sha in code["files_sha256"].items())),
        ("generated_at_utc", generated_at),
        ("Files written", ", ".join(files)),
    ]
    return ["## 1. Run information", ""] + _md_table(("Item", "Value"), rows)


def _md_integrity(study: Study) -> List[str]:
    rows = [(i + 1, r["title"], r["result"], r["host"], r["detail"]) for i, r in enumerate(_integrity_rows(study))]
    out = (["## 2. Integrity checks", "", f"Overall result: {_worst(study.findings)}", ""]
           + _md_table(("#", "Check", "Result", "Host", "Detail"), rows))
    not_ok = _ledger_not_ok(study)
    out += [f"Ledger rows that are not OK (as `ledger verify` reports them; {len(study.row_states)} rows in all). "
            "SUPERSEDED rows were corrected before they could matter, and ARCHIVED rows (withdrawals and seal "
            "openings) record a configuration that has changed since, kept in ledger-archive; both are listed for "
            "information only:", ""]
    if not not_ok:
        return out + ["- None.", ""]
    for r in not_ok:
        order = ", OUT OF ORDER" if r["out_of_order"] else ""
        out.append(f"- line {r['line']}: {r['state']}{order} {r['path'] or '(no path)'} ({r['kind']}, "
                   f"{r['host_code']}, recorded {r['recorded_at_utc']})")
    return out + [""]


def _md_h1(study: Study, analysis: Analysis, methodology: str, heading: str) -> List[str]:
    threshold = study.config.threshold
    rows = [r for r in analysis.h1 if r["methodology"] == methodology and r["measure"] == "within_one"
            and r["scope"] in H1_SCOPES]
    hosts = len(_hosts_with_levels(analysis.levels, methodology, study.config.hosts))
    needed = stats.minimum_successes(hosts, threshold)
    out = [heading, "",
           "Unit: hosts. A host agrees on a scope when |tool level - manual level| <= 1. Tool levels are "
           "recomputed without the checks marked UNASSESSED. A level unassessed on one side only counts as a "
           "disagreement; unassessed on both sides is left out of n.", "",
           f"Tool levels: {_tool_side_text(study, methodology)}.", ""]
    if needed is None:
        out += ["No host has comparable levels for this methodology.", ""]
    else:
        out += [f"With n = {hosts} hosts, the threshold {_threshold_text(threshold)} needs at least "
                f"{needed} of {hosts}.", ""]
    if any(r["n"] != hosts for r in rows):
        out += ["Some scopes have fewer comparable hosts; see the Needed column.", ""]
    table = [(r["scope"], _kn(r), _fmt(r["rate"]) or "n/a", _ci(r), _fmt(r["threshold"]),
              "n/a" if r["needed"] is None else f"{r['needed']} of {r['n']}",
              _yes_no(r["meets_threshold"]) or "n/a") for r in rows]
    return out + _md_table(("Scope", "Within-one k/n", "Rate", "Wilson 95% CI", "Threshold", "Needed",
                            "Meets threshold"), table)


def _md_h2(study: Study, records: Optional[List[Dict[str, object]]]) -> List[str]:
    out = ["## 4. H2 (primary): register entries judged both accurate and actionable", ""]
    if records is None:
        return out + ["Not yet available: no register review sheets in register/.", ""]
    total = records[-1]
    out += [f"Unit: risk-register entries of the {study.config.primary_methodology} outputs. An entry is judged "
            "when accurate and actionable are both answered, or when either is N (it cannot count as k whatever "
            "the other answer). n = judged entries; k = entries with accurate = Y and actionable = Y. An entry "
            "with Y and a blank, or two blanks, is not judged: a CRITICAL integrity problem, because every entry "
            "must be judged before the final analysis; not-judged entries are left out of n and counted in the "
            "Not judged column. Per-host rows are descriptive; the threshold applies to the TOTAL row.", "",
            "The Wilson interval treats the entries as independent, although entries from the same host may be "
            "correlated, so it can be too narrow. A host-cluster bootstrap interval, which resamples whole hosts, "
            "is reported below the table as a secondary check; it does not replace the protocol's Wilson "
            "interval.", ""]
    table = [(r["host"], r["entries"], r["judged"], r["not_judged"], r["accurate_y"], r["actionable_y"], _kn(r),
              _fmt(r["rate"]) or "n/a", _ci(r)) for r in records]
    out += _md_table(("Host", "Entries", "Judged", "Not judged", "Accurate Y", "Actionable Y", "k/n", "Rate",
                      "Wilson 95% CI"), table)
    if total["n"]:
        out += [f"TOTAL: k/n = {_kn(total)}, rate {_fmt(total['rate'])}, Wilson 95% CI {_ci(total)}, threshold "
                f"{_threshold_text(study.config.threshold)}, needs at least {total['needed']} of {total['n']}, "
                f"meets threshold: {_yes_no(total['meets_threshold'])}.", "",
                f"Secondary: host-cluster bootstrap 95% CI {_ci(total, 'boot_low', 'boot_high')} "
                f"({_boot_text(total, 'hosts with judged entries')}).", ""]
    else:
        out += ["TOTAL: no judged entries yet.", ""]
    if total["not_judged"]:
        out += [f"{total['not_judged']} entries are not judged and are left out of n (CRITICAL: every entry must "
                "be judged before the final analysis; see section 2).", ""]
    return out


def _boot_text(record: Dict[str, object], what: str = "hosts") -> str:
    """How one host-cluster bootstrap was run, e.g. 'exact, 3125 resamples
    of 5 hosts'."""
    if record.get("boot_method") in (None, "none"):
        return f"no {what} to resample"
    text = f"{record['boot_method']}, {record['boot_resamples']} resamples of {record['boot_hosts']} {what}"
    if record.get("boot_dropped"):
        text += f", {record['boot_dropped']} dropped"
    return text


def _md_secondary(study: Study, analysis: Analysis, records: Optional[List[Dict[str, object]]]) -> List[str]:
    config = study.config
    primary = config.primary_methodology
    out = ["## 5. Secondary measures", "", f"Primary methodology ({primary}) unless stated.", ""]

    out += ["### 5.1 Exact-level agreement (hosts)", "", _rule_only_sentence(study), ""]
    l5 = {r["scope"]: r for r in analysis.l5 if r["methodology"] == primary}
    rows = [(r["scope"], _kn(r), _fmt(r["rate"]) or "n/a", _ci(r), _l5_cell(l5[r["scope"]]),
             _rule_only_cell(l5[r["scope"]]))
            for r in analysis.h1 if r["methodology"] == primary and r["measure"] == "exact" and r["scope"] in H1_SCOPES]
    out += _md_table(("Scope", "Exact k/n", "Rate", "Wilson 95% CI", "Of the mismatches: Level 5 rule only",
                      "Of the mismatches: rule only"), rows)

    pooled = [r for r in analysis.pooled if r["methodology"] == primary]
    kept = len(_subset_scopes(study, "excl_input_driven"))
    out += ["### 5.2 Pooled host x property agreement", "",
            f"All host x property comparisons pooled (up to {len(PROPERTY_KEYS)} per host; {kept} without the "
            "input-driven properties). The Wilson interval treats the comparisons as independent; the bootstrap "
            "interval resamples whole hosts (clusters), 2.5th to 97.5th percentile. "
            + _bootstrap_sentence(pooled, config), ""]
    rows = [(r["measure"], r["subset"], _kn(r), _fmt(r["rate"]) or "n/a", _ci(r), _ci(r, "boot_low", "boot_high"),
             _boot_text(r)) for r in pooled]
    out += _md_table(("Measure", "Subset", "k/n", "Rate", "Wilson 95% CI", "Bootstrap 95% CI", "Bootstrap"), rows)
    out += ["The level confusion matrices (confusion_levels_<methodology>.csv) count every host x property row, "
            "including comparisons left out of n, so their total can exceed n; manual_unassessed counts UNASSESSED "
            "entries and manual_missing blank or unreadable manual levels.", ""]

    out += ["### 5.3 Overall agreement with and without the input-driven properties (hosts)", "",
            f"{OVERALL_EXCL} is the overall level over the properties other than "
            f"{', '.join(config.input_driven_properties)}.", ""]
    by_key = {(r["scope"], r["measure"]): r for r in analysis.h1 if r["methodology"] == primary}
    rows = []
    for scope in (OVERALL, OVERALL_EXCL):
        w, e = by_key[(scope, "within_one")], by_key[(scope, "exact")]
        rows.append((scope, _kn(w), _fmt(w["rate"]) or "n/a", _ci(w), _kn(e), _fmt(e["rate"]) or "n/a", _ci(e)))
    out += _md_table(("Scope", "Within-one k/n", "Rate", "Wilson 95% CI", "Exact k/n", "Rate", "Wilson 95% CI"), rows)

    out += ["### 5.4 Check-verdict agreement: device-observable and input-driven checks", "",
            "Unit: host x check comparisons (UNASSESSED checks left out). N/A equals NOT_APPLICABLE. The Wilson "
            "interval treats the comparisons as independent; the host-cluster bootstrap interval (secondary) "
            "resamples whole hosts, 2.5th to 97.5th percentile, leaving out hosts with no comparison.", ""]
    rows = [(r["group"], r["checks"], _kn(r), _fmt(r["rate"]) or "n/a", _ci(r), _ci(r, "boot_low", "boot_high"),
             _boot_text(r), _kappa_cell(r["kappa"], r["kappa_note"]))
            for r in analysis.check_agreement]
    out += _md_table(("Group", "Distinct checks", "k/n", "Rate", "Wilson 95% CI",
                      "Host bootstrap 95% CI (secondary)", "Bootstrap", "Cohen's kappa"), rows)

    out += ["### 5.5 Uniform chance baselines", "",
            "Agreement expected if tool and manual levels were drawn uniformly at random on their scales.", ""]
    rows = [(r["methodology"], r["tool_levels"], r["manual_levels"],
             f"{r['within_one_fraction']} = {r['within_one']:.4f}", f"{r['exact_fraction']} = {r['exact']:.4f}")
            for r in analysis.chance]
    out += _md_table(("Methodology", "Tool levels", "Manual levels", "Within-one", "Exact"), rows)

    out += ["### 5.6 Level 5 rule", "",
            "Exact mismatches where the tool is at its top level and the manual level is at the configured cap "
            "below it (manual_max_level), counted separately; not applicable when the tool's top level is not "
            "above the manual cap. Rule only (see 5.1) counts every exact mismatch that comes from how the levels "
            "were derived rather than from the verdicts, the Level 5 cases included.", ""]
    rows = []
    for methodology in config.methodologies:
        selected = [r for r in analysis.l5 if r["methodology"] == methodology and r["scope"] in H1_SCOPES]
        summed = {"l5_rule_only": sum(r["l5_rule_only"] for r in selected),
                  "l5_rule_applies": _l5_applies(study, methodology),
                  "rule_only": sum(r["rule_only"] for r in selected),
                  "rule_only_blank": sum(r["rule_only_blank"] for r in selected)}
        rows.append((methodology, config.manual_max(methodology), config.tool_max_level(methodology),
                     sum(r["comparisons"] for r in selected), sum(r["exact_mismatches"] for r in selected),
                     _l5_cell(summed), _rule_only_cell(summed)))
    out += _md_table(("Methodology", "Manual cap", "Tool top level", "Comparisons (7 properties + overall)",
                      "Exact mismatches", "Level 5 rule only", "Rule only"), rows)

    out += ["### 5.7 Register prioritization and missed gaps", ""]
    if records is None:
        out += ["Not yet available: no register review sheets.", ""]
    else:
        out += ["Prioritized counts every entry with an answer in the prioritized column (judged or not). "
                "Prioritization rate (secondary): k = entries answered Y, n = entries answered Y or N; UNSURE "
                "answers are left out of n and counted separately; 95% Wilson interval, no threshold. Missed gaps "
                "counts missed-gaps rows with a description.", ""]
        rows = [(r["host"], r["prioritized_y"], r["prioritized_n"], r["prioritized_unsure"],
                 f"{r['prioritization_k']}/{r['prioritization_n']}", _fmt(r["prioritization_rate"]) or "n/a",
                 _ci(r, "prioritization_wilson_low", "prioritization_wilson_high"), r["missed_gaps"])
                for r in records]
        out += _md_table(("Host", "Prioritized Y", "Prioritized N", "Prioritized UNSURE", "Prioritization k/n (Y of Y+N)",
                          "Rate", "Wilson 95% CI", "Missed gaps"), rows)

    if analysis.kappa is not None:
        out += ["### 5.8 Linear-weighted kappa (levels)", "",
                "Pairs where both levels are known; categories 1 to the higher of the tool's top level and the "
                "manual cap. Kappa is marked when one side uses a single category.", ""]
        rows = [(r["methodology"], r["subset"], r["pairs"], _kappa_cell(r["linear_weighted_kappa"], r["kappa_note"]))
                for r in analysis.kappa]
        out += _md_table(("Methodology", "Subset", "Pairs", "Linear-weighted kappa"), rows)

    out += ["### Notes", ""]
    out += [f"- {note}" for note in study.sorted_notes()] or ["- None."]
    return out + [""]


def _rule_only_sentence(study: Study) -> str:
    return ("Rule only counts exact mismatches where the level derived from the worksheet's own verdicts "
            f"(UNASSESSED left out) with the tool-side rule ({study.config.tool_side_rule}) equals the tool level "
            "used, so the difference comes from how the levels were derived rather than from the verdicts; a "
            "mismatch whose scope has a blank or unreadable verdict, a blank or unreadable manual level, or a typed "
            "manual level that does not follow the declared manual rule (level_rule.manual), is not classified.")


def _l5_cell(record: Dict[str, object]) -> object:
    return record["l5_rule_only"] if record["l5_rule_applies"] else "not applicable"


def _rule_only_cell(record: Dict[str, object]) -> str:
    text = str(record["rule_only"])
    if record["rule_only_blank"]:
        text += f" ({record['rule_only_blank']} not classified)"
    return text


def _kappa_cell(value: Optional[float], note: str) -> str:
    text = _fmt(value) or "n/a"
    return f"{text} ({note})" if note else text


def _bootstrap_sentence(rows: Sequence[Dict[str, object]], config: StudyConfig) -> str:
    """How the pooled bootstrap was run, from the rows actually computed.
    Hosts with no comparison in a subset (n = 0) are left out of its
    resampling; the count of hosts resampled is the informative count."""
    if not rows:
        return "No pooled comparisons."
    counts = sorted({int(r["boot_hosts"]) for r in rows})
    left_out = any(int(r["boot_hosts"]) < int(r["hosts"]) for r in rows)
    tail = (" Hosts with no comparable levels in a subset are left out of its resampling (see the Bootstrap "
            "column)." if left_out else "")
    if len(counts) > 1:
        return ("The number of hosts resampled differs by row (see the Bootstrap column); with this few hosts the "
                "interval is coarse and can collapse to a single value." + tail)
    hosts = counts[0]
    method = rows[0]["boot_method"]
    if method == "exact":
        return (f"The bootstrap enumerates all {hosts}^{hosts} = {hosts ** hosts} ordered resamples of the "
                f"{hosts} hosts with comparable levels ({math.comb(2 * hosts - 1, hosts)} distinct host "
                "combinations), so with this few hosts the interval is coarse and can collapse to a single value."
                + tail)
    if method == "monte-carlo":
        return (f"The bootstrap draws {config.bootstrap_iterations} random resamples of the {hosts} hosts with "
                f"comparable levels (seed {config.bootstrap_seed})." + tail)
    return "No hosts to resample."


def _md_hand_check(study: Study, analysis: Analysis, files: Sequence[str]) -> List[str]:
    primary = study.config.primary_methodology
    name = {n.replace(SYNTHETIC_PREFIX, "", 1): n for n in files}
    out = ["## 7. How to hand-check", "",
           "Wilson 95% interval for k agreements out of n, with z = 1.959964 (z^2 = 3.841459):", "",
           "- p = k / n; denominator = 1 + z^2 / n; centre = (p + z^2 / (2n)) / denominator",
           "- half-width = z / denominator x sqrt(p (1 - p) / n + z^2 / (4 n^2))",
           "- interval = centre - half-width to centre + half-width (exactly 0 when k = 0, exactly 1 when k = n)",
           ""]
    # Prefer a row of the section 3 table with 0 < k < n (no clipping at 0 or 1).
    table = [r for r in analysis.h1 if r["methodology"] == primary and r["measure"] == "within_one"
             and r["scope"] in H1_SCOPES]
    example = (next((r for r in table if 0 < r["k"] < r["n"]), None)
               or next((r for r in table if r["scope"] == OVERALL and r["n"]), None)
               or next((r for r in analysis.h1 if r["n"]), None))
    if example is None:
        out += ["No comparison has n > 0, so there is no worked example.", ""]
    else:
        s = stats.wilson_steps(example["k"], example["n"])
        out += [f"Worked example ({example['methodology']}, {example['scope']}, {example['measure']}, from the "
                f"agreement tables): "
                f"k = {s['k']}, n = {s['n']}, p = {s['p']:.4f}; denominator = 1 + {s['z2']:.6f} / {s['n']} = "
                f"{s['denominator']:.6f}; centre = ({s['p']:.4f} + {s['z2'] / (2 * s['n']):.6f}) / "
                f"{s['denominator']:.6f} = {s['centre']:.6f}; half-width = {s['half_width']:.6f}; "
                f"interval = {s['low']:.4f} to {s['high']:.4f}.", ""]
    out += ["Recounting the headline numbers:", "",
            f"- H1 (section 3): in {name['host_levels.csv']}, keep the rows with methodology = {primary} and the "
            "scope; n = rows whose within_one is yes or no (blank = left out); k = rows with within_one = yes. "
            "Exact agreement (5.1) uses the exact column of the same rows.",
            f"- Pooled (5.2): the same rows of {name['host_levels.csv']} over the seven properties (or the "
            "properties that are not input-driven), summed over hosts.",
            f"- Rule only (5.1, 5.6): in {name['host_levels.csv']}, rows with exact = no and rule_only = yes; to "
            "check one, derive that scope's level from the worksheet's verdicts (UNASSESSED left out) with the "
            f"tool-side rule ({study.config.tool_side_rule}) and compare it with tool_level_used.",
            f"- Check agreement (5.4): in {name['check_verdicts.csv']}, rows with compared = yes; k = rows with "
            "agree = yes; the group column separates device and input checks.",
            f"- Bootstrap (5.2, 5.4, section 4): {name['summary.json']} lists each row's per-host (k, n) clusters; "
            "hosts with n = 0 are left out, and a resample's rate is the summed k over the summed n of the drawn "
            "hosts.",
            ]
    if "register_h2.csv" in name:
        out.append(f"- H2 (section 4): in {name['register_h2.csv']}, the TOTAL row; n = judged entries "
                   "(accurate and actionable both answered, or either answered N), k = entries with accurate = Y "
                   "and actionable = Y, not_judged = the other entries (left out of n); the per-host rows add up "
                   "to the TOTAL row.")
        out.append(f"- Prioritization (5.7): in {name['register_h2.csv']}, prioritization_k = prioritized_y and "
                   "prioritization_n = prioritized_y + prioritized_n; UNSURE answers are left out of n.")
    out += [f"- {name['disagreements.csv']} lists every exact level mismatch and every verdict mismatch. The "
            "researcher fills root_cause (one of: " + "; ".join(ROOT_CAUSES) + "), action and "
            "assessor_error_note; this command leaves them blank.", ""]
    return out


# ------------------------------------------------------------------ writing
def _write_outputs(study: Study, analysis: Analysis, out_dir: Path, planned: Sequence[str],
                   generated_at: str, overwrite: bool) -> None:
    prefix = SYNTHETIC_PREFIX if study.synthetic else ""
    register_records = _register_records(study, analysis.register) if analysis.register is not None else None
    out_dir.mkdir(parents=True, exist_ok=True)

    def target(name: str) -> Path:
        return out_dir / (prefix + name)

    summary = _summary_md(study, analysis, register_records, planned, generated_at)
    md_path = target("summary.md")
    if md_path.exists() and not overwrite:
        raise StudyError(f"{md_path} already exists; refusing to overwrite it")
    with open(md_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(summary)
    write_json(target("summary.json"), _summary_json(study, analysis, register_records, planned, generated_at),
               overwrite=overwrite)
    write_csv(target("host_levels.csv"), HOST_LEVELS_COLUMNS, _host_level_rows(analysis), overwrite=overwrite)
    write_csv(target("agreement_h1.csv"), AGREEMENT_H1_COLUMNS, _h1_csv_rows(analysis), overwrite=overwrite)
    write_csv(target("pooled.csv"), POOLED_COLUMNS, _pooled_csv_rows(analysis), overwrite=overwrite)
    write_csv(target("check_verdicts.csv"), CHECK_VERDICTS_COLUMNS, _check_verdict_rows(analysis),
              overwrite=overwrite)
    write_csv(target("check_agreement.csv"), CHECK_AGREEMENT_COLUMNS, _check_agreement_csv_rows(analysis),
              overwrite=overwrite)
    for methodology in study.config.methodologies:
        write_csv(target(f"confusion_levels_{methodology}.csv"), _confusion_level_columns(study, methodology),
                  analysis.level_confusion[methodology], overwrite=overwrite)
    write_csv(target("confusion_verdicts.csv"), CONFUSION_VERDICT_COLUMNS, analysis.verdict_confusion,
              overwrite=overwrite)
    if register_records is not None:
        write_csv(target("register_h2.csv"), REGISTER_H2_COLUMNS, _register_csv_rows(register_records),
                  overwrite=overwrite)
    write_csv(target("disagreements.csv"), DISAGREEMENT_COLUMNS, _disagreement_rows(analysis, study.config.hosts),
              overwrite=overwrite)
