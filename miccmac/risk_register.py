"""Risk register: one entry per check that needs attention, joined with that
check's CIS Implementation Group + FAIR-inspired risk metadata (from
miccmac.metadata), in priority order.

Pure function of (Assessment, metadata) -- no target/network dependency.

Which checks get an entry (RiskEntry.entry_type):

    finding       FAIL or PARTIAL: the control is missing or incomplete.
    missing-data  ERROR (the data the check reads cannot be read), or
                  NOT_APPLICABLE only because an organizational input the
                  check reads was not supplied: the attestation or inventory
                  record, or the entry it reads there. The check says so with
                  a miccmac.model.MissingData marker, set in the branch that
                  returns that status; detail text is never parsed. The entry
                  says what is missing and how to supply it.

No entry: PASS; NOT_APPLICABLE without a marker (the check does not apply,
e.g. CUR-02 with no third-party software); a check excluded by the config;
NOT_IMPLEMENTED (no facts or inputs reached the check, or a custom check is a
placeholder: a run-level condition, not a gap of the device; the text and
markdown registers count such checks in one "Not evaluated" line). A check
whose control is missing is a FAIL finding; a missing-data entry is a check
the tool could not evaluate.

The risk rating is a 3x3 qualitative lookup table, not a numeric product:
LOW/MEDIUM/HIGH are ordinal, not interval, values, so multiplying them would
imply precision the underlying judgment doesn't have. This is the
"FAIR-inspired, simplified, qualitative" framing -- not quantitative
FAIR/Monte Carlo, which is out of scope. A missing-data entry carries the
check's own rating: the one the finding would have if the control turned out
to be absent (sp800_30.risk_basis "if-control-absent").

Order: findings first, then missing-data entries, so an unconfirmed gap never
outranks a confirmed finding; within each group risk rating is the dominant
key (CRITICAL, HIGH, MODERATE, LOW, UNRATED: fix CRITICALs before HIGHs
regardless of IG), then CIS IG (IG1, IG2, IG3, none: an IG1 failure is more
foundational, expected of every organization, than an IG2 failure at the same
risk level), then check id. The key (group, -risk rank, IG rank, check id) is
a total order that depends only on the assessment and the metadata, never on
the methodology, so the CMMI and CISA ZTMM outputs of one run list the same
entries in the same order and a --facts replay reproduces it. Findings keep
exactly the order they had before missing-data entries existed.

Each entry also carries:

- next_level: with a maturity lens (assessment.methodology), the property's
  level now and what fixing this check does toward the next level
  (next_level_hint). None without a lens.
- sp800_30: the entry's own fields arranged as NIST SP 800-30 Rev. 1 risk
  factors (threat source type, threat event, vulnerability, likelihood,
  impact) and the resulting risk, plus a recommended response (Sp80030).
  This is not an SP 800-30 risk assessment: there is no
  organization-specific threat analysis, no SP 800-30 assessment scale or
  table, and no quantitative estimate.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from miccmac.engine import score_statuses
from miccmac.metadata import CheckMetadata, DEFAULT_MAPPINGS_PATH, load_register_metadata
from miccmac.methodology import LEVEL_WORDS, get_methodology
from miccmac.model import SCORE_MAP, Assessment, CheckResult, MissingData, PropertyResult, Status

RISK_MATRIX = {
    ("LOW", "LOW"): "LOW", ("LOW", "MEDIUM"): "LOW", ("LOW", "HIGH"): "MODERATE",
    ("MEDIUM", "LOW"): "LOW", ("MEDIUM", "MEDIUM"): "MODERATE", ("MEDIUM", "HIGH"): "HIGH",
    ("HIGH", "LOW"): "MODERATE", ("HIGH", "MEDIUM"): "HIGH", ("HIGH", "HIGH"): "CRITICAL",
}
_RISK_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "UNRATED": 0}
_IG_RANK = {"IG1": 1, "IG2": 2, "IG3": 3}

FINDING = "finding"
MISSING_DATA = "missing-data"
ENTRY_TYPES = (FINDING, MISSING_DATA)
_FINDING_STATUSES = (Status.FAIL, Status.PARTIAL)
# Statuses an open entry can have that count in the property score.
_OPEN_SCORED = (Status.FAIL, Status.PARTIAL, Status.ERROR)

# next_level effects (NextLevelHint.effect).
EFFECT_ALONE = "alone"              # this fix alone reaches the next level
EFFECT_WITH_OTHERS = "with-others"  # every fewest set of fixes that reaches it includes this one
EFFECT_ONE_OF = "one-of"            # some fewest sets include this one; others reach it without it
EFFECT_NOT_NEEDED = "not-needed"    # no fewest set includes this one
EFFECT_TOP_LEVEL = "top-level"      # the property is at the methodology's top level
EFFECT_NOT_SCORED = "not-scored"    # this check is not scored until its data is supplied
NEXT_LEVEL_EFFECTS = (EFFECT_ALONE, EFFECT_WITH_OTHERS, EFFECT_ONE_OF, EFFECT_NOT_NEEDED, EFFECT_TOP_LEVEL,
                      EFFECT_NOT_SCORED)

# sp800_30.risk_basis: what the risk rating applies to.
RISK_BASIS_FINDING = "finding"
RISK_BASIS_IF_ABSENT = "if-control-absent"

_NOT_DECLARED = "n/a (not declared)"


# ------------------------------------------------------------------ entry objects
@dataclass(frozen=True)
class MissingDataInfo:
    """What is missing for a missing-data entry and how to supply it. The
    first four fields copy the check's MissingData marker; they are None for
    an ERROR without one (a custom check), which gets generic texts."""
    source: Optional[str]
    problem: Optional[str]
    field: Optional[str]
    expected: Optional[str]
    what: str
    how_to_supply: str

    def to_dict(self) -> dict:
        return {"source": self.source, "problem": self.problem, "field": self.field,
                "expected": self.expected, "what": self.what, "how_to_supply": self.how_to_supply}


@dataclass(frozen=True)
class NextLevelHint:
    """The entry's property under the active maturity lens: its level now,
    and what fixing this check does toward the next level (next_level_hint).
    A fix means the check re-tests as PASS and nothing else changes; the
    target fields are None at the top level and for a check that is not
    scored."""
    methodology: str
    effect: str
    current_level: Optional[int]
    current_label: str
    current_score: Optional[float]
    max_level: int
    target_level: Optional[int] = None
    target_label: Optional[str] = None
    target_min_score: Optional[float] = None
    score_if_fixed: Optional[float] = None       # this fix alone
    level_if_fixed: Optional[int] = None
    level_if_fixed_label: Optional[str] = None
    fixes_needed: Optional[int] = None           # the fewest fixes that include this one and reach the target
    with_check_ids: Optional[Tuple[str, ...]] = None    # the others in that set
    fewest_fixes: Optional[int] = None           # the fewest fixes of any open entries that reach the target
    target_reachable_without_this: Optional[bool] = None
    without_check_ids: Optional[Tuple[str, ...]] = None  # the fewest open entries that reach it without this one
    text: str = ""

    def to_dict(self) -> dict:
        return {
            "methodology": self.methodology, "effect": self.effect,
            "current_level": self.current_level, "current_label": self.current_label,
            "current_score": self.current_score, "max_level": self.max_level,
            "target_level": self.target_level, "target_label": self.target_label,
            "target_min_score": self.target_min_score,
            "score_if_fixed": self.score_if_fixed, "level_if_fixed": self.level_if_fixed,
            "level_if_fixed_label": self.level_if_fixed_label,
            "fixes_needed": self.fixes_needed,
            "with_check_ids": None if self.with_check_ids is None else list(self.with_check_ids),
            "fewest_fixes": self.fewest_fixes,
            "target_reachable_without_this": self.target_reachable_without_this,
            "without_check_ids": None if self.without_check_ids is None else list(self.without_check_ids),
            "text": self.text,
        }


@dataclass(frozen=True)
class Sp80030:
    """The entry's fields as NIST SP 800-30 Rev. 1 risk factors and the
    resulting risk, plus a recommended response (the risk response itself
    is the organization's decision, as in NIST SP 800-39). Mapped only where
    faithful:
    vulnerability = the finding (None for missing data: not determined);
    likelihood = the FAIR frequency band; impact = the FAIR magnitude band;
    risk = the register's own matrix rating. The threat source type and
    event come from the check metadata (`threats:`), with their review
    state (drafted/confirmed; None when not declared)."""
    threat_source_type: Optional[str]
    threat_event: Optional[str]
    vulnerability: Optional[str]
    likelihood: Optional[str]
    impact: Optional[str]
    risk: str
    risk_basis: str
    response: Optional[str]
    review: Optional[str]

    def to_dict(self) -> dict:
        return {"threat_source_type": self.threat_source_type, "threat_event": self.threat_event,
                "vulnerability": self.vulnerability, "likelihood": self.likelihood, "impact": self.impact,
                "risk": self.risk, "risk_basis": self.risk_basis, "response": self.response,
                "review": self.review}


@dataclass(frozen=True)
class RiskEntry:
    check_id: str
    property_key: str
    name: str
    status: Status
    cis_ig: Optional[str]
    fair_frequency: Optional[str]
    fair_magnitude: Optional[str]
    risk_rating: str
    detail: str
    remediation: Optional[str] = None
    entry_type: str = FINDING
    missing_data: Optional[MissingDataInfo] = None
    next_level: Optional[NextLevelHint] = None
    sp800_30: Optional[Sp80030] = None

    def to_dict(self) -> dict:
        # The first ten keys are the register's original ones, unchanged and in
        # their original order; the last four were added with missing-data
        # entries, next-level hints and the SP 800-30 fields.
        return {
            "check_id": self.check_id,
            "property_key": self.property_key,
            "name": self.name,
            "status": self.status.value,
            "cis_ig": self.cis_ig,
            "fair_frequency": self.fair_frequency,
            "fair_magnitude": self.fair_magnitude,
            "risk_rating": self.risk_rating,
            "detail": self.detail,
            "remediation": self.remediation,
            "entry_type": self.entry_type,
            "missing_data": None if self.missing_data is None else self.missing_data.to_dict(),
            "next_level": None if self.next_level is None else self.next_level.to_dict(),
            "sp800_30": None if self.sp800_30 is None else self.sp800_30.to_dict(),
        }

    @property
    def response(self) -> Optional[str]:
        """The action to take now: the fix for a finding; for missing data,
        how to supply it, then the fix."""
        return self.sp800_30.response if self.sp800_30 is not None else self.remediation


def risk_rating(frequency: Optional[str], magnitude: Optional[str]) -> str:
    if frequency is None or magnitude is None:
        return "UNRATED"
    return RISK_MATRIX.get((frequency, magnitude), "UNRATED")


def entry_type_for(check: CheckResult, excluded: Iterable[str] = ()) -> Optional[str]:
    """FINDING, MISSING_DATA or None (no entry) for a check, by the rule in
    the module docstring."""
    if check.status in _FINDING_STATUSES:
        return FINDING
    if check.check_id in set(excluded):
        return None
    if check.status is Status.ERROR:
        return MISSING_DATA
    if check.status is Status.NOT_APPLICABLE and isinstance(check.missing_data, MissingData):
        return MISSING_DATA
    return None


def not_evaluated_count(assessment: Assessment) -> int:
    """How many checks are NOT_IMPLEMENTED (they get no register entry)."""
    return sum(1 for prop in assessment.properties for check in prop.checks
               if check.status is Status.NOT_IMPLEMENTED)


def sort_key(entry: RiskEntry) -> tuple:
    """The register's order (module docstring): a total order."""
    return (0 if entry.entry_type == FINDING else 1, -_RISK_RANK.get(entry.risk_rating, 0),
            _IG_RANK.get(entry.cis_ig, 99), entry.check_id)


# ------------------------------------------------------------------ building
def build_risk_register(
    assessment: Assessment,
    metadata_path=DEFAULT_MAPPINGS_PATH,
    extra_metadata: Optional[Dict[str, CheckMetadata]] = None,
) -> List[RiskEntry]:
    """Collect every finding and missing-data entry across
    assessment.properties (module docstring), join each by check_id with
    its CIS IG/FAIR and SP 800-30 metadata, and sort by sort_key.

    ``extra_metadata`` (check_id -> CheckMetadata) supplies risk metadata for
    custom checks, declared via their RISK_METADATA attribute (see
    miccmac/config.py) -- merged over the built-in lookup so custom checks
    plug into the same prioritization instead of always sorting last as
    UNRATED. A check_id with no metadata at all (in neither source) still
    gets None fields and rating UNRATED, sorted last in its group.

    Raises MappingsError if metadata_path itself is missing/malformed (its
    `checks:` or `threats:` section) -- that's a real configuration problem,
    not a per-check gap, so it should surface rather than silently degrade
    every entry to UNRATED."""
    metadata_by_id = dict(load_register_metadata(metadata_path))
    if extra_metadata:
        metadata_by_id.update(extra_metadata)
    excluded = set(assessment.excluded_check_ids)

    entries: List[RiskEntry] = []
    for prop in assessment.properties:
        for check in prop.checks:
            kind = entry_type_for(check, excluded)
            if kind is None:
                continue
            meta = metadata_by_id.get(check.check_id)
            frequency = meta.fair_frequency if meta else None
            magnitude = meta.fair_magnitude if meta else None
            remediation = meta.remediation if meta else None
            rating = risk_rating(frequency, magnitude)
            missing = _missing_data_info(check) if kind == MISSING_DATA else None
            if kind == FINDING:
                response = remediation
                vulnerability = check.detail or check.name
            else:
                response = missing.how_to_supply
                if remediation:
                    response += " If the check then fails: " + remediation
                vulnerability = None
            entries.append(RiskEntry(
                check_id=check.check_id,
                property_key=prop.key,
                name=check.name,
                status=check.status,
                cis_ig=meta.cis_ig if meta else None,
                fair_frequency=frequency,
                fair_magnitude=magnitude,
                risk_rating=rating,
                detail=check.detail,
                remediation=remediation,
                entry_type=kind,
                missing_data=missing,
                next_level=next_level_hint(assessment, prop, check),
                sp800_30=Sp80030(
                    threat_source_type=meta.threat_source_type if meta else None,
                    threat_event=meta.threat_event if meta else None,
                    vulnerability=vulnerability,
                    likelihood=frequency,
                    impact=magnitude,
                    risk=rating,
                    risk_basis=RISK_BASIS_FINDING if kind == FINDING else RISK_BASIS_IF_ABSENT,
                    response=response,
                    review=meta.sp800_30_review if meta else None,
                ),
            ))
    entries.sort(key=sort_key)
    return entries


# ------------------------------------------------------------------ missing-data texts
_DOES_NOT_APPLY = (" If this check does not apply to this device, exclude it with a reason in the --config file "
                   "(excluded_checks) instead.")
_AGAIN = "and run the assessment again."


def _sentence_body(text: str) -> str:
    """`text` without its final period, stripped."""
    text = (text or "").strip()
    return text[:-1] if text.endswith(".") else text


def _paren(detail: str) -> str:
    return f" ({detail})" if detail else ""


def _missing_data_info(check: CheckResult) -> MissingDataInfo:
    marker = check.missing_data if isinstance(check.missing_data, MissingData) else None
    detail = _sentence_body(check.detail)
    cid = check.check_id
    if marker is None:
        what = (f"{cid} could not be evaluated ({detail})." if detail
                else f"{cid} could not be evaluated (status {check.status.value}).")
        how = "Supply or correct the data this check reads (its detail says what failed), " + _AGAIN
        return MissingDataInfo(None, None, None, None, what, how)
    return MissingDataInfo(marker.source, marker.problem, marker.field, marker.expected,
                           _what_is_missing(cid, marker, detail), _how_to_supply(marker))


def _what_is_missing(cid: str, marker: MissingData, detail: str) -> str:
    field, end = marker.field, f", so {cid} could not be evaluated."
    key = (marker.source, marker.problem)
    if key == ("attestation", "not-supplied"):
        return "No attestation file was given (--attestation)" + end
    if key == ("inventory_record", "not-supplied"):
        return "No inventory-system record was given (--inventory-record)" + end
    if key == ("attestation", "missing-field"):
        return (f'The attestation file has no "{field}" entry' if field
                else "The attestation file holds no entries for this check") + end
    if key == ("inventory_record", "missing-field"):
        return (f'The inventory record has no "{field}" entry' if field
                else "The --inventory-record file holds no record") + end
    if key == ("facts", "missing-field"):
        return (f"The collected device facts have no {field} value" if field
                else "The collected device facts lack the data this check reads") + end
    owner = {"attestation": "The attestation file's", "inventory_record": "The inventory record's",
             "facts": "The collected device facts'"}[marker.source]
    if field:
        return f"{owner} {field} value cannot be read{_paren(detail)}" + end
    return f"{owner} data for this check cannot be read{_paren(detail)}" + end


def _how_to_supply(marker: MissingData) -> str:
    field, expected = marker.field, marker.expected
    entry = (f'the entry "{field}": {expected}' if expected else f'a "{field}" entry') if field else ""
    example = f", for example {expected}," if expected else ","
    source, problem = marker.source, marker.problem
    if source == "facts":
        if field:
            shown = f" (expected: {expected})" if expected else ""
            return (f"Collect the device facts again with --connector; if {field} is still missing or "
                    f"unreadable{shown}, check it on the device by hand.")
        return ("Collect the device facts again with --connector; if the data is still missing or unreadable, "
                "check it on the device by hand.")
    if problem == "invalid-value":
        option = "--attestation" if source == "attestation" else "--inventory-record"
        target = f" to {expected}" if expected else ""
        if field:
            return f"Correct {field} in the {option} file{target}, " + _AGAIN
        return f"Correct the {option} file{target}, " + _AGAIN
    if source == "attestation":
        if problem == "not-supplied":
            text = (f"Give an --attestation JSON file with {entry}, recording this device's facts, "
                    + _AGAIN if field else
                    f"Give an --attestation JSON file recording this device's facts{example} " + _AGAIN)
        else:
            text = (f"Add {entry} to the --attestation file, recording this device's facts, " + _AGAIN
                    if field else f"Put this device's facts in the --attestation file{example} " + _AGAIN)
        return text + _DOES_NOT_APPLY
    if problem == "not-supplied":
        text = (f"Give the device's record from the inventory system as an --inventory-record JSON file{example} "
                + _AGAIN)
    elif field:
        text = f"Add {entry} to the --inventory-record file, " + _AGAIN
    else:
        text = (f"Put the device's record from the inventory system in the --inventory-record file{example} "
                + _AGAIN)
    return text + _DOES_NOT_APPLY


# ------------------------------------------------------------------ next-level hint
_GAIN_ORDER = {Status.FAIL: 0, Status.ERROR: 0, Status.PARTIAL: 1}   # larger score gain first


def _words(name: str) -> Tuple[str, str]:
    return LEVEL_WORDS.get(name, (name.upper(), "level"))


def _score_text(score: Optional[float]) -> str:
    return "n/a" if score is None else f"{score:.1f}"


def _cut_text(value: float) -> str:
    return format(value, "g")


def _id_list(ids: Sequence[str]) -> str:
    ids = list(ids)
    if len(ids) <= 1:
        return "".join(ids)
    return ", ".join(ids[:-1]) + " and " + ids[-1]


def next_level_hint(assessment: Assessment, prop: PropertyResult, check: CheckResult) -> Optional[NextLevelHint]:
    """What fixing `check` does toward its property's next maturity level
    under the assessment's methodology, or None without one.

    The current level is the reported one (assessment.methodology). A fix
    means the check re-tests as PASS and nothing else changes; scores and
    levels after a fix use the engine's own scoring (score_statuses) and the
    methodology's cutoffs (level_for_score), so a hint always agrees with
    what a re-test would report. Hints are per property: the overall level
    gets none. The open entries of the property are its FAIL, PARTIAL and
    ERROR checks, taken largest score gain first (FAIL and ERROR before
    PARTIAL, then by check id), which gives the fewest fixes for a level.

    Effects: alone (this fix alone reaches the next level); with-others (it
    does not, and every fewest set of fixes that reaches the next level
    includes this check); one-of (it does not, some fewest sets include this
    check and others reach the next level without it, so it is one of
    several interchangeable fixes); not-needed (no fewest set includes it:
    the fewest fixes reach the next level without it); top-level (the
    property is already at the methodology's top level); not-scored (this
    check is NOT_APPLICABLE until its data is supplied, so no arithmetic is
    shown; the text says whether its result can change the level at all,
    from the property scored with the check as PASS and as FAIL)."""
    result = assessment.methodology
    if result is None:
        return None
    methodology = get_methodology(result.name)
    top = len(methodology.levels)
    current = result.properties.get(prop.key) or methodology.level_for_score(prop.score)
    display, word = _words(methodology.name)
    title = prop.title
    base = dict(methodology=methodology.name, current_level=current.level, current_label=current.level_label,
                current_score=prop.score, max_level=top)

    if check.status not in SCORE_MAP:
        if current.level is None:
            text = (f"{title} has no {display} {word} yet: none of its checks could be scored. "
                    f"Supplying this data lets the tool score it.")
        else:
            others = [c.status for c in prop.checks if c is not check]
            if_pass, if_fail = (methodology.level_for_score(score_statuses(others + [status])).level
                                for status in (Status.PASS, Status.FAIL))
            text = (f"{title} is at {display} {word} {current.level} ({current.level_label}) without this check, "
                    f"which is not scored until its data is supplied; ")
            if if_pass == if_fail:
                text += f"{title} stays at {word} {current.level} whatever its result."
            else:
                text += f"its result can then change that {word}."
        return NextLevelHint(effect=EFFECT_NOT_SCORED, text=text, **base)

    level_now = current.level if current.level is not None else methodology.level_for_score(prop.score).level
    if level_now is None:   # only an inconsistent, hand-built assessment gets here
        level_now = 1
    if level_now >= top:
        text = (f"{title} is already at the top {display} {word}, {word} {level_now} ({current.level_label}); "
                f"there is no next {word}.")
        return NextLevelHint(effect=EFFECT_TOP_LEVEL, text=text, **base)

    target = level_now + 1
    need = methodology.min_score_for_level(target)
    statuses = {c.check_id: c.status for c in prop.checks}

    def outcome(fixed: Set[str]) -> Tuple[Optional[float], int]:
        score = score_statuses(Status.PASS if cid in fixed else status for cid, status in statuses.items())
        return score, methodology.level_for_score(score).level or 0

    def fewest(candidates: Sequence[str], start: Sequence[str] = ()):
        """(chosen ids, score, level) for the shortest prefix of `candidates`
        that, with `start`, reaches the target; chosen None when none does."""
        chosen = list(start)
        score, level = outcome(set(chosen))
        if chosen and level >= target:
            return chosen, score, level
        for cid in candidates:
            chosen.append(cid)
            score, level = outcome(set(chosen))
            if level >= target:
                return chosen, score, level
        return None, score, level

    open_ids = sorted((c.check_id for c in prop.checks if c.status in _OPEN_SCORED),
                      key=lambda cid: (_GAIN_ORDER[statuses[cid]], cid))
    others = [cid for cid in open_ids if cid != check.check_id]
    score_alone, level_alone = outcome({check.check_id})
    with_set, score_with, level_with = fewest(others, start=[check.check_id])
    all_set, _, _ = fewest(open_ids)
    without_set, score_without, _ = fewest(others)
    if with_set is None or all_set is None:
        # Fixing every open entry gives 100.0, which meets every cutoff.
        raise RuntimeError(f"internal: {check.check_id} cannot reach {methodology.name} level {target}")
    labels = methodology.levels
    reached_alone = level_alone >= target
    # with_set is the fewest fixes that include this check, all_set the fewest of all, and
    # without_set the fewest without it (None when none reaches the target).
    in_a_fewest_set = len(with_set) == len(all_set)
    a_fewest_set_without = without_set is not None and len(without_set) == len(all_set)
    effect = (EFFECT_ALONE if reached_alone
              else EFFECT_NOT_NEEDED if not in_a_fewest_set
              else EFFECT_ONE_OF if a_fewest_set_without
              else EFFECT_WITH_OTHERS)
    hint = dict(base, effect=effect, target_level=target, target_label=labels[target - 1], target_min_score=need,
                score_if_fixed=score_alone, level_if_fixed=level_alone, level_if_fixed_label=labels[level_alone - 1],
                fixes_needed=len(with_set), with_check_ids=tuple(with_set[1:]), fewest_fixes=len(all_set),
                target_reachable_without_this=without_set is not None,
                without_check_ids=None if without_set is None else tuple(without_set))

    error = check.status is Status.ERROR
    now = f"{display} {word} {level_now} ({current.level_label})"
    if effect == EFFECT_ALONE:
        reached = f"{word} {level_alone} ({labels[level_alone - 1]})"
        change = (f"score {_score_text(prop.score)} -> {_score_text(score_alone)} "
                  f"({word} {level_alone} needs {_cut_text(methodology.min_score_for_level(level_alone))})")
        if error:
            text = f"If this check passes once it can be evaluated, {title} rises from {now} to {reached}: {change}."
        else:
            text = f"Fixing this check alone raises {title} from {now} to {reached}: {change}."
        return NextLevelHint(text=text, **hint)

    intro = (f"{title} is at {now}, score {_score_text(prop.score)}; {word} {target} ({labels[target - 1]}) "
             f"needs {_cut_text(need)}.")
    own = (f"If this check passes once it can be evaluated, the score is {_score_text(score_alone)}." if error
           else f"Fixing this check alone gives {_score_text(score_alone)}.")
    together = _id_list(with_set[1:])
    if effect == EFFECT_WITH_OTHERS:
        text = (f"{intro} {own} Together with {together} ({len(with_set)} fixes), it takes {title} to {word} "
                f"{level_with} ({labels[level_with - 1]}), score {_score_text(score_with)}; ")
        if without_set is None:
            text += f"{word} {target} cannot be reached without this check."
        else:
            text += (f"every way to reach {word} {target} with {len(with_set)} fixes includes this check, and "
                     f"without it {word} {target} takes {len(without_set)} fixes ({_id_list(without_set)}).")
    elif effect == EFFECT_ONE_OF:
        text = (f"{intro} {own} {word.capitalize()} {target} takes at least {len(with_set)} fixes, and this check "
                f"can be one of them: together with {together}, it takes {title} to {word} {level_with} "
                f"({labels[level_with - 1]}), score {_score_text(score_with)}. Other sets of {len(with_set)} fixes "
                f"reach {word} {target} without this check, for example {_id_list(without_set)} (score "
                f"{_score_text(score_without)}).")
    else:
        text = (f"{intro} {own} {word.capitalize()} {target} does not need this check: fixing "
                f"{_id_list(without_set)} reaches it (score {_score_text(score_without)}). Together with "
                f"{together}, this check gives {_score_text(score_with)}.")
    return NextLevelHint(text=text, **hint)


# ------------------------------------------------------------------ legend
# Ordered highest-severity first, to drive both the sort tiebreak display and
# the legend's severity scale.
_RISK_LEGEND = [
    ("CRITICAL", "HIGH+HIGH FAIR rating -- fix immediately, ahead of everything else below it"),
    ("HIGH",     "HIGH+MEDIUM or MEDIUM+HIGH -- fix in the current remediation cycle"),
    ("MODERATE", "MEDIUM+MEDIUM, LOW+HIGH, or HIGH+LOW -- schedule into the normal backlog"),
    ("LOW",      "LOW+LOW, LOW+MEDIUM, or MEDIUM+LOW -- track, but not urgent"),
    ("UNRATED",  "no CIS IG/FAIR metadata on file for this check_id -- rate it manually"),
]

_ORDER_TEXT = ("Findings first (FAIL, PARTIAL), then missing-data entries (ERROR, or an input not supplied); "
               "within each: risk rating, then CIS IG, then check id. Work top to bottom.")
_EMPTY_TEXT = "No FAIL, PARTIAL or missing-data checks -- nothing to remediate."
_ENTRY_TYPE_LINES = [
    ("finding", "FAIL or PARTIAL: the control is missing or incomplete."),
    ("missing data", "ERROR (the data the check reads cannot be read), or NOT_APPLICABLE only because an "
                     "organizational input (the attestation or inventory record, or one of its entries) was not "
                     "supplied. The entry says what is missing and how to supply it. Its ratings are those the "
                     "check would carry if the control turned out to be absent."),
]
_NO_ENTRY_TEXT = ("Checks that do not apply, checks excluded by the config and NOT_IMPLEMENTED checks get no "
                  "entry; a check whose control is missing is a FAIL finding.")
_SP800_30_TITLE = ("NIST SP 800-30 Rev. 1 risk factors and the resulting risk, plus a recommended response: this "
                   "register's own fields arranged in SP 800-30's terms; not an SP 800-30 risk assessment.")
_SP800_30_LINES = [
    ("threat source type", "the SP 800-30 Appendix D type of source most likely to exploit or trigger a failure "
                           "of the check (adversarial, accidental, structural or environmental); a judgment per "
                           "check, not an analysis of this organization's threats"),
    ("threat event", "a short, generic event per check, not threat intelligence"),
    ("vulnerability", "the finding (for missing data: not determined)"),
    ("likelihood", "the FAIR frequency band (3 levels, not SP 800-30's 5-level scale; not derived through SP "
                   "800-30's tables or from this device's exposure)"),
    ("impact", "the FAIR magnitude band (same caveat)"),
    ("risk", "this register's risk rating (its own 3x3 matrix, not SP 800-30's table); for missing data, the "
             "rating if the control is absent"),
    ("response", "the recommended mitigation step (for missing data: supply the data, then the fix); choosing a "
                 "response (accept, avoid, mitigate, share or transfer, as in NIST SP 800-39) stays the "
                 "organization's decision"),
]
_QUALITATIVE_TEXT = "Qualitative throughout: no quantitative (FAIR/Monte Carlo) estimate."
_STAND_IN_TEXT = ("The FAIR bands were rated for how often adversaries exploit the failure in the wild; on an "
                  "accidental, structural or environmental row they stand in for likelihood and impact and were "
                  "not rated for that threat source.")
_DRAFTED_TEXT = ("(drafted) marks a threat source type and event drafted for the researcher's "
                 "review and not yet confirmed (docs/sp800-30-review.md).")
_LEVELS_CAVEAT = ("Levels and stages are this tool's score bands under CMMI or CISA ZTMM names "
                  "(docs/methodology.md section 7), not a CMMI appraisal or a CISA assessment; the top band "
                  "(CMMI level 5, CISA ZTMM stage 4) reflects one snapshot scoring 90 or more, not sustained "
                  "improvement.")


def _next_level_legend(methodology: Optional[str]) -> str:
    if methodology is None:
        return "Next level: not shown (no maturity lens: --methodology none)."
    display, word = _words(methodology)
    return (f"Next level ({display}): the property's {word} now and what fixing this check does toward the next "
            f"{word}: on its own, or together with the fewest other open entries in the property (largest score "
            f"gain first), and whether every fewest set of fixes includes this check, only some do (it is one of "
            f"several interchangeable fixes), or none does. A fix means the check re-tests as PASS and nothing "
            f"else changes. A check that is not scored (missing input) gets no estimate, only whether its result "
            f"can change the {word}, and the overall {word} gets no hint. " + _LEVELS_CAVEAT)


def _wrap(text: str, width: int, indent: str) -> List[str]:
    """Greedy word wrap for the text legend (no word is ever split)."""
    lines, line = [], ""
    for word in text.split():
        if line and len(indent) + len(line) + 1 + len(word) > width:
            lines.append(indent + line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        lines.append(indent + line)
    return lines


def _legend_flags(entries: Sequence[RiskEntry]) -> Tuple[bool, bool]:
    """(any drafted threat fields, any non-adversarial threat source)."""
    drafted = any(e.sp800_30 is not None and e.sp800_30.review == "drafted" for e in entries)
    stand_in = any(e.sp800_30 is not None and e.sp800_30.threat_source_type not in (None, "adversarial")
                   for e in entries)
    return drafted, stand_in


def _legend_lines(entries: Sequence[RiskEntry], methodology: Optional[str]) -> List[str]:
    lines = [
        "  LEGEND",
        "  " + "-" * 62,
        "  CIS IG (CIS Controls v8 Implementation Group -- who is expected to have",
        "  this control in place):",
        "    IG1  basic cyber hygiene, expected of every organization",
        "    IG2  requires more organizational maturity (centralized tooling,",
        "         scheduled processes, identity integration)",
        "    IG3  controls for organizations facing sophisticated/targeted threats",
        "  FAIR (Factor Analysis of Information Risk, simplified/qualitative here,",
        "  not quantitative FAIR/Monte Carlo):",
        "    frequency  how often this failure mode is actually exploited in the wild",
        "    magnitude  the blast radius if it is",
        "    both are banded LOW / MEDIUM / HIGH and combined into a risk rating below",
        "  Risk rating (frequency x magnitude, from the matrix in this module):",
    ]
    for rating, meaning in _RISK_LEGEND:
        lines.append(f"    {rating:8s} {meaning}.")
    lines.append("  Entries:")
    for label, meaning in _ENTRY_TYPE_LINES:
        wrapped = _wrap(meaning, 78, " " * 18)
        lines.append(f"    {label:13s} " + wrapped[0].strip())
        lines.extend(wrapped[1:])
    lines.extend(_wrap(_NO_ENTRY_TEXT, 78, "    "))
    lines.extend(_wrap(_SP800_30_TITLE, 78, "  "))
    for label, meaning in _SP800_30_LINES:
        wrapped = _wrap(meaning, 78, " " * 24)
        lines.append(f"    {label:19s} " + wrapped[0].strip())
        lines.extend(wrapped[1:])
    lines.extend(_wrap(_QUALITATIVE_TEXT, 78, "    "))
    drafted, stand_in = _legend_flags(entries)
    if stand_in:
        lines.extend(_wrap(_STAND_IN_TEXT, 78, "    "))
    if drafted:
        lines.extend(_wrap(_DRAFTED_TEXT, 78, "    "))
    lines.extend(_wrap(_next_level_legend(methodology), 78, "  "))
    return lines


def _legend_markdown(entries: Sequence[RiskEntry], methodology: Optional[str]) -> List[str]:
    drafted, stand_in = _legend_flags(entries)
    sp_items = "; ".join(f"*{label}* = {meaning}" for label, meaning in _SP800_30_LINES)
    md = [
        "**Legend**",
        "",
        "- **CIS IG** (CIS Controls v8 Implementation Group -- who is expected to "
        "have this control in place): `IG1` basic cyber hygiene, expected of every "
        "organization; `IG2` requires more organizational maturity (centralized "
        "tooling, scheduled processes, identity integration); `IG3` controls for "
        "organizations facing sophisticated/targeted threats.",
        "- **FAIR** (Factor Analysis of Information Risk, simplified/qualitative "
        "here, not quantitative FAIR/Monte Carlo): *frequency* = how often this "
        "failure mode is actually exploited in the wild; *magnitude* = the blast "
        "radius if it is. Both are banded LOW/MEDIUM/HIGH.",
        "- **Risk rating** (frequency x magnitude, via the matrix in "
        "`miccmac/risk_register.py`): " + "; ".join(f"`{r}` {m}" for r, m in _RISK_LEGEND) + ".",
        "- **Entries:** " + "; ".join(f"*{label}* = {meaning.rstrip('.')}" for label, meaning in _ENTRY_TYPE_LINES)
        + ". " + _NO_ENTRY_TEXT,
        f"- **{_SP800_30_TITLE}** {sp_items}. {_QUALITATIVE_TEXT}"
        + (f" {_STAND_IN_TEXT}" if stand_in else "") + (f" {_DRAFTED_TEXT}" if drafted else ""),
        "- **" + _next_level_legend(methodology).replace(": ", ":** ", 1),
        "",
    ]
    return md


# ------------------------------------------------------------------ rendering
def _methodology_of(entries: Sequence[RiskEntry]) -> Optional[str]:
    for entry in entries:
        if entry.next_level is not None:
            return entry.next_level.methodology
    return None


def _not_evaluated_text(count: int) -> str:
    return (f"Not evaluated: {count} check(s) are NOT_IMPLEMENTED (no facts or inputs reached them, or a custom "
            f"check is a placeholder); they have no register entry.")


def _threat_source(entry: RiskEntry) -> str:
    sp = entry.sp800_30
    if sp is None or sp.threat_source_type is None:
        return _NOT_DECLARED
    return sp.threat_source_type + (" (drafted)" if sp.review == "drafted" else "")


def _threat_event(entry: RiskEntry) -> str:
    sp = entry.sp800_30
    return sp.threat_event if sp is not None and sp.threat_event else _NOT_DECLARED


def _fair(value: Optional[str]) -> str:
    return value or "n/a"


def _text_entry(number: int, e: RiskEntry) -> List[str]:
    pad = " " * 13
    lines = ["", f"  #{number} [{e.risk_rating:8s}] {e.check_id}  {e.name}"]
    status = e.status.value + (" (missing data)" if e.entry_type == MISSING_DATA else "")
    lines.append(f"{pad}Status: {status}   CIS IG: {e.cis_ig or 'n/a'}   "
                 f"FAIR: {_fair(e.fair_frequency)}/{_fair(e.fair_magnitude)}")
    if e.entry_type == FINDING:
        if e.detail:
            lines.append(f"{pad}{e.detail}")
        lines.append(f"{pad}Recommended fix: {e.remediation or 'n/a -- no remediation on file for this check_id.'}")
    else:
        lines.append(f"{pad}Missing: {e.missing_data.what}")
        lines.append(f"{pad}How to supply it: {e.missing_data.how_to_supply}")
        if e.remediation:
            lines.append(f"{pad}If the check then fails: {e.remediation}")
    if e.next_level is not None:
        lines.append(f"{pad}Next level: {e.next_level.text}")
    lines.append(f"{pad}SP 800-30: threat source type {_threat_source(e)}; threat event: {_threat_event(e)}")
    if e.entry_type == FINDING:
        tail = (f"vulnerability: the finding above; likelihood {_fair(e.fair_frequency)}, impact "
                f"{_fair(e.fair_magnitude)}, risk {e.risk_rating}; response: the recommended fix above.")
    else:
        tail = (f"vulnerability: not determined (missing data); likelihood {_fair(e.fair_frequency)}, impact "
                f"{_fair(e.fair_magnitude)}, risk {e.risk_rating} if the control is absent; response: supply "
                f"the data first (above).")
    lines.append(f"{pad}           {tail}")
    return lines


def to_text(entries: List[RiskEntry], not_evaluated: int = 0, methodology: Optional[str] = None) -> str:
    methodology = methodology or _methodology_of(entries)
    lines = ["=" * 64, "  MICCMAC RISK REGISTER (structured after NIST SP 800-30 Rev. 1;",
             "  CIS IG + FAIR-inspired rating)", "=" * 64]
    lines.extend(_legend_lines(entries, methodology))
    lines.append("=" * 64)
    if not entries:
        lines.append("  " + _EMPTY_TEXT)
        if not_evaluated:
            lines.extend(_wrap(_not_evaluated_text(not_evaluated), 78, "  "))
        lines.append("=" * 64)
        return "\n".join(lines)
    lines.extend(_wrap(_ORDER_TEXT, 78, "  "))
    if not_evaluated:
        lines.extend(_wrap(_not_evaluated_text(not_evaluated), 78, "  "))
    for number, (heading, kind) in ((1, ("  FINDINGS (FAIL, PARTIAL)", FINDING)),
                                    (2, ("  MISSING DATA (ratings apply if the control turns out to be absent)",
                                         MISSING_DATA))):
        group = [(n, e) for n, e in enumerate(entries, start=1) if e.entry_type == kind]
        if not group:
            continue
        lines.append("")
        lines.append(heading)
        for entry_no, entry in group:
            lines.extend(_text_entry(entry_no, entry))
    lines.append("")
    lines.append("=" * 64)
    return "\n".join(lines)


def _md_cell(value: object) -> str:
    """A markdown table cell: | escaped, line breaks as spaces."""
    text = "" if value is None else str(value)
    return " ".join(text.split("\n")).replace("\r", " ").replace("|", "\\|")


def to_markdown(entries: List[RiskEntry], not_evaluated: int = 0, methodology: Optional[str] = None) -> str:
    methodology = methodology or _methodology_of(entries)
    md = ["## Risk Register (structured after NIST SP 800-30 Rev. 1; CIS IG + FAIR-inspired rating)\n"]
    md.extend(_legend_markdown(entries, methodology))
    note = [_not_evaluated_text(not_evaluated) + "\n"] if not_evaluated else []
    if not entries:
        md.append(_EMPTY_TEXT + "\n")
        md.extend(note)
        return "\n".join(md)
    md.append(_ORDER_TEXT + "\n")
    md.extend(note)
    level_header = None if methodology is None else f"Next level ({_words(methodology)[0]})"
    numbered = list(enumerate(entries, start=1))
    findings = [(n, e) for n, e in numbered if e.entry_type == FINDING]
    missing = [(n, e) for n, e in numbered if e.entry_type == MISSING_DATA]
    if findings:
        md.append("### Findings (FAIL, PARTIAL)\n")
        header = ["#", "Risk", "Check", "Name", "Status", "CIS IG", "Threat source type", "Threat event",
                  "Vulnerability (finding)", "Likelihood (FAIR freq.)", "Impact (FAIR mag.)", "Recommended fix"]
        md.extend(_md_table(header, level_header, [
            ([n, e.risk_rating, e.check_id, e.name, e.status.value, e.cis_ig or "n/a", _threat_source(e),
              _threat_event(e), e.detail, _fair(e.fair_frequency), _fair(e.fair_magnitude), e.remediation or "n/a"],
             e) for n, e in findings]))
    if missing:
        md.append("### Missing data\n")
        header = ["#", "Risk if absent", "Check", "Name", "Status", "CIS IG", "Threat source type", "Threat event",
                  "What is missing", "Likelihood (FAIR freq.)", "Impact (FAIR mag.)",
                  "How to supply it (then the fix)"]
        md.extend(_md_table(header, level_header, [
            ([n, e.risk_rating, e.check_id, e.name, e.status.value, e.cis_ig or "n/a", _threat_source(e),
              _threat_event(e), e.missing_data.what, _fair(e.fair_frequency), _fair(e.fair_magnitude),
              e.response or "n/a"], e) for n, e in missing]))
    return "\n".join(md)


def _md_table(header: List[str], level_header: Optional[str], rows) -> List[str]:
    columns = header + ([level_header] if level_header else [])
    out = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for cells, entry in rows:
        if level_header:
            cells = cells + [entry.next_level.text if entry.next_level is not None else ""]
        out.append("| " + " | ".join(_md_cell(c) for c in cells) + " |")
    out.append("")
    return out


def to_json(entries: List[RiskEntry]) -> str:
    return json.dumps([e.to_dict() for e in entries], indent=2)


def render(entries: List[RiskEntry], fmt: str = "text", not_evaluated: int = 0,
           methodology: Optional[str] = None) -> str:
    """The register as text, markdown or JSON (a list of to_dict()).
    ``not_evaluated`` (not_evaluated_count) adds the "Not evaluated" line to
    text and markdown; ``methodology`` names the lens for the legend (default:
    the one the entries' hints name; none when they have no hint)."""
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return to_json(entries)
    if fmt in ("md", "markdown"):
        return to_markdown(entries, not_evaluated, methodology)
    return to_text(entries, not_evaluated, methodology)
