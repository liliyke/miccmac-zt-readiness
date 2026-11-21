"""Core data model for the MICCMAC readiness toolkit.

Assessment.provenance holds the run provenance block (tool build, inputs,
facts and the --as-of reference date) that the CLI sets for --connector,
--facts, --as-of and --save-facts runs. MissingData, in
CheckResult.missing_data, is the marker a check sets when it cannot be
evaluated because the data it reads is missing or unreadable (the risk
register's missing-data entries).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Status(str, Enum):
    """Outcome of a single check."""
    PASS = "PASS"                      # control fully satisfied
    PARTIAL = "PARTIAL"                # control partially satisfied
    FAIL = "FAIL"                      # control not satisfied
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"  # check logic not yet written (scaffold default)
    NOT_APPLICABLE = "NOT_APPLICABLE"  # check does not apply to this device
    ERROR = "ERROR"                    # check could not be evaluated


# Numeric weight used when scoring a property. NOT_IMPLEMENTED / NOT_APPLICABLE
# are excluded from scoring entirely (see engine.score_property).
SCORE_MAP = {
    Status.PASS: 100.0,
    Status.PARTIAL: 50.0,
    Status.FAIL: 0.0,
    Status.ERROR: 0.0,
}

# Where the data a check reads comes from (MissingData.source), and what is
# wrong with it (MissingData.problem):
#   not-supplied   the whole input was not given (no --attestation or
#                  --inventory-record option)
#   missing-field  the input was given but has no entry for this check
#   invalid-value  the value is there but cannot be read
# "facts" has no not-supplied case: without facts every device check keeps
# its NOT_IMPLEMENTED placeholder instead.
MISSING_DATA_SOURCES = ("attestation", "inventory_record", "facts")
MISSING_DATA_PROBLEMS = ("not-supplied", "missing-field", "invalid-value")
_MISSING_DATA_COMBINATIONS = frozenset(
    (source, problem) for source in MISSING_DATA_SOURCES for problem in MISSING_DATA_PROBLEMS
    if (source, problem) != ("facts", "not-supplied")
)


@dataclass(frozen=True)
class MissingData:
    """Why a check could not be evaluated from the data it reads. Set by the
    check, in the branch that returns NOT_APPLICABLE for an input that was
    not supplied or ERROR for a value that cannot be read; read by the risk
    register, which turns it into a missing-data entry. ``field`` is the
    dotted path of the value read (None: the whole input); ``expected`` shows
    what valid data looks like for ``field`` (or for the whole input)."""
    source: str
    problem: str
    field: Optional[str] = None
    expected: str = ""

    def __post_init__(self):
        if self.source not in MISSING_DATA_SOURCES:
            raise ValueError(f"MissingData.source must be one of {MISSING_DATA_SOURCES}, got {self.source!r}")
        if self.problem not in MISSING_DATA_PROBLEMS:
            raise ValueError(f"MissingData.problem must be one of {MISSING_DATA_PROBLEMS}, got {self.problem!r}")
        if (self.source, self.problem) not in _MISSING_DATA_COMBINATIONS:
            raise ValueError(f"MissingData: {self.source} cannot be {self.problem} (without facts the device "
                             f"checks keep their NOT_IMPLEMENTED placeholder)")
        if self.field is not None and (not isinstance(self.field, str) or not self.field.strip()):
            raise ValueError("MissingData.field must be a non-empty string or None")
        if not isinstance(self.expected, str):
            raise ValueError("MissingData.expected must be a string")

    def to_dict(self) -> dict:
        return {"source": self.source, "problem": self.problem, "field": self.field,
                "expected": self.expected}


# The seven MICCMAC properties, fixed. Used to validate custom-check ATTACH_TO
# values and to guard against ever growing an eighth property.
PROPERTY_KEYS = (
    "monitored", "inventoried", "controlled", "claimed",
    "minimized", "assessed", "current",
)


@dataclass
class CheckResult:
    """Result of evaluating one check within a MICCMAC property."""
    check_id: str
    name: str
    status: Status = Status.NOT_IMPLEMENTED
    detail: str = ""
    evidence: str = ""
    control_refs: List[str] = field(default_factory=list)
    # Set only when the check could not be evaluated because the data it reads
    # is missing or unreadable (see MissingData); the engine clears it on
    # excluded checks and on any status other than NOT_APPLICABLE or ERROR.
    missing_data: Optional[MissingData] = None

    def to_dict(self) -> dict:
        d = {
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "control_refs": self.control_refs,
        }
        # Only when set, so every other check (and a stub run's whole JSON) is
        # exactly as before the marker existed.
        if isinstance(self.missing_data, MissingData):
            d["missing_data"] = self.missing_data.to_dict()
        return d


@dataclass
class PropertyResult:
    """Aggregated result for one MICCMAC property (e.g. Monitored)."""
    key: str               # e.g. "monitored"
    letter: str            # e.g. "M"
    title: str             # e.g. "Monitored"
    checks: List[CheckResult] = field(default_factory=list)
    score: Optional[float] = None   # 0-100, or None if nothing scorable

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "letter": self.letter,
            "title": self.title,
            "score": self.score,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class Assessment:
    """Full MICCMAC assessment for a single device/target."""
    target: str
    properties: List[PropertyResult] = field(default_factory=list)
    overall_score: Optional[float] = None
    readiness_tier: str = "Unassessed"
    # A methodology.MethodologyResult when a maturity lens was applied (the CLI
    # applies CMMI unless --methodology names another or none); None otherwise.
    methodology: Optional[object] = None
    # check_ids dropped by user configuration (miccmac.config.Config.excluded_checks).
    excluded_check_ids: List[str] = field(default_factory=list)
    # Where this result came from (tool build, inputs, facts, reference
    # date), set by the CLI when --connector, --facts, --as-of or
    # --save-facts is used. See miccmac/provenance.py.
    provenance: Optional[dict] = None

    def to_dict(self) -> dict:
        d = {
            "target": self.target,
            "overall_score": self.overall_score,
            "readiness_tier": self.readiness_tier,
            "properties": [p.to_dict() for p in self.properties],
        }
        if self.methodology is not None:
            d["methodology"] = self.methodology.to_dict()
        if self.excluded_check_ids:
            d["excluded_check_ids"] = list(self.excluded_check_ids)
        if self.provenance is not None:
            d["provenance"] = dict(self.provenance)
        return d
