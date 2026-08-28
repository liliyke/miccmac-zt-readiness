"""Core data model for the MICCMAC readiness toolkit."""
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

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "control_refs": self.control_refs,
        }


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
    # Set only when a --methodology was requested; a methodology.MethodologyResult.
    methodology: Optional[object] = None
    # check_ids dropped by user configuration (miccmac.config.Config.excluded_checks).
    excluded_check_ids: List[str] = field(default_factory=list)

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
        return d
