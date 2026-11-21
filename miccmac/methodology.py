"""Pluggable maturity-model scoring methodologies.

These re-bucket the *existing* flat 0-100 score (PropertyResult.score /
Assessment.overall_score) into an ordinal maturity level, rather than
re-deriving anything from raw check results. That keeps this module purely
additive: the flat score is always computed by miccmac.engine regardless of
whether a methodology was requested, and applying a methodology never changes
it.

CMMI and CISA ZTMM have different numbers of levels (5 vs 4), so they are
made comparable via a zero-anchored percentage conversion:

    percentage = (level - 1) / (max_level - 1) * 100

Both methodologies also reuse the tool's existing 20/40/70/90 breakpoints as
shared threshold anchors (CISA's 4 stages map 1:1 onto the default readiness
tiers; CMMI's 5th level bisects the bottom band at 20). That shared-anchor
design is what makes "comparable regardless of methodology" a defensible
claim rather than an arbitrary one.

The CLI applies CMMI unless --methodology says otherwise
(DEFAULT_METHODOLOGY), and --methodology none (NO_METHODOLOGY) applies no
methodology at all. engine.run_assessment itself still applies none unless
it is given a methodology name.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from miccmac.model import PROPERTY_KEYS, Assessment, PropertyResult

UNASSESSED_LABEL = "Unassessed"
# The lens `miccmac assess` applies when --methodology is not given.
DEFAULT_METHODOLOGY = "cmmi"
# `--methodology none`: no lens (flat score and readiness tier only). Never a
# REGISTRY key, so apply_methodology rejects it.
NO_METHODOLOGY = "none"


@dataclass(frozen=True)
class LevelResult:
    level: Optional[int]          # 1-indexed ordinal position, or None if unassessed
    level_label: str              # e.g. "Managed", or "Unassessed"
    max_level: int                # 5 for CMMI, 4 for CISA ZTMM
    percentage: Optional[float]   # zero-anchored, or None if unassessed

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "level_label": self.level_label,
            "max_level": self.max_level,
            "percentage": self.percentage,
        }


@dataclass(frozen=True)
class MethodologyResult:
    name: str
    overall: LevelResult
    properties: Dict[str, LevelResult] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "overall": self.overall.to_dict(),
            "properties": {key: lr.to_dict() for key, lr in self.properties.items()},
        }


def level_to_percentage(level: int, max_level: int) -> float:
    """Zero-anchored percentage: (level - 1) / (max_level - 1) * 100."""
    if max_level < 2:
        raise ValueError(f"max_level must be >= 2, got {max_level}")
    return round((level - 1) / (max_level - 1) * 100, 1)


def _bucket(score: Optional[float], cutoffs: List[float]) -> Optional[int]:
    """cutoffs: ascending minimum scores required for level 2..max_level.
    Returns a 1-indexed level, or None iff score is None."""
    if score is None:
        return None
    level = 1
    for cutoff in cutoffs:
        if score >= cutoff:
            level += 1
    return level


class _ThresholdMethodology:
    name: str = ""
    levels: List[str] = []
    _cutoffs: List[float] = []

    def level_for_score(self, score: Optional[float]) -> LevelResult:
        """The LevelResult a property or overall score gets under this
        methodology (Unassessed for None), exactly as score_property and
        score_overall report it."""
        return self._level_result(score)

    def min_score_for_level(self, level: int) -> float:
        """The lowest score that gets `level` (0.0 for level 1)."""
        if not 1 <= level <= len(self.levels):
            raise ValueError(f"{self.name} has levels 1-{len(self.levels)}, not {level}")
        return 0.0 if level == 1 else self._cutoffs[level - 2]

    def _level_result(self, score: Optional[float]) -> LevelResult:
        max_level = len(self.levels)
        level = _bucket(score, self._cutoffs)
        if level is None:
            return LevelResult(level=None, level_label=UNASSESSED_LABEL,
                                max_level=max_level, percentage=None)
        return LevelResult(
            level=level,
            level_label=self.levels[level - 1],
            max_level=max_level,
            percentage=level_to_percentage(level, max_level),
        )

    def score_property(self, prop: PropertyResult) -> LevelResult:
        return self._level_result(prop.score)

    def score_overall(self, overall_score: Optional[float]) -> LevelResult:
        return self._level_result(overall_score)

    @property
    def cutoffs(self) -> List[float]:
        """Ascending minimum scores required for level 2..max_level, exposed
        read-only so callers (e.g. report.py's scoring-chart legend) can
        display the real thresholds instead of hardcoding a second copy."""
        return list(self._cutoffs)


class CMMIMethodology(_ThresholdMethodology):
    name = "cmmi"
    levels = ["Initial", "Managed", "Defined", "Quantitatively Managed", "Optimizing"]
    _cutoffs = [20.0, 40.0, 70.0, 90.0]   # min score for level 2, 3, 4, 5


class CISAZTMMMethodology(_ThresholdMethodology):
    name = "cisa-ztmm"
    levels = ["Traditional", "Initial", "Advanced", "Optimal"]
    _cutoffs = [40.0, 70.0, 90.0]         # min score for level 2, 3, 4


REGISTRY: Dict[str, _ThresholdMethodology] = {
    "cmmi": CMMIMethodology(),
    "cisa-ztmm": CISAZTMMMethodology(),
}

# Full names for the acronyms, used by report.py's legend so the scorecard is
# readable without already knowing what "CMMI" or "CISA ZTMM" stand for.
FULL_NAMES: Dict[str, str] = {
    "cmmi": "Capability Maturity Model Integration",
    "cisa-ztmm": "CISA (Cybersecurity and Infrastructure Security Agency) Zero Trust Maturity Model",
}


# How running text names each methodology and its levels: (display name,
# level word). CISA's Zero Trust Maturity Model calls its levels stages. Used
# by the risk register's next-level hints and the study worksheets (whose
# wording these are).
LEVEL_WORDS: Dict[str, Tuple[str, str]] = {
    "cmmi": ("CMMI", "level"),
    "cisa-ztmm": ("CISA ZTMM", "stage"),
}


def get_methodology(name: str) -> _ThresholdMethodology:
    try:
        return REGISTRY[name]
    except KeyError:
        raise ValueError(
            f"unknown methodology {name!r}; must be one of {sorted(REGISTRY)}"
        ) from None


def apply_methodology(assessment: Assessment, methodology_name: str) -> MethodologyResult:
    """Build a MethodologyResult from assessment's already-computed flat scores.
    Pure function: does not mutate assessment."""
    methodology = get_methodology(methodology_name)
    properties = {}
    for prop in assessment.properties:
        properties[prop.key] = methodology.score_property(prop)
    # Guard against a partial/custom assessment missing a canonical property.
    for key in PROPERTY_KEYS:
        properties.setdefault(key, methodology._level_result(None))
    overall = methodology.score_overall(assessment.overall_score)
    return MethodologyResult(name=methodology.name, overall=overall, properties=properties)
