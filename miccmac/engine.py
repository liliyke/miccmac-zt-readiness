"""Assessment engine: runs property checks, scores them, builds the Assessment."""
from __future__ import annotations

from typing import List, Optional

from miccmac.model import Assessment, PropertyResult, Status, SCORE_MAP
from miccmac.checks import (
    monitored, inventoried, controlled, claimed,
    minimized, assessed, current,
)

# MICCMAC property order is meaningful: it spells the framework name.
PROPERTY_MODULES = [
    monitored, inventoried, controlled, claimed,
    minimized, assessed, current,
]

# Overall readiness tiers. Thresholds are intentionally simple and can be
# tuned in line with the methodology described in docs/methodology.md.
READINESS_TIERS = [
    (90.0, "Zero Trust Ready"),
    (70.0, "Defensible"),
    (40.0, "Developing"),
    (0.0,  "Not Ready"),
]


def score_property(prop: PropertyResult) -> Optional[float]:
    """Average score of all *scorable* checks (PASS/PARTIAL/FAIL/ERROR).

    NOT_IMPLEMENTED and NOT_APPLICABLE checks are excluded so that an
    incomplete scaffold does not produce a misleadingly low score.
    Returns None when nothing is scorable.
    """
    scorable = [c for c in prop.checks if c.status in SCORE_MAP]
    if not scorable:
        return None
    return round(sum(SCORE_MAP[c.status] for c in scorable) / len(scorable), 1)


def overall_score(properties: List[PropertyResult]) -> Optional[float]:
    """Mean of the property scores that could be computed."""
    scored = [p.score for p in properties if p.score is not None]
    if not scored:
        return None
    return round(sum(scored) / len(scored), 1)


def readiness_tier(score: Optional[float]) -> str:
    if score is None:
        return "Unassessed"
    for threshold, label in READINESS_TIERS:
        if score >= threshold:
            return label
    return "Not Ready"


def run_assessment(target: str, context: dict | None = None) -> Assessment:
    """Run every MICCMAC property check against ``target``.

    ``context`` is a free-form dict passed to each check module. Use it to
    supply connection details, collected device facts, API clients, etc.
    """
    context = context or {}
    assessment = Assessment(target=target)

    for module in PROPERTY_MODULES:
        prop: PropertyResult = module.evaluate(target, context)
        prop.score = score_property(prop)
        assessment.properties.append(prop)

    assessment.overall_score = overall_score(assessment.properties)
    assessment.readiness_tier = readiness_tier(assessment.overall_score)
    return assessment
