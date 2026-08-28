"""Risk register: joins FAIL/PARTIAL CheckResults with CIS Implementation
Group + FAIR-inspired risk metadata (from miccmac.metadata) and produces a
priority-sorted remediation list.

Pure function of (Assessment, metadata) -- no target/network dependency.

The risk rating is a 3x3 qualitative lookup table, not a numeric product:
LOW/MEDIUM/HIGH are ordinal, not interval, values, so multiplying them would
imply precision the underlying judgment doesn't have. This is the
"FAIR-inspired, simplified, qualitative" framing -- not quantitative
FAIR/Monte Carlo, which is out of scope.

Sort order: risk rating is the dominant key (fix CRITICALs before HIGHs
regardless of IG, since rating reflects actual measured exposure); CIS IG is
the tiebreaker within a rating band (an IG1 failure is more foundational --
expected of every organization -- than an IG2 failure at the same risk
level, so it's remediated first).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from miccmac.metadata import CheckMetadata, DEFAULT_MAPPINGS_PATH, load_check_metadata
from miccmac.model import Assessment, Status

RISK_MATRIX = {
    ("LOW", "LOW"): "LOW", ("LOW", "MEDIUM"): "LOW", ("LOW", "HIGH"): "MODERATE",
    ("MEDIUM", "LOW"): "LOW", ("MEDIUM", "MEDIUM"): "MODERATE", ("MEDIUM", "HIGH"): "HIGH",
    ("HIGH", "LOW"): "MODERATE", ("HIGH", "MEDIUM"): "HIGH", ("HIGH", "HIGH"): "CRITICAL",
}
_RISK_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "UNRATED": 0}
_IG_RANK = {"IG1": 1, "IG2": 2, "IG3": 3}
_RISK_STATUSES = (Status.FAIL, Status.PARTIAL)


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

    def to_dict(self) -> dict:
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
        }


def risk_rating(frequency: Optional[str], magnitude: Optional[str]) -> str:
    if frequency is None or magnitude is None:
        return "UNRATED"
    return RISK_MATRIX.get((frequency, magnitude), "UNRATED")


def build_risk_register(
    assessment: Assessment,
    metadata_path=DEFAULT_MAPPINGS_PATH,
    extra_metadata: Optional[Dict[str, CheckMetadata]] = None,
) -> List[RiskEntry]:
    """Collect every FAIL/PARTIAL check across assessment.properties, join by
    check_id against check-level CIS IG/FAIR metadata, sorted by
    (-risk_rank, ig_rank, check_id).

    ``extra_metadata`` (check_id -> CheckMetadata) supplies risk metadata for
    custom checks, declared via their RISK_METADATA attribute (see
    miccmac/config.py) -- merged over the built-in lookup so custom checks
    plug into the same prioritization instead of always sorting last as
    UNRATED. A check_id with no metadata at all (in neither source) still
    gets None fields and rating UNRATED, sorted last.

    Raises MappingsError if metadata_path itself is missing/malformed --
    that's a real configuration problem, not a per-check gap, so it should
    surface rather than silently degrade every entry to UNRATED."""
    metadata_by_id = dict(load_check_metadata(metadata_path))
    if extra_metadata:
        metadata_by_id.update(extra_metadata)

    entries: List[RiskEntry] = []
    for prop in assessment.properties:
        for check in prop.checks:
            if check.status not in _RISK_STATUSES:
                continue
            meta = metadata_by_id.get(check.check_id)
            frequency = meta.fair_frequency if meta else None
            magnitude = meta.fair_magnitude if meta else None
            ig = meta.cis_ig if meta else None
            remediation = meta.remediation if meta else None
            entries.append(RiskEntry(
                check_id=check.check_id,
                property_key=prop.key,
                name=check.name,
                status=check.status,
                cis_ig=ig,
                fair_frequency=frequency,
                fair_magnitude=magnitude,
                risk_rating=risk_rating(frequency, magnitude),
                detail=check.detail,
                remediation=remediation,
            ))

    entries.sort(key=lambda e: (
        -_RISK_RANK.get(e.risk_rating, 0),
        _IG_RANK.get(e.cis_ig, 99),
        e.check_id,
    ))
    return entries


# Ordered highest-severity first, to drive both the sort tiebreak display and
# the legend's severity scale.
_RISK_LEGEND = [
    ("CRITICAL", "HIGH+HIGH FAIR rating -- fix immediately, ahead of everything else below it"),
    ("HIGH",     "HIGH+MEDIUM or MEDIUM+HIGH -- fix in the current remediation cycle"),
    ("MODERATE", "MEDIUM+MEDIUM, LOW+HIGH, or HIGH+LOW -- schedule into the normal backlog"),
    ("LOW",      "LOW+LOW, LOW+MEDIUM, or MEDIUM+LOW -- track, but not urgent"),
    ("UNRATED",  "no CIS IG/FAIR metadata on file for this check_id -- rate it manually"),
]


def _legend_lines() -> List[str]:
    lines = [
        "  LEGEND",
        "  " + "-" * 62,
        "  CIS IG (CIS Controls v8 Implementation Group -- who is expected to have",
        "  this control in place):",
        "    IG1  basic cyber hygiene, expected of every organization",
        "    IG2  requires more organizational maturity (centralized tooling,",
        "         scheduled processes, identity integration)",
        "    IG3  reserved for controls facing sophisticated/targeted threats",
        "         (no built-in check is IG3; a custom check plugin may add one)",
        "  FAIR (Factor Analysis of Information Risk, simplified/qualitative here,",
        "  not quantitative FAIR/Monte Carlo):",
        "    frequency  how often this failure mode is actually exploited in the wild",
        "    magnitude  the blast radius if it is",
        "    both are banded LOW / MEDIUM / HIGH and combined into a risk rating below",
        "  Risk rating (frequency x magnitude, from the matrix in this module):",
    ]
    for rating, meaning in _RISK_LEGEND:
        lines.append(f"    {rating:8s} {meaning}.")
    return lines


def _legend_markdown() -> List[str]:
    md = [
        "**Legend**",
        "",
        "- **CIS IG** (CIS Controls v8 Implementation Group -- who is expected to "
        "have this control in place): `IG1` basic cyber hygiene, expected of every "
        "organization; `IG2` requires more organizational maturity (centralized "
        "tooling, scheduled processes, identity integration); `IG3` reserved for "
        "controls facing sophisticated/targeted threats (no built-in check is IG3; "
        "a custom check plugin may add one).",
        "- **FAIR** (Factor Analysis of Information Risk, simplified/qualitative "
        "here, not quantitative FAIR/Monte Carlo): *frequency* = how often this "
        "failure mode is actually exploited in the wild; *magnitude* = the blast "
        "radius if it is. Both are banded LOW/MEDIUM/HIGH.",
        "- **Risk rating** (frequency x magnitude, via the matrix in "
        "`miccmac/risk_register.py`): " + "; ".join(f"`{r}` {m}" for r, m in _RISK_LEGEND) + ".",
        "",
    ]
    return md


def to_text(entries: List[RiskEntry]) -> str:
    lines = ["=" * 64, "  MICCMAC RISK REGISTER (CIS IG + FAIR-inspired rating)", "=" * 64]
    lines.extend(_legend_lines())
    lines.append("=" * 64)
    if not entries:
        lines.append("  No FAIL/PARTIAL checks -- nothing to remediate.")
        lines.append("=" * 64)
        return "\n".join(lines)
    lines.append("  Sorted highest priority first -- work top to bottom as your")
    lines.append("  next course of action.")
    for e in entries:
        lines.append("")
        lines.append(f"  [{e.risk_rating:8s}] {e.check_id}  {e.name}")
        lines.append(f"             Status: {e.status.value}   CIS IG: {e.cis_ig or 'n/a'}   "
                      f"FAIR: {e.fair_frequency or 'n/a'}/{e.fair_magnitude or 'n/a'}")
        if e.detail:
            lines.append(f"             {e.detail}")
        lines.append(f"             Recommended fix: {e.remediation or 'n/a -- no remediation on file for this check_id.'}")
    lines.append("")
    lines.append("=" * 64)
    return "\n".join(lines)


def to_markdown(entries: List[RiskEntry]) -> str:
    md = ["## Risk Register (CIS IG + FAIR-inspired rating)\n"]
    md.extend(_legend_markdown())
    if not entries:
        md.append("No FAIL/PARTIAL checks -- nothing to remediate.\n")
        return "\n".join(md)
    md.append("Sorted highest priority first -- work top to bottom as your next course "
               "of action.\n")
    md.append("| Risk | Check | Name | Status | CIS IG | FAIR (freq/mag) | Detail | Recommended fix |")
    md.append("|---|---|---|---|---|---|---|---|")
    for e in entries:
        detail = e.detail.replace("|", "\\|") if e.detail else ""
        fix = (e.remediation or "n/a").replace("|", "\\|")
        md.append(
            f"| {e.risk_rating} | {e.check_id} | {e.name} | {e.status.value} | "
            f"{e.cis_ig or 'n/a'} | {e.fair_frequency or 'n/a'}/{e.fair_magnitude or 'n/a'} | {detail} | {fix} |"
        )
    md.append("")
    return "\n".join(md)


def to_json(entries: List[RiskEntry]) -> str:
    import json
    return json.dumps([e.to_dict() for e in entries], indent=2)


def render(entries: List[RiskEntry], fmt: str = "text") -> str:
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return to_json(entries)
    if fmt in ("md", "markdown"):
        return to_markdown(entries)
    return to_text(entries)
