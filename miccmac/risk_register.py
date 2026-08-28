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
            ))

    entries.sort(key=lambda e: (
        -_RISK_RANK.get(e.risk_rating, 0),
        _IG_RANK.get(e.cis_ig, 99),
        e.check_id,
    ))
    return entries


def to_text(entries: List[RiskEntry]) -> str:
    lines = ["=" * 64, "  MICCMAC RISK REGISTER (CIS IG + FAIR-inspired rating)", "=" * 64]
    if not entries:
        lines.append("  No FAIL/PARTIAL checks -- nothing to remediate.")
        lines.append("=" * 64)
        return "\n".join(lines)
    for e in entries:
        lines.append("")
        lines.append(f"  [{e.risk_rating:8s}] {e.check_id}  {e.name}")
        lines.append(f"             Status: {e.status.value}   CIS IG: {e.cis_ig or 'n/a'}   "
                      f"FAIR: {e.fair_frequency or 'n/a'}/{e.fair_magnitude or 'n/a'}")
        if e.detail:
            lines.append(f"             {e.detail}")
    lines.append("")
    lines.append("=" * 64)
    return "\n".join(lines)


def to_markdown(entries: List[RiskEntry]) -> str:
    md = ["## Risk Register (CIS IG + FAIR-inspired rating)\n"]
    if not entries:
        md.append("No FAIL/PARTIAL checks -- nothing to remediate.\n")
        return "\n".join(md)
    md.append("| Risk | Check | Name | Status | CIS IG | FAIR (freq/mag) | Detail |")
    md.append("|---|---|---|---|---|---|---|")
    for e in entries:
        detail = e.detail.replace("|", "\\|") if e.detail else ""
        md.append(
            f"| {e.risk_rating} | {e.check_id} | {e.name} | {e.status.value} | "
            f"{e.cis_ig or 'n/a'} | {e.fair_frequency or 'n/a'}/{e.fair_magnitude or 'n/a'} | {detail} |"
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
