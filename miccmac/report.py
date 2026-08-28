"""Render an Assessment as text, markdown, or JSON."""
from __future__ import annotations

import json

from miccmac.engine import READINESS_TIERS
from miccmac.methodology import FULL_NAMES as METHODOLOGY_FULL_NAMES
from miccmac.methodology import REGISTRY as METHODOLOGY_REGISTRY
from miccmac.model import Assessment, Status

_STATUS_GLYPH = {
    Status.PASS: "[PASS]",
    Status.PARTIAL: "[PART]",
    Status.FAIL: "[FAIL]",
    Status.NOT_IMPLEMENTED: "[TODO]",
    Status.NOT_APPLICABLE: "[ N/A]",
    Status.ERROR: "[ ERR]",
}

_STATUS_MEANING = [
    ("[PASS]", "control fully satisfied"),
    ("[PART]", "control partially satisfied"),
    ("[FAIL]", "control not satisfied"),
    ("[TODO]", "check logic not yet implemented"),
    ("[ N/A]", "excluded by config, or not applicable to this device"),
    ("[ ERR]", "check could not be evaluated (e.g. data source unreachable)"),
]

# M-I-C-C-M-A-C: the seven MICCMAC properties, in framework order.
_PROPERTY_LETTERS = [
    ("M", "Monitored"), ("I", "Inventoried"), ("C", "Controlled"), ("C", "Claimed"),
    ("M", "Minimized"), ("A", "Assessed"), ("C", "Current"),
]


def _fmt_score(score) -> str:
    return "n/a" if score is None else f"{score:.1f}/100"


def _fmt_level(level_result) -> str:
    """Format a methodology.LevelResult for display, e.g.
    'Level 4 - Quantitatively Managed (75.0%)' or 'Unassessed'."""
    if level_result is None or level_result.level is None:
        return level_result.level_label if level_result else "Unassessed"
    return f"Level {level_result.level}/{level_result.max_level} - {level_result.level_label} ({level_result.percentage:.1f}%)"


def _tier_ranges():
    """[(range_str, label), ...] for READINESS_TIERS, highest first, e.g.
    ('90-100', 'Zero Trust Ready')."""
    ranges = []
    for i, (threshold, label) in enumerate(READINESS_TIERS):
        upper = "100" if i == 0 else str(int(READINESS_TIERS[i - 1][0]) - 1)
        ranges.append((f"{int(threshold)}-{upper}", label))
    return ranges


def _level_ranges(methodology):
    """[(range_str, 'Level N label'), ...] for a methodology instance, lowest
    first, derived from its real .levels/.cutoffs rather than a hardcoded copy."""
    cutoffs = methodology.cutoffs
    ranges = []
    for i, label in enumerate(methodology.levels):
        level = i + 1
        lower = "0" if level == 1 else str(int(cutoffs[level - 2]))
        upper = "100" if level == len(methodology.levels) else str(int(cutoffs[level - 1]) - 1)
        ranges.append((f"{lower}-{upper}", f"Level {level} {label}"))
    return ranges


def _legend_lines(assessment: Assessment):
    lines = [
        "  LEGEND",
        "  " + "-" * 62,
        "  MICCMAC properties (framework name spelled out by the property order):",
        "    " + "   ".join(f"{letter} {name}" for letter, name in _PROPERTY_LETTERS),
        "  Check status:",
    ]
    for glyph, meaning in _STATUS_MEANING:
        lines.append(f"    {glyph} {meaning}")
    lines.append("  Overall score -> readiness tier (always computed; thresholds are tunable):")
    for rng, label in _tier_ranges():
        lines.append(f"    {rng:7s} {label}")
    if assessment.methodology is not None:
        methodology = METHODOLOGY_REGISTRY[assessment.methodology.name]
        full_name = METHODOLOGY_FULL_NAMES.get(methodology.name, methodology.name.upper())
        lines.append(f"  {methodology.name.upper()} ({full_name}) maturity levels, shown")
        lines.append("  alongside the readiness tier above, not instead of it:")
        for rng, label in _level_ranges(methodology):
            lines.append(f"    {rng:7s} {label}")
    return lines


def _legend_markdown(assessment: Assessment):
    md = ["**Legend**", ""]
    md.append(
        "- **MICCMAC properties** (framework name spelled out by the property "
        "order): " + ", ".join(f"**{letter}** {name}" for letter, name in _PROPERTY_LETTERS) + "."
    )
    md.append(
        "- **Check status:** " + "; ".join(f"`{g}` {m}" for g, m in _STATUS_MEANING) + "."
    )
    tier_str = "; ".join(f"`{rng}` {label}" for rng, label in _tier_ranges())
    md.append(
        "- **Overall score -> readiness tier** (always computed; thresholds are "
        f"tunable): {tier_str}."
    )
    if assessment.methodology is not None:
        methodology = METHODOLOGY_REGISTRY[assessment.methodology.name]
        full_name = METHODOLOGY_FULL_NAMES.get(methodology.name, methodology.name.upper())
        level_str = "; ".join(f"`{rng}` {label}" for rng, label in _level_ranges(methodology))
        md.append(
            f"- **{methodology.name.upper()}** ({full_name}) **maturity levels**, "
            f"shown alongside the readiness tier above, not instead of it: {level_str}."
        )
    md.append("")
    return md


def to_json(assessment: Assessment) -> str:
    return json.dumps(assessment.to_dict(), indent=2)


def to_text(assessment: Assessment) -> str:
    lines = []
    lines.append("=" * 64)
    lines.append("  MICCMAC ZERO TRUST DEVICE READINESS ASSESSMENT")
    lines.append("=" * 64)
    lines.append(f"  Target          : {assessment.target}")
    lines.append(f"  Overall score   : {_fmt_score(assessment.overall_score)}")
    lines.append(f"  Readiness tier  : {assessment.readiness_tier}")
    if assessment.methodology is not None:
        lines.append(f"  {assessment.methodology.name.upper():<16}: {_fmt_level(assessment.methodology.overall)}")
    lines.append("=" * 64)
    for prop in assessment.properties:
        lines.append("")
        level_suffix = ""
        if assessment.methodology is not None:
            level_result = assessment.methodology.properties.get(prop.key)
            level_suffix = f"  [{assessment.methodology.name.upper()}: {_fmt_level(level_result)}]"
        lines.append(f"  {prop.letter}  {prop.title}  ({_fmt_score(prop.score)}){level_suffix}")
        lines.append("  " + "-" * 60)
        for c in prop.checks:
            glyph = _STATUS_GLYPH.get(c.status, "[ ?? ]")
            lines.append(f"   {glyph} {c.check_id}  {c.name}")
            if c.detail:
                lines.append(f"          {c.detail}")
    lines.append("")
    lines.append("=" * 64)
    todo = sum(
        1 for p in assessment.properties for c in p.checks
        if c.status is Status.NOT_IMPLEMENTED
    )
    if todo:
        lines.append(f"  NOTE: {todo} check(s) await implementation. See miccmac/checks/.")
        lines.append("=" * 64)
    lines.append("")
    lines.extend(_legend_lines(assessment))
    lines.append("=" * 64)
    return "\n".join(lines)


def to_markdown(assessment: Assessment) -> str:
    md = []
    md.append("# MICCMAC Zero Trust Device Readiness Assessment\n")
    md.append(f"- **Target:** {assessment.target}")
    md.append(f"- **Overall score:** {_fmt_score(assessment.overall_score)}")
    md.append(f"- **Readiness tier:** {assessment.readiness_tier}")
    if assessment.methodology is not None:
        md.append(f"- **{assessment.methodology.name.upper()}:** {_fmt_level(assessment.methodology.overall)}")
    md.append("")
    for prop in assessment.properties:
        level_suffix = ""
        if assessment.methodology is not None:
            level_result = assessment.methodology.properties.get(prop.key)
            level_suffix = f" &mdash; {assessment.methodology.name.upper()}: {_fmt_level(level_result)}"
        md.append(f"## {prop.letter} &mdash; {prop.title} ({_fmt_score(prop.score)}){level_suffix}\n")
        md.append("| Check | Name | Status | Detail |")
        md.append("|---|---|---|---|")
        for c in prop.checks:
            detail = c.detail.replace("|", "\\|") if c.detail else ""
            md.append(f"| {c.check_id} | {c.name} | {c.status.value} | {detail} |")
        md.append("")
    md.extend(_legend_markdown(assessment))
    return "\n".join(md)


def render(assessment: Assessment, fmt: str = "text") -> str:
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return to_json(assessment)
    if fmt in ("md", "markdown"):
        return to_markdown(assessment)
    return to_text(assessment)
