"""Render an Assessment as text, markdown, or JSON."""
from __future__ import annotations

import json

from miccmac.model import Assessment, Status

_STATUS_GLYPH = {
    Status.PASS: "[PASS]",
    Status.PARTIAL: "[PART]",
    Status.FAIL: "[FAIL]",
    Status.NOT_IMPLEMENTED: "[TODO]",
    Status.NOT_APPLICABLE: "[ N/A]",
    Status.ERROR: "[ ERR]",
}


def _fmt_score(score) -> str:
    return "n/a" if score is None else f"{score:.1f}/100"


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
    lines.append("=" * 64)
    for prop in assessment.properties:
        lines.append("")
        lines.append(f"  {prop.letter}  {prop.title}  ({_fmt_score(prop.score)})")
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
    return "\n".join(lines)


def to_markdown(assessment: Assessment) -> str:
    md = []
    md.append("# MICCMAC Zero Trust Device Readiness Assessment\n")
    md.append(f"- **Target:** {assessment.target}")
    md.append(f"- **Overall score:** {_fmt_score(assessment.overall_score)}")
    md.append(f"- **Readiness tier:** {assessment.readiness_tier}\n")
    for prop in assessment.properties:
        md.append(f"## {prop.letter} &mdash; {prop.title} ({_fmt_score(prop.score)})\n")
        md.append("| Check | Name | Status | Detail |")
        md.append("|---|---|---|---|")
        for c in prop.checks:
            detail = c.detail.replace("|", "\\|") if c.detail else ""
            md.append(f"| {c.check_id} | {c.name} | {c.status.value} | {detail} |")
        md.append("")
    return "\n".join(md)


def render(assessment: Assessment, fmt: str = "text") -> str:
    fmt = (fmt or "text").lower()
    if fmt == "json":
        return to_json(assessment)
    if fmt in ("md", "markdown"):
        return to_markdown(assessment)
    return to_text(assessment)
