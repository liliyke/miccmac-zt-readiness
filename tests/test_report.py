"""Tests for miccmac.report: text/markdown/json rendering, including the
methodology display fix (assessment.methodology was computed but never
shown outside --format json before this)."""
from miccmac.methodology import apply_methodology
from miccmac.model import Assessment, PropertyResult
from miccmac.report import to_json, to_markdown, to_text


def _assessment_with_methodology(score=75.0):
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=score)
    assessment = Assessment(target="x", properties=[prop], overall_score=score, readiness_tier="Defensible")
    assessment.methodology = apply_methodology(assessment, "cmmi")
    return assessment


def test_to_text_without_methodology_has_no_methodology_lines():
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=75.0)
    assessment = Assessment(target="x", properties=[prop], overall_score=75.0, readiness_tier="Defensible")
    out = to_text(assessment)
    assert "CMMI" not in out
    assert "cmmi" not in out.lower()


def test_to_text_with_methodology_shows_overall_and_per_property_level():
    assessment = _assessment_with_methodology()
    out = to_text(assessment)
    assert "CMMI" in out
    assert "Quantitatively Managed" in out
    # shown twice: once for overall, once for the Monitored property line
    assert out.count("Quantitatively Managed") == 2


def test_to_text_unassessed_methodology_shows_unassessed_not_level_1():
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=None)
    assessment = Assessment(target="x", properties=[prop])
    assessment.methodology = apply_methodology(assessment, "cmmi")
    out = to_text(assessment)
    assert "Unassessed" in out
    assert "Level 1" not in out


def test_to_markdown_with_methodology_shows_overall_and_per_property_level():
    assessment = _assessment_with_methodology()
    out = to_markdown(assessment)
    assert "**CMMI:**" in out
    assert "Quantitatively Managed" in out


def test_to_markdown_without_methodology_has_no_methodology_lines():
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=75.0)
    assessment = Assessment(target="x", properties=[prop], overall_score=75.0, readiness_tier="Defensible")
    out = to_markdown(assessment)
    assert "CMMI" not in out


def test_to_json_still_includes_methodology():
    """Confirm the JSON path (which already worked) is unaffected."""
    import json
    assessment = _assessment_with_methodology()
    data = json.loads(to_json(assessment))
    assert data["methodology"]["name"] == "cmmi"
