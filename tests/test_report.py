"""Tests for miccmac.report: text/markdown/json rendering, including the
methodology display fix (assessment.methodology was computed but never
shown outside --format json before this).

In this file, AI assistance (Claude Code, Anthropic) covers
test_the_legend_explains_a_missing_input_only_when_a_check_lacks_one, drafted
for the researcher's review."""
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
    # shown three times: once for overall, once for the Monitored property
    # line, and once in the legend's static score->level chart.
    assert out.count("Quantitatively Managed") == 3


def test_to_text_unassessed_methodology_shows_unassessed_not_level_1():
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=None)
    assessment = Assessment(target="x", properties=[prop])
    assessment.methodology = apply_methodology(assessment, "cmmi")
    out = to_text(assessment)
    assert "Unassessed" in out
    # The legend's static score->level reference chart legitimately shows
    # "Level 1 Initial" -- what must never appear is the *actual* overall/
    # property result being formatted as if level 1 were assigned.
    assert "Level 1/" not in out


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


# The legend line for a NOT_APPLICABLE check that lacks an input.
def test_the_legend_explains_a_missing_input_only_when_a_check_lacks_one():
    from miccmac.engine import run_assessment

    facts = {"os": {"platform": "ubuntu"}, "system_info": {}, "deb_packages": []}
    with_gap = run_assessment("x", context={"facts": facts})
    assert any(c.missing_data for p in with_gap.properties for c in p.checks)
    line = "or not evaluated: an organizational input it reads was not supplied"
    assert line in to_text(with_gap) and line in to_markdown(with_gap)
    text = to_text(with_gap).splitlines()
    assert text[text.index("    [ N/A] excluded by config, or not applicable to this device") + 1].strip().startswith(
        "or not evaluated")
    stub = run_assessment("x")
    assert line not in to_text(stub) and line not in to_markdown(stub)


def test_cisa_ztmm_levels_are_shown_as_stages_and_cmmi_levels_as_levels():
    """Verifier finding (fix round; drafted with AI assistance for the
    researcher's review): a CISA ZTMM scorecard said 'Level 2/4' while the
    register's hints in the same output say 'CISA ZTMM stage 2'."""
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=50.0)
    assessment = Assessment(target="x", properties=[prop], overall_score=50.0, readiness_tier="Developing")
    assessment.methodology = apply_methodology(assessment, "cisa-ztmm")
    for out in (to_text(assessment), to_markdown(assessment)):
        assert "Stage 2/4 - Initial (33.3%)" in out and "Level 2/4" not in out
        assert "Stage 1 Traditional" in out and "Level 1 Traditional" not in out
        assert "maturity stages" in out
    assessment.methodology = apply_methodology(assessment, "cmmi")
    for out in (to_text(assessment), to_markdown(assessment)):
        assert "Level 3/5 - Defined (50.0%)" in out and "Stage" not in out
        assert "maturity levels" in out
