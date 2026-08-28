"""Tests for miccmac.methodology: pluggable CMMI / CISA ZTMM scoring.
All tests construct Assessment/PropertyResult objects directly -- no target,
osquery, or network dependency."""
import pytest

from miccmac.methodology import (
    REGISTRY,
    CISAZTMMMethodology,
    CMMIMethodology,
    apply_methodology,
    get_methodology,
    level_to_percentage,
)
from miccmac.model import Assessment, PropertyResult


def test_level_to_percentage_zero_anchored():
    assert level_to_percentage(1, 5) == 0.0
    assert level_to_percentage(5, 5) == 100.0
    assert level_to_percentage(3, 5) == 50.0
    assert level_to_percentage(1, 4) == 0.0
    assert level_to_percentage(4, 4) == 100.0


def test_level_to_percentage_rejects_max_level_lt_2():
    with pytest.raises(ValueError):
        level_to_percentage(1, 1)


@pytest.mark.parametrize("score,expected_level,expected_label", [
    (0.0, 1, "Initial"),
    (19.9, 1, "Initial"),
    (20.0, 2, "Managed"),
    (39.9, 2, "Managed"),
    (40.0, 3, "Defined"),
    (69.9, 3, "Defined"),
    (70.0, 4, "Quantitatively Managed"),
    (89.9, 4, "Quantitatively Managed"),
    (90.0, 5, "Optimizing"),
    (100.0, 5, "Optimizing"),
])
def test_cmmi_thresholds(score, expected_level, expected_label):
    m = CMMIMethodology()
    result = m.score_overall(score)
    assert result.level == expected_level
    assert result.level_label == expected_label
    assert result.max_level == 5


@pytest.mark.parametrize("score,expected_level,expected_label", [
    (0.0, 1, "Traditional"),
    (39.9, 1, "Traditional"),
    (40.0, 2, "Initial"),
    (69.9, 2, "Initial"),
    (70.0, 3, "Advanced"),
    (89.9, 3, "Advanced"),
    (90.0, 4, "Optimal"),
    (100.0, 4, "Optimal"),
])
def test_cisa_thresholds(score, expected_level, expected_label):
    m = CISAZTMMMethodology()
    result = m.score_overall(score)
    assert result.level == expected_level
    assert result.level_label == expected_label
    assert result.max_level == 4


def test_none_score_is_unassessed_for_both_methodologies():
    for methodology in REGISTRY.values():
        result = methodology.score_overall(None)
        assert result.level is None
        assert result.level_label == "Unassessed"
        assert result.percentage is None


def test_apply_methodology_builds_overall_and_per_property_levels():
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=75.0)
    assessment = Assessment(target="x", properties=[prop], overall_score=75.0, readiness_tier="Defensible")
    result = apply_methodology(assessment, "cmmi")
    assert result.name == "cmmi"
    assert result.overall.level_label == "Quantitatively Managed"
    assert result.properties["monitored"].level_label == "Quantitatively Managed"
    # every canonical property key present even though only one was assessed
    assert set(result.properties) >= {"monitored"}


def test_apply_methodology_does_not_mutate_assessment():
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", score=50.0)
    assessment = Assessment(target="x", properties=[prop], overall_score=50.0)
    apply_methodology(assessment, "cisa-ztmm")
    assert assessment.methodology is None
    assert assessment.overall_score == 50.0


def test_get_methodology_unknown_name_raises_valueerror():
    with pytest.raises(ValueError, match="unknown methodology"):
        get_methodology("bogus")
