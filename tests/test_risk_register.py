"""Tests for miccmac.risk_register: joins FAIL/PARTIAL checks with CIS IG /
FAIR-inspired metadata and sorts by priority. All tests construct
Assessment/PropertyResult/CheckResult objects directly -- no target,
osquery, or network dependency."""
import pytest

from miccmac.metadata import MappingsError
from miccmac.model import Assessment, CheckResult, PropertyResult, Status
from miccmac.risk_register import build_risk_register, render, risk_rating


def _assessment(checks):
    prop = PropertyResult(key="monitored", letter="M", title="Monitored", checks=checks)
    return Assessment(target="x", properties=[prop])


def test_only_fail_and_partial_checks_are_included():
    checks = [
        CheckResult("MON-01", "a", Status.FAIL),
        CheckResult("MON-02", "b", Status.PARTIAL),
        CheckResult("MON-03", "c", Status.PASS),
        CheckResult("MON-04", "d", Status.NOT_IMPLEMENTED),
    ]
    entries = build_risk_register(_assessment(checks))
    assert {e.check_id for e in entries} == {"MON-01", "MON-02"}


def test_sort_order_highest_risk_lowest_ig_first():
    # MON-03 is IG2/HIGH-HIGH (CRITICAL), MON-01 is IG1/HIGH-MEDIUM (HIGH)
    checks = [
        CheckResult("MON-01", "a", Status.FAIL),
        CheckResult("MON-03", "c", Status.FAIL),
    ]
    entries = build_risk_register(_assessment(checks))
    assert [e.check_id for e in entries] == ["MON-03", "MON-01"]
    assert entries[0].risk_rating == "CRITICAL"
    assert entries[1].risk_rating == "HIGH"


def test_missing_metadata_check_sorts_last_as_unrated():
    checks = [
        CheckResult("MON-01", "a", Status.FAIL),      # rated
        CheckResult("CUSTOM-01", "custom", Status.FAIL),  # no metadata entry
    ]
    entries = build_risk_register(_assessment(checks))
    assert entries[-1].check_id == "CUSTOM-01"
    assert entries[-1].risk_rating == "UNRATED"
    assert entries[-1].cis_ig is None


def test_build_risk_register_raises_on_bad_metadata_path(tmp_path):
    checks = [CheckResult("MON-01", "a", Status.FAIL)]
    with pytest.raises(MappingsError):
        build_risk_register(_assessment(checks), metadata_path=tmp_path / "nope.yaml")


@pytest.mark.parametrize("frequency,magnitude,expected", [
    ("LOW", "LOW", "LOW"), ("LOW", "MEDIUM", "LOW"), ("LOW", "HIGH", "MODERATE"),
    ("MEDIUM", "LOW", "LOW"), ("MEDIUM", "MEDIUM", "MODERATE"), ("MEDIUM", "HIGH", "HIGH"),
    ("HIGH", "LOW", "MODERATE"), ("HIGH", "MEDIUM", "HIGH"), ("HIGH", "HIGH", "CRITICAL"),
])
def test_risk_rating_matrix_all_nine_combinations(frequency, magnitude, expected):
    assert risk_rating(frequency, magnitude) == expected


def test_risk_rating_none_inputs_are_unrated():
    assert risk_rating(None, "HIGH") == "UNRATED"
    assert risk_rating("HIGH", None) == "UNRATED"
    assert risk_rating(None, None) == "UNRATED"


def test_render_text_markdown_json_smoke():
    checks = [CheckResult("MON-01", "a", Status.FAIL)]
    entries = build_risk_register(_assessment(checks))
    assert "MON-01" in render(entries, "text")
    assert "MON-01" in render(entries, "markdown")
    assert '"check_id": "MON-01"' in render(entries, "json")


def test_render_empty_register():
    assert "nothing to remediate" in render([], "text").lower()
    assert "nothing to remediate" in render([], "markdown").lower()
