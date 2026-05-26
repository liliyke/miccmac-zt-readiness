"""Basic tests for the assessment engine and model."""
from miccmac.engine import run_assessment, readiness_tier, PROPERTY_MODULES
from miccmac.model import Status, CheckResult, PropertyResult
from miccmac.engine import score_property


def test_seven_properties_in_miccmac_order():
    assessment = run_assessment("test-device")
    letters = "".join(p.letter for p in assessment.properties)
    assert letters == "MICCMAC"
    assert len(assessment.properties) == 7


def test_scaffold_runs_and_is_unassessed():
    # With only NOT_IMPLEMENTED checks, the scaffold must not invent a score.
    assessment = run_assessment("test-device")
    assert assessment.overall_score is None
    assert assessment.readiness_tier == "Unassessed"


def test_score_property_excludes_not_implemented():
    prop = PropertyResult(key="x", letter="X", title="X", checks=[
        CheckResult("X-1", "a", Status.PASS),
        CheckResult("X-2", "b", Status.FAIL),
        CheckResult("X-3", "c", Status.NOT_IMPLEMENTED),
    ])
    # Only PASS (100) and FAIL (0) count -> average 50.
    assert score_property(prop) == 50.0


def test_readiness_tiers():
    assert readiness_tier(95) == "Zero Trust Ready"
    assert readiness_tier(75) == "Defensible"
    assert readiness_tier(55) == "Developing"
    assert readiness_tier(10) == "Not Ready"
    assert readiness_tier(None) == "Unassessed"


def test_every_check_has_control_refs():
    for module in PROPERTY_MODULES:
        prop = module.evaluate("test-device", {})
        for check in prop.checks:
            assert check.control_refs, f"{check.check_id} missing control_refs"
