"""Basic tests for the assessment engine and model."""
import pytest

from miccmac.config import Config, ConfigError
from miccmac.engine import (
    PROPERTY_MODULES,
    enabled_check_ids,
    readiness_tier,
    run_assessment,
    score_property,
)
from miccmac.model import CheckResult, PropertyResult, Status


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


def test_default_run_assessment_output_unchanged():
    """Golden backward-compat test: no config/methodology -> identical shape
    to the original scaffold's to_dict() output (4 keys, no methodology,
    no excluded_check_ids)."""
    assessment = run_assessment("test-device")
    d = assessment.to_dict()
    assert set(d.keys()) == {"target", "overall_score", "readiness_tier", "properties"}


def test_enabled_check_ids_default_matches_all_26_builtin_ids():
    ids = enabled_check_ids()
    assert len(ids) == 26
    assert len(ids) == len(set(ids))  # no duplicates
    assert set(ids) == {c.check_id for m in PROPERTY_MODULES for c in m.evaluate("x", {}).checks}


def test_excluded_checks_render_as_not_applicable_with_reason_and_are_unscored():
    """Excluded checks are never silently dropped: they stay in the report
    as NOT_APPLICABLE with the recorded reason, and are removed from the
    scoring denominator rather than counted as a pass or fail."""
    config = Config(excluded_checks={"MON-01": "Not relevant to this pilot's fleet."})
    assessment = run_assessment("test-device", config=config)
    mon = next(p for p in assessment.properties if p.key == "monitored")
    mon01 = next(c for c in mon.checks if c.check_id == "MON-01")
    assert mon01.status == Status.NOT_APPLICABLE
    assert mon01.detail == "Excluded: Not relevant to this pilot's fleet."
    assert assessment.excluded_check_ids == ["MON-01"]


def test_enabled_check_ids_reflects_exclusions():
    config = Config(excluded_checks={"MON-01": "Not relevant to this pilot's fleet."})
    ids = enabled_check_ids(config)
    assert "MON-01" not in ids
    assert len(ids) == 25


def test_excluding_unknown_check_id_raises_configerror():
    config = Config(excluded_checks={"NOPE-99": "typo'd id"})
    with pytest.raises(ConfigError, match="unknown"):
        run_assessment("test-device", config=config)
    with pytest.raises(ConfigError, match="unknown"):
        enabled_check_ids(config)


def test_custom_check_attaches_to_correct_property_only(tmp_path):
    plugin_src = '''
from miccmac.model import CheckResult, Status
CHECK_IDS = ["ACME-01"]
ATTACH_TO = "controlled"
RISK_METADATA = {"ACME-01": {"cis_ig": "IG2"}}
def run_checks(target, context):
    return [CheckResult(check_id="ACME-01", name="test", status=Status.PASS)]
'''
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (checks_dir / "acme.py").write_text(plugin_src, encoding="utf-8")

    config = Config(custom_checks_dir=checks_dir)
    assessment = run_assessment("test-device", config=config)

    ctl = next(p for p in assessment.properties if p.key == "controlled")
    assert "ACME-01" in {c.check_id for c in ctl.checks}
    for prop in assessment.properties:
        if prop.key != "controlled":
            assert "ACME-01" not in {c.check_id for c in prop.checks}


def test_custom_check_cannot_create_an_eighth_property(tmp_path):
    plugin_src = '''
from miccmac.model import CheckResult, Status
CHECK_IDS = ["ACME-01"]
ATTACH_TO = "controlled"
RISK_METADATA = {"ACME-01": {"cis_ig": "IG2"}}
def run_checks(target, context):
    return [CheckResult(check_id="ACME-01", name="test", status=Status.PASS)]
'''
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (checks_dir / "acme.py").write_text(plugin_src, encoding="utf-8")

    config = Config(custom_checks_dir=checks_dir)
    assessment = run_assessment("test-device", config=config)
    assert len(assessment.properties) == 7


def test_custom_check_mismatched_ids_raises_configerror(tmp_path):
    plugin_src = '''
from miccmac.model import CheckResult, Status
CHECK_IDS = ["ACME-01"]
ATTACH_TO = "controlled"
RISK_METADATA = {"ACME-01": {"cis_ig": "IG2"}}
def run_checks(target, context):
    return [CheckResult(check_id="WRONG-ID", name="test", status=Status.PASS)]
'''
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (checks_dir / "acme.py").write_text(plugin_src, encoding="utf-8")

    config = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="ACME-01"):
        run_assessment("test-device", config=config)


def test_methodology_flag_attaches_methodology_without_altering_flat_score():
    plain = run_assessment("test-device")
    with_methodology = run_assessment("test-device", methodology_name="cmmi")

    assert with_methodology.overall_score == plain.overall_score
    assert with_methodology.readiness_tier == plain.readiness_tier
    assert with_methodology.methodology is not None
    assert with_methodology.methodology.name == "cmmi"
    # scaffold today has no scorable checks -> Unassessed, not falsely "Level 1"
    assert with_methodology.methodology.overall.level_label == "Unassessed"


def test_no_methodology_flag_leaves_methodology_none():
    assessment = run_assessment("test-device")
    assert assessment.methodology is None
