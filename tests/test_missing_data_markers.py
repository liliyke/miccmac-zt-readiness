"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for the missing-data marker (miccmac.model.MissingData,
CheckResult.missing_data): which check branches set it and with what
source, problem, field and expected value; that every other result carries
none and every detail string is unchanged; how CheckResult.to_dict shows it;
and how the engine clears it (excluded checks, statuses other than
NOT_APPLICABLE and ERROR) and refuses a custom check that sets something
else. Also engine.score_statuses. Fake facts and input dicts only; nothing
connects anywhere."""
from __future__ import annotations

import dataclasses
import datetime as dt
import itertools

import pytest

from miccmac import clock
from miccmac.config import Config, ConfigError
from miccmac.engine import run_assessment, score_property, score_statuses
from miccmac.model import (
    MISSING_DATA_PROBLEMS,
    MISSING_DATA_SOURCES,
    CheckResult,
    MissingData,
    PropertyResult,
    Status,
)

AS_OF = dt.date(2026, 11, 23)
LINUX_FACTS = {"os": {"platform": "ubuntu"}, "system_info": {}, "deb_packages": [], "systemd_units": {},
               "apt_sources": [], "expired_certificates": []}
WINDOWS_FACTS = {"os": {"platform": "windows"}, "system_info": {}, "programs": [], "services": {},
                 "expired_certificates": []}
FULL_ATTESTATION = {
    "identity_aware_access": {"enabled": True},
    "business_owner": {"assigned": True, "name": "Owner"},
    "system_administrator": {"assigned": True, "name": "assessor"},
    "business_purpose": {"documented": True, "data_classification": "internal"},
    "vulnerability_scanning": {"performed": True, "last_scan": "2026-11-20", "interval_days": 30},
    "compliance_assessment": {"performed": True, "last_assessment": "2026-11-01", "interval_days": 90},
    "finding_remediation_sla": {"tracked": True, "sla_days": 30},
    "firmware_currency": {"current": True},
}
FULL_INVENTORY = {"device_id": "H1", "tracked": True, "last_reviewed": "2026-11-01"}
# The attestation entry each input-driven check reads, and what valid data looks like.
ATTESTATION_KEYS = {
    "CTL-03": ("identity_aware_access", '{"enabled": true or false}'),
    "CLM-01": ("business_owner", '{"assigned": true or false, "name": "OWNER NAME"}'),
    "CLM-02": ("system_administrator", '{"assigned": true or false, "name": "ADMINISTRATOR OR TEAM"}'),
    "CLM-03": ("business_purpose", '{"documented": true or false, "data_classification": "LABEL"}'),
    "ASM-01": ("vulnerability_scanning",
               '{"performed": true or false, "last_scan": "YYYY-MM-DD", "interval_days": DAYS}'),
    "ASM-02": ("compliance_assessment",
               '{"performed": true or false, "last_assessment": "YYYY-MM-DD", "interval_days": DAYS}'),
    "ASM-03": ("finding_remediation_sla", '{"tracked": true or false, "sla_days": DAYS}'),
    "CUR-03": ("firmware_currency", '{"current": true or false}'),
}
# Both checks read one record, so each example gives all of it (verifier finding: following
# INV-01's partial example turned INV-04 into a FAIL finding).
_WHOLE_RECORD = '{"device_id": "ASSET ID", "tracked": true or false, "last_reviewed": "YYYY-MM-DD"}'
INVENTORY_EXPECTED = {"INV-01": _WHOLE_RECORD, "INV-04": _WHOLE_RECORD}


def _checks(context, config=None):
    assessment = run_assessment("t", context=dict(context, **{clock.AS_OF_KEY: AS_OF}), config=config)
    return {c.check_id: c for p in assessment.properties for c in p.checks}


def _marker(check):
    return None if check.missing_data is None else check.missing_data.to_dict()


# ------------------------------------------------------------------ the 2.4 table
@pytest.mark.parametrize("facts", [LINUX_FACTS, WINDOWS_FACTS], ids=["linux", "windows"])
def test_no_attestation_and_no_inventory_record_are_not_supplied(facts):
    checks = _checks({"facts": facts})
    for check_id, (key, expected) in ATTESTATION_KEYS.items():
        assert checks[check_id].status is Status.NOT_APPLICABLE
        assert _marker(checks[check_id]) == {"source": "attestation", "problem": "not-supplied", "field": key,
                                             "expected": expected}, check_id
    for check_id, expected in INVENTORY_EXPECTED.items():
        assert checks[check_id].status is Status.NOT_APPLICABLE
        assert _marker(checks[check_id]) == {"source": "inventory_record", "problem": "not-supplied",
                                             "field": None, "expected": expected}, check_id


@pytest.mark.parametrize("check_id", sorted(ATTESTATION_KEYS))
def test_an_attestation_without_the_checks_entry_is_a_missing_field(check_id):
    key, expected = ATTESTATION_KEYS[check_id]
    attestation = {k: v for k, v in FULL_ATTESTATION.items() if k != key}
    checks = _checks({"facts": LINUX_FACTS, "attestation": attestation, "inventory_record": FULL_INVENTORY})
    assert checks[check_id].status is Status.NOT_APPLICABLE
    assert _marker(checks[check_id]) == {"source": "attestation", "problem": "missing-field", "field": key,
                                         "expected": expected}
    # Only that check is affected: every other input-driven check is evaluated, with no marker.
    assert [c for c, r in checks.items() if r.missing_data is not None] == [check_id]


def test_an_attestation_file_holding_null_was_given_so_its_entries_are_missing_fields():
    """--attestation given with JSON null: the option was given, so this is
    missing-field, not not-supplied (the critique's case)."""
    checks = _checks({"facts": LINUX_FACTS, "attestation": None, "inventory_record": None})
    for check_id, (key, _) in ATTESTATION_KEYS.items():
        assert (checks[check_id].missing_data.problem, checks[check_id].missing_data.field) == (
            "missing-field", key)
    for check_id in INVENTORY_EXPECTED:
        assert (checks[check_id].missing_data.problem, checks[check_id].missing_data.field) == (
            "missing-field", None)


@pytest.mark.parametrize("check_id, key, date_field", [
    ("ASM-01", "vulnerability_scanning", "last_scan"),
    ("ASM-02", "compliance_assessment", "last_assessment"),
])
def test_an_unreadable_attestation_date_is_an_invalid_value(check_id, key, date_field):
    attestation = dict(FULL_ATTESTATION)
    attestation[key] = dict(attestation[key], **{date_field: "23/11/2026"})   # invalid on every Python
    check = _checks({"facts": LINUX_FACTS, "attestation": attestation, "inventory_record": FULL_INVENTORY})[check_id]
    assert check.status is Status.ERROR
    assert check.detail == f"Attestation's {date_field}='23/11/2026' is not a valid ISO date."   # unchanged
    assert _marker(check) == {"source": "attestation", "problem": "invalid-value", "field": f"{key}.{date_field}",
                              "expected": "a YYYY-MM-DD date"}


def test_an_unreadable_inventory_date_is_an_invalid_value():
    record = dict(FULL_INVENTORY, last_reviewed="2026-13-01")
    check = _checks({"facts": LINUX_FACTS, "attestation": FULL_ATTESTATION, "inventory_record": record})["INV-04"]
    assert check.status is Status.ERROR
    assert check.detail == "Supplied inventory record's last_reviewed='2026-13-01' is not a valid ISO date."
    assert _marker(check) == {"source": "inventory_record", "problem": "invalid-value", "field": "last_reviewed",
                              "expected": "a YYYY-MM-DD date"}


def test_an_unreadable_windows_update_timestamp_is_an_invalid_fact():
    facts = dict(WINDOWS_FACTS, services={"wuauserv": {"status": "RUNNING"}}, last_update_installed_iso="soon")
    check = _checks({"facts": facts})["CUR-01"]
    assert check.status is Status.ERROR
    assert check.detail == "Last Windows Update install timestamp 'soon' is not a valid date."
    assert _marker(check) == {"source": "facts", "problem": "invalid-value", "field": "last_update_installed_iso",
                              "expected": "an ISO 8601 timestamp of the last successful update install"}


def test_details_of_the_not_applicable_results_are_unchanged():
    checks = _checks({"facts": LINUX_FACTS})
    assert checks["CTL-03"].detail == (
        "No --attestation supplied for identity_aware_access; conditional-access policy is enforced by a cloud "
        "identity provider and is not observable from the device itself.")
    assert checks["CLM-01"].detail == ("No --attestation supplied for 'business_owner'; this is an organizational "
                                       "record-keeping fact, not observable from the device itself.")
    assert checks["ASM-03"].detail == ("No --attestation supplied for 'finding_remediation_sla'; scan/assessment "
                                       "history is an external process fact, not observable from the device "
                                       "itself.")
    assert checks["CUR-03"].detail.startswith("No --attestation supplied for firmware_currency; a device can report")
    assert checks["INV-01"].detail.startswith("No inventory-system integration configured (no --inventory-record "
                                              "supplied); device presence")
    assert checks["INV-04"].detail.startswith("No inventory-system integration configured (no --inventory-record "
                                              "supplied); review recency")


# ------------------------------------------------------------------ results without a marker
def test_evaluated_results_and_genuine_not_applicable_carry_no_marker():
    checks = _checks({"facts": LINUX_FACTS, "attestation": FULL_ATTESTATION, "inventory_record": FULL_INVENTORY})
    statuses = {c.status for c in checks.values()}
    assert {Status.PASS, Status.FAIL, Status.NOT_APPLICABLE} <= statuses
    assert all(c.missing_data is None for c in checks.values())
    # CUR-02 with no third-party software does not apply: NOT_APPLICABLE, no marker.
    assert checks["CUR-02"].status is Status.NOT_APPLICABLE and checks["CUR-02"].missing_data is None


def test_partial_and_fail_from_incomplete_entries_stay_findings_without_a_marker():
    """ASM-01/ASM-02 'performed' with no date, INV-04 with no last_reviewed and
    an explicit null stay evaluated results (researcher question in the spec)."""
    attestation = dict(FULL_ATTESTATION, vulnerability_scanning={"performed": True},
                       firmware_currency=None)
    checks = _checks({"facts": LINUX_FACTS, "attestation": attestation,
                      "inventory_record": {"device_id": "H1", "tracked": True}})
    assert (checks["ASM-01"].status, checks["ASM-01"].missing_data) == (Status.PARTIAL, None)
    assert (checks["INV-04"].status, checks["INV-04"].missing_data) == (Status.FAIL, None)
    assert (checks["CUR-03"].status, checks["CUR-03"].missing_data) == (Status.FAIL, None)


def test_a_stub_run_has_no_marker_and_its_json_is_unchanged():
    assessment = run_assessment("test-device")
    assert all("missing_data" not in c.to_dict() for p in assessment.properties for c in p.checks)


def test_to_dict_shows_the_marker_after_control_refs_only_when_set():
    check = CheckResult("X-01", "x", Status.NOT_APPLICABLE, "d")
    assert list(check.to_dict()) == ["check_id", "name", "status", "detail", "evidence", "control_refs"]
    check.missing_data = MissingData("attestation", "missing-field", "k", "{}")
    assert list(check.to_dict())[-1] == "missing_data"
    assert check.to_dict()["missing_data"] == {"source": "attestation", "problem": "missing-field", "field": "k",
                                               "expected": "{}"}


# ------------------------------------------------------------------ MissingData validation
def test_every_source_and_problem_combination_but_facts_not_supplied_is_valid():
    for source, problem in itertools.product(MISSING_DATA_SOURCES, MISSING_DATA_PROBLEMS):
        if (source, problem) == ("facts", "not-supplied"):
            with pytest.raises(ValueError, match="NOT_IMPLEMENTED"):
                MissingData(source, problem)
        else:
            assert MissingData(source, problem).source == source


@pytest.mark.parametrize("kwargs", [
    {"source": "registry", "problem": "missing-field"},
    {"source": "attestation", "problem": "absent"},
    {"source": "attestation", "problem": "missing-field", "field": " "},
    {"source": "attestation", "problem": "missing-field", "expected": None},
])
def test_invalid_markers_are_refused(kwargs):
    with pytest.raises(ValueError):
        MissingData(**kwargs)


def test_markers_are_frozen():
    marker = MissingData("attestation", "missing-field", "k")
    with pytest.raises(dataclasses.FrozenInstanceError):
        marker.field = "other"


# ------------------------------------------------------------------ engine
def test_an_excluded_check_has_no_marker():
    config = Config(excluded_checks={"CTL-03": "Identity-aware access is out of scope in this lab."})
    checks = _checks({"facts": LINUX_FACTS}, config=config)
    assert checks["CTL-03"].status is Status.NOT_APPLICABLE
    assert checks["CTL-03"].detail.startswith("Excluded: ")
    assert checks["CTL-03"].missing_data is None and "missing_data" not in checks["CTL-03"].to_dict()
    assert checks["CLM-01"].missing_data is not None    # the other checks keep theirs


def _plugin_dir(tmp_path, status: str, marker: str) -> Config:
    folder = tmp_path / "plugins"
    folder.mkdir()
    (folder / "acme.py").write_text(
        "from miccmac.model import CheckResult, MissingData, Status\n"
        "CHECK_IDS = ['ACME-01']\nATTACH_TO = 'controlled'\n"
        "RISK_METADATA = {'ACME-01': {'cis_ig': 'IG1'}}\n"
        "def run_checks(target, context):\n"
        f"    return [CheckResult('ACME-01', 'Acme', Status.{status}, 'acme detail.', missing_data={marker})]\n",
        encoding="utf-8")
    return Config(custom_checks_dir=folder)


def test_the_engine_clears_a_marker_on_a_status_other_than_not_applicable_or_error(tmp_path):
    config = _plugin_dir(tmp_path, "FAIL", "MissingData('facts', 'missing-field', 'acme')")
    checks = _checks({"facts": LINUX_FACTS}, config=config)
    assert checks["ACME-01"].status is Status.FAIL and checks["ACME-01"].missing_data is None


def test_a_plugin_marker_on_not_applicable_is_kept(tmp_path):
    config = _plugin_dir(tmp_path, "NOT_APPLICABLE", "MissingData('facts', 'missing-field', 'acme')")
    checks = _checks({"facts": LINUX_FACTS}, config=config)
    assert checks["ACME-01"].missing_data == MissingData("facts", "missing-field", "acme")


def test_a_plugin_marker_that_is_not_a_missing_data_is_refused(tmp_path):
    config = _plugin_dir(tmp_path, "NOT_APPLICABLE", "{'source': 'facts'}")
    with pytest.raises(ConfigError, match="must be a miccmac.model.MissingData or None"):
        _checks({"facts": LINUX_FACTS}, config=config)


@pytest.mark.parametrize("statuses", list(itertools.product(list(Status), repeat=3)))
def test_score_statuses_equals_score_property(statuses):
    prop = PropertyResult(key="x", letter="X", title="X",
                          checks=[CheckResult(f"X-{i}", "x", s) for i, s in enumerate(statuses)])
    assert score_statuses(statuses) == score_property(prop)
