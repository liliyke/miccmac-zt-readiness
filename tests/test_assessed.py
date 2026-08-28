"""Tests for miccmac.checks.assessed's real detection logic. All tests
construct fake attestation dicts directly -- no SSH/osquery/VM dependency.
Assessed is 100% attestation-driven, like Claimed -- see that module's
docstring for why its stub gate is "context is empty" rather than "facts
is None"."""
import datetime

from miccmac.checks import assessed
from miccmac.model import Status


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_empty_context_falls_back_to_original_stub_behavior():
    prop = assessed.evaluate("x", {})
    assert len(prop.checks) == 3
    for c in prop.checks:
        assert c.status == Status.NOT_IMPLEMENTED
        assert c.detail == "Check not yet implemented."


def test_facts_only_no_attestation_reports_not_applicable():
    prop = assessed.evaluate("x", {"facts": {"os": {}}})
    for c in prop.checks:
        assert c.status == Status.NOT_APPLICABLE


def test_asm01_pass_within_scan_interval():
    recent = (datetime.date.today() - datetime.timedelta(days=10)).isoformat()
    attestation = {"vulnerability_scanning": {"performed": True, "last_scan": recent, "interval_days": 30}}
    asm01 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-01")
    assert asm01.status == Status.PASS


def test_asm01_fail_outside_scan_interval():
    old = (datetime.date.today() - datetime.timedelta(days=100)).isoformat()
    attestation = {"vulnerability_scanning": {"performed": True, "last_scan": old, "interval_days": 30}}
    asm01 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-01")
    assert asm01.status == Status.FAIL


def test_asm01_fail_when_not_performed():
    attestation = {"vulnerability_scanning": {"performed": False}}
    asm01 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-01")
    assert asm01.status == Status.FAIL


def test_asm01_partial_when_performed_but_no_date():
    attestation = {"vulnerability_scanning": {"performed": True}}
    asm01 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-01")
    assert asm01.status == Status.PARTIAL


def test_asm01_error_on_malformed_date():
    attestation = {"vulnerability_scanning": {"performed": True, "last_scan": "not-a-date", "interval_days": 30}}
    asm01 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-01")
    assert asm01.status == Status.ERROR


def test_asm01_not_applicable_when_key_missing():
    asm01 = _by_id(assessed.evaluate("x", {"attestation": {}}).checks, "ASM-01")
    assert asm01.status == Status.NOT_APPLICABLE


def test_asm02_pass_within_assessment_interval():
    recent = (datetime.date.today() - datetime.timedelta(days=5)).isoformat()
    attestation = {"compliance_assessment": {"performed": True, "last_assessment": recent, "interval_days": 90}}
    asm02 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-02")
    assert asm02.status == Status.PASS


def test_asm03_pass_when_tracked():
    attestation = {"finding_remediation_sla": {"tracked": True, "sla_days": 30}}
    asm03 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-03")
    assert asm03.status == Status.PASS


def test_asm03_fail_when_not_tracked():
    attestation = {"finding_remediation_sla": {"tracked": False}}
    asm03 = _by_id(assessed.evaluate("x", {"attestation": attestation}).checks, "ASM-03")
    assert asm03.status == Status.FAIL


def test_asm03_not_applicable_when_key_missing():
    asm03 = _by_id(assessed.evaluate("x", {"attestation": {}}).checks, "ASM-03")
    assert asm03.status == Status.NOT_APPLICABLE


def test_control_refs_and_names_unchanged_from_stub():
    stub_checks = {c.check_id: c for c in assessed._stub_checks()}
    real_checks = {c.check_id: c for c in assessed.evaluate("x", {"attestation": {}}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
