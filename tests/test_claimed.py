"""Tests for miccmac.checks.claimed's real detection logic. All tests
construct fake attestation dicts directly -- no SSH/osquery/VM dependency.
Claimed is 100% attestation-driven (no device facts), so its stub gate is
"context is empty" rather than "facts is None" -- see the module docstring
in miccmac/checks/claimed.py for why."""
from miccmac.checks import claimed
from miccmac.model import Status


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_empty_context_falls_back_to_original_stub_behavior():
    prop = claimed.evaluate("x", {})
    assert len(prop.checks) == 3
    for c in prop.checks:
        assert c.status == Status.NOT_IMPLEMENTED
        assert c.detail == "Check not yet implemented."


def test_facts_only_no_attestation_reports_not_applicable():
    """Unlike Inventoried/Monitored/Controlled, Claimed activates on any
    non-empty context, even facts-only (--connector with no --attestation),
    and correctly reports NOT_APPLICABLE per check rather than a blanket stub."""
    prop = claimed.evaluate("x", {"facts": {"os": {}}})
    assert len(prop.checks) == 3
    for c in prop.checks:
        assert c.status == Status.NOT_APPLICABLE


def test_clm01_pass_when_owner_assigned_with_name():
    attestation = {"business_owner": {"assigned": True, "name": "Jane Doe"}}
    clm01 = _by_id(claimed.evaluate("x", {"attestation": attestation}).checks, "CLM-01")
    assert clm01.status == Status.PASS


def test_clm01_fail_when_owner_not_assigned():
    attestation = {"business_owner": {"assigned": False}}
    clm01 = _by_id(claimed.evaluate("x", {"attestation": attestation}).checks, "CLM-01")
    assert clm01.status == Status.FAIL


def test_clm01_not_applicable_when_key_missing():
    clm01 = _by_id(claimed.evaluate("x", {"attestation": {}}).checks, "CLM-01")
    assert clm01.status == Status.NOT_APPLICABLE


def test_clm02_pass_when_admin_identified():
    attestation = {"system_administrator": {"assigned": True, "name": "John Smith"}}
    clm02 = _by_id(claimed.evaluate("x", {"attestation": attestation}).checks, "CLM-02")
    assert clm02.status == Status.PASS


def test_clm02_fail_when_admin_not_assigned():
    attestation = {"system_administrator": {"assigned": False}}
    clm02 = _by_id(claimed.evaluate("x", {"attestation": attestation}).checks, "CLM-02")
    assert clm02.status == Status.FAIL


def test_clm03_pass_when_documented_with_classification():
    attestation = {"business_purpose": {"documented": True, "data_classification": "internal"}}
    clm03 = _by_id(claimed.evaluate("x", {"attestation": attestation}).checks, "CLM-03")
    assert clm03.status == Status.PASS


def test_clm03_partial_when_documented_without_classification():
    attestation = {"business_purpose": {"documented": True}}
    clm03 = _by_id(claimed.evaluate("x", {"attestation": attestation}).checks, "CLM-03")
    assert clm03.status == Status.PARTIAL


def test_clm03_fail_when_not_documented():
    attestation = {"business_purpose": {"documented": False}}
    clm03 = _by_id(claimed.evaluate("x", {"attestation": attestation}).checks, "CLM-03")
    assert clm03.status == Status.FAIL


def test_control_refs_and_names_unchanged_from_stub():
    stub_checks = {c.check_id: c for c in claimed._stub_checks()}
    real_checks = {c.check_id: c for c in claimed.evaluate("x", {"attestation": {}}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
