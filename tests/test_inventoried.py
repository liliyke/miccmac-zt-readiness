"""Tests for miccmac.checks.inventoried's real detection logic. All tests
construct fake facts/inventory_record dicts directly -- no SSH/osquery/VM
dependency (that lives in the opt-in integration test)."""
import datetime

from miccmac.checks import inventoried
from miccmac.model import Status


def _facts(**overrides):
    base = {
        "system_info": {
            "hardware_vendor": "VMware, Inc.",
            "hardware_model": "VMware Virtual Platform",
            "hardware_serial": "VMware-12 34",
        },
        "deb_packages": [{"name": "bash", "version": "5.2"}],
    }
    base.update(overrides)
    return base


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_no_facts_falls_back_to_original_stub_behavior():
    prop = inventoried.evaluate("x", {})
    assert len(prop.checks) == 4
    for c in prop.checks:
        assert c.status == Status.NOT_IMPLEMENTED
        assert c.detail == "Check not yet implemented."


def test_inv02_pass_when_all_hardware_attributes_present():
    prop = inventoried.evaluate("x", {"facts": _facts()})
    inv02 = _by_id(prop.checks, "INV-02")
    assert inv02.status == Status.PASS


def test_inv02_partial_when_some_hardware_attributes_missing():
    facts = _facts(system_info={"hardware_vendor": "VMware, Inc.", "hardware_model": "", "hardware_serial": ""})
    inv02 = _by_id(inventoried.evaluate("x", {"facts": facts}).checks, "INV-02")
    assert inv02.status == Status.PARTIAL


def test_inv02_fail_when_no_hardware_attributes():
    facts = _facts(system_info={})
    inv02 = _by_id(inventoried.evaluate("x", {"facts": facts}).checks, "INV-02")
    assert inv02.status == Status.FAIL


def test_inv03_pass_when_packages_present():
    inv03 = _by_id(inventoried.evaluate("x", {"facts": _facts()}).checks, "INV-03")
    assert inv03.status == Status.PASS
    assert "1 installed packages" in inv03.detail


def test_inv03_fail_when_no_packages():
    facts = _facts(deb_packages=[])
    inv03 = _by_id(inventoried.evaluate("x", {"facts": facts}).checks, "INV-03")
    assert inv03.status == Status.FAIL


def test_inv01_and_inv04_not_applicable_without_inventory_record():
    prop = inventoried.evaluate("x", {"facts": _facts()})
    assert _by_id(prop.checks, "INV-01").status == Status.NOT_APPLICABLE
    assert _by_id(prop.checks, "INV-04").status == Status.NOT_APPLICABLE


def test_inv01_pass_when_tracked():
    record = {"device_id": "dev-1", "tracked": True}
    inv01 = _by_id(inventoried.evaluate("x", {"facts": _facts(), "inventory_record": record}).checks, "INV-01")
    assert inv01.status == Status.PASS


def test_inv01_fail_when_not_tracked():
    record = {"device_id": "dev-1", "tracked": False}
    inv01 = _by_id(inventoried.evaluate("x", {"facts": _facts(), "inventory_record": record}).checks, "INV-01")
    assert inv01.status == Status.FAIL


def test_inv04_pass_within_policy_interval():
    recent = (datetime.date.today() - datetime.timedelta(days=10)).isoformat()
    record = {"device_id": "dev-1", "tracked": True, "last_reviewed": recent}
    inv04 = _by_id(inventoried.evaluate("x", {"facts": _facts(), "inventory_record": record}).checks, "INV-04")
    assert inv04.status == Status.PASS


def test_inv04_fail_outside_policy_interval():
    old = (datetime.date.today() - datetime.timedelta(days=200)).isoformat()
    record = {"device_id": "dev-1", "tracked": True, "last_reviewed": old}
    inv04 = _by_id(inventoried.evaluate("x", {"facts": _facts(), "inventory_record": record}).checks, "INV-04")
    assert inv04.status == Status.FAIL


def test_inv04_fail_when_no_last_reviewed_field():
    record = {"device_id": "dev-1", "tracked": True}
    inv04 = _by_id(inventoried.evaluate("x", {"facts": _facts(), "inventory_record": record}).checks, "INV-04")
    assert inv04.status == Status.FAIL


def test_inv04_error_on_malformed_date():
    record = {"device_id": "dev-1", "tracked": True, "last_reviewed": "not-a-date"}
    inv04 = _by_id(inventoried.evaluate("x", {"facts": _facts(), "inventory_record": record}).checks, "INV-04")
    assert inv04.status == Status.ERROR


def test_control_refs_and_names_unchanged_from_stub():
    """Real logic must not drift check_id/name/control_refs from the stub."""
    stub_checks = {c.check_id: c for c in inventoried._stub_checks()}
    real_checks = {c.check_id: c for c in inventoried.evaluate("x", {"facts": _facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
