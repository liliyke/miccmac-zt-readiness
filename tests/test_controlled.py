"""Tests for miccmac.checks.controlled's real detection logic. All tests
construct fake facts/attestation dicts directly -- no SSH/osquery/VM
dependency."""
from miccmac.checks import controlled
from miccmac.model import Status


def _facts(**overrides):
    base = {
        "deb_packages": [{"name": "bash", "version": "5.2"}],
        "root_locked": True,
        "sudo_users": ["miccmac"],
    }
    base.update(overrides)
    return base


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_no_facts_falls_back_to_original_stub_behavior():
    prop = controlled.evaluate("x", {})
    assert len(prop.checks) == 4
    for c in prop.checks:
        assert c.status == Status.NOT_IMPLEMENTED
        assert c.detail == "Check not yet implemented."


def test_ctl01_fail_when_no_config_mgmt_agent():
    ctl01 = _by_id(controlled.evaluate("x", {"facts": _facts()}).checks, "CTL-01")
    assert ctl01.status == Status.FAIL


def test_ctl01_pass_when_config_mgmt_agent_present():
    facts = _facts(deb_packages=[{"name": "landscape-client", "version": "1.0"}])
    ctl01 = _by_id(controlled.evaluate("x", {"facts": facts}).checks, "CTL-01")
    assert ctl01.status == Status.PASS


def test_ctl02_pass_when_root_locked_and_sudo_users_exist():
    ctl02 = _by_id(controlled.evaluate("x", {"facts": _facts()}).checks, "CTL-02")
    assert ctl02.status == Status.PASS


def test_ctl02_partial_when_root_locked_but_no_sudo_users():
    facts = _facts(sudo_users=[])
    ctl02 = _by_id(controlled.evaluate("x", {"facts": facts}).checks, "CTL-02")
    assert ctl02.status == Status.PARTIAL


def test_ctl02_fail_when_root_not_locked():
    facts = _facts(root_locked=False)
    ctl02 = _by_id(controlled.evaluate("x", {"facts": facts}).checks, "CTL-02")
    assert ctl02.status == Status.FAIL


def test_ctl03_not_applicable_without_attestation():
    ctl03 = _by_id(controlled.evaluate("x", {"facts": _facts()}).checks, "CTL-03")
    assert ctl03.status == Status.NOT_APPLICABLE


def test_ctl03_pass_when_attestation_confirms_identity_aware_access():
    attestation = {"identity_aware_access": {"enabled": True}}
    ctl03 = _by_id(
        controlled.evaluate("x", {"facts": _facts(), "attestation": attestation}).checks, "CTL-03"
    )
    assert ctl03.status == Status.PASS


def test_ctl03_fail_when_attestation_denies_identity_aware_access():
    attestation = {"identity_aware_access": {"enabled": False}}
    ctl03 = _by_id(
        controlled.evaluate("x", {"facts": _facts(), "attestation": attestation}).checks, "CTL-03"
    )
    assert ctl03.status == Status.FAIL


def test_ctl03_accepts_plain_boolean_attestation_value():
    attestation = {"identity_aware_access": True}
    ctl03 = _by_id(
        controlled.evaluate("x", {"facts": _facts(), "attestation": attestation}).checks, "CTL-03"
    )
    assert ctl03.status == Status.PASS


def test_ctl04_fail_when_no_hardening_tool():
    ctl04 = _by_id(controlled.evaluate("x", {"facts": _facts()}).checks, "CTL-04")
    assert ctl04.status == Status.FAIL


def test_ctl04_pass_when_hardening_tool_present():
    facts = _facts(deb_packages=[{"name": "usg", "version": "1.0"}])
    ctl04 = _by_id(controlled.evaluate("x", {"facts": facts}).checks, "CTL-04")
    assert ctl04.status == Status.PASS


def test_control_refs_and_names_unchanged_from_stub():
    stub_checks = {c.check_id: c for c in controlled._stub_checks()}
    real_checks = {c.check_id: c for c in controlled.evaluate("x", {"facts": _facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
