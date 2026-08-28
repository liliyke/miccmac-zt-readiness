"""Tests for miccmac.checks.monitored's real detection logic. All tests
construct fake facts dicts directly -- no SSH/osquery/VM dependency."""
from miccmac.checks import monitored
from miccmac.model import Status


def _units(**overrides):
    base = {
        "systemd-journald.service": {"active_state": "active", "load_state": "loaded"},
        "rsyslog.service": {"active_state": "active", "load_state": "loaded"},
        "syslog-ng.service": {"active_state": "inactive", "load_state": "not-found"},
        "osqueryd.service": {"active_state": "active", "load_state": "loaded"},
        "auditd.service": {"active_state": "inactive", "load_state": "not-found"},
    }
    base.update(overrides)
    return base


def _facts(**overrides):
    base = {"systemd_units": _units(), "rsyslog_forwarding_configured": False}
    base.update(overrides)
    return base


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_no_facts_falls_back_to_original_stub_behavior():
    prop = monitored.evaluate("x", {})
    assert len(prop.checks) == 4
    for c in prop.checks:
        assert c.status == Status.NOT_IMPLEMENTED
        assert c.detail == "Check not yet implemented."


def test_mon01_pass_when_journald_and_syslog_active():
    mon01 = _by_id(monitored.evaluate("x", {"facts": _facts()}).checks, "MON-01")
    assert mon01.status == Status.PASS


def test_mon01_partial_when_only_journald_active():
    units = _units(**{"rsyslog.service": {"active_state": "inactive", "load_state": "loaded"}})
    mon01 = _by_id(monitored.evaluate("x", {"facts": _facts(systemd_units=units)}).checks, "MON-01")
    assert mon01.status == Status.PARTIAL


def test_mon01_fail_when_journald_inactive():
    units = _units(**{"systemd-journald.service": {"active_state": "inactive", "load_state": "loaded"}})
    mon01 = _by_id(monitored.evaluate("x", {"facts": _facts(systemd_units=units)}).checks, "MON-01")
    assert mon01.status == Status.FAIL


def test_mon02_pass_when_rsyslog_forwarding_configured():
    mon02 = _by_id(
        monitored.evaluate("x", {"facts": _facts(rsyslog_forwarding_configured=True)}).checks, "MON-02"
    )
    assert mon02.status == Status.PASS


def test_mon02_fail_when_no_forwarding_configured():
    mon02 = _by_id(monitored.evaluate("x", {"facts": _facts()}).checks, "MON-02")
    assert mon02.status == Status.FAIL


def test_mon03_pass_when_osqueryd_active():
    mon03 = _by_id(monitored.evaluate("x", {"facts": _facts()}).checks, "MON-03")
    assert mon03.status == Status.PASS


def test_mon03_fail_when_osqueryd_inactive():
    units = _units(**{"osqueryd.service": {"active_state": "inactive", "load_state": "loaded"}})
    mon03 = _by_id(monitored.evaluate("x", {"facts": _facts(systemd_units=units)}).checks, "MON-03")
    assert mon03.status == Status.FAIL


def test_mon04_fail_when_auditd_not_installed():
    mon04 = _by_id(monitored.evaluate("x", {"facts": _facts()}).checks, "MON-04")
    assert mon04.status == Status.FAIL
    assert "not installed" in mon04.detail


def test_mon04_fail_when_auditd_installed_but_inactive():
    units = _units(**{"auditd.service": {"active_state": "inactive", "load_state": "loaded"}})
    mon04 = _by_id(monitored.evaluate("x", {"facts": _facts(systemd_units=units)}).checks, "MON-04")
    assert mon04.status == Status.FAIL
    assert "not active" in mon04.detail


def test_mon04_pass_when_auditd_active():
    units = _units(**{"auditd.service": {"active_state": "active", "load_state": "loaded"}})
    mon04 = _by_id(monitored.evaluate("x", {"facts": _facts(systemd_units=units)}).checks, "MON-04")
    assert mon04.status == Status.PASS


def test_control_refs_and_names_unchanged_from_stub():
    """Real logic must not drift check_id/name/control_refs from the stub."""
    stub_checks = {c.check_id: c for c in monitored._stub_checks()}
    real_checks = {c.check_id: c for c in monitored.evaluate("x", {"facts": _facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
