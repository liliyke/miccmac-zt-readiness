"""Tests for miccmac.checks.current's real detection logic. All tests
construct fake facts/attestation dicts directly -- no SSH/osquery/VM
dependency."""
import datetime

from miccmac.checks import current
from miccmac.model import Status


def _facts(**overrides):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    base = {
        "systemd_units": {"apt-daily-upgrade.timer": {"active_state": "active"}},
        "apt_update_stamp_mtime": int((now - datetime.timedelta(days=1)).timestamp()),
        "apt_sources": ["http://us.archive.ubuntu.com/ubuntu", "http://security.ubuntu.com/ubuntu"],
        "expired_certificates": [],
    }
    base.update(overrides)
    return base


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_no_facts_falls_back_to_original_stub_behavior():
    prop = current.evaluate("x", {})
    assert len(prop.checks) == 4
    for c in prop.checks:
        assert c.status == Status.NOT_IMPLEMENTED
        assert c.detail == "Check not yet implemented."


def test_cur01_pass_when_timer_active_and_recently_updated():
    cur01 = _by_id(current.evaluate("x", {"facts": _facts()}).checks, "CUR-01")
    assert cur01.status == Status.PASS


def test_cur01_fail_when_timer_inactive():
    facts = _facts(systemd_units={"apt-daily-upgrade.timer": {"active_state": "inactive"}})
    cur01 = _by_id(current.evaluate("x", {"facts": facts}).checks, "CUR-01")
    assert cur01.status == Status.FAIL


def test_cur01_fail_when_update_stamp_stale():
    old = int((datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=30)).timestamp())
    facts = _facts(apt_update_stamp_mtime=old)
    cur01 = _by_id(current.evaluate("x", {"facts": facts}).checks, "CUR-01")
    assert cur01.status == Status.FAIL


def test_cur01_partial_when_no_update_stamp_at_all():
    facts = _facts(apt_update_stamp_mtime=None)
    cur01 = _by_id(current.evaluate("x", {"facts": facts}).checks, "CUR-01")
    assert cur01.status == Status.PARTIAL


def test_cur02_not_applicable_when_no_third_party_sources():
    cur02 = _by_id(current.evaluate("x", {"facts": _facts()}).checks, "CUR-02")
    assert cur02.status == Status.NOT_APPLICABLE


def test_cur02_partial_when_third_party_sources_and_timer_active():
    facts = _facts(apt_sources=["http://ppa.launchpadcontent.net/someppa/ubuntu"])
    cur02 = _by_id(current.evaluate("x", {"facts": facts}).checks, "CUR-02")
    assert cur02.status == Status.PARTIAL


def test_cur02_fail_when_third_party_sources_and_timer_inactive():
    facts = _facts(
        apt_sources=["http://ppa.launchpadcontent.net/someppa/ubuntu"],
        systemd_units={"apt-daily-upgrade.timer": {"active_state": "inactive"}},
    )
    cur02 = _by_id(current.evaluate("x", {"facts": facts}).checks, "CUR-02")
    assert cur02.status == Status.FAIL


def test_cur03_not_applicable_without_attestation():
    cur03 = _by_id(current.evaluate("x", {"facts": _facts()}).checks, "CUR-03")
    assert cur03.status == Status.NOT_APPLICABLE


def test_cur03_pass_when_attestation_confirms_current():
    attestation = {"firmware_currency": {"current": True}}
    cur03 = _by_id(current.evaluate("x", {"facts": _facts(), "attestation": attestation}).checks, "CUR-03")
    assert cur03.status == Status.PASS


def test_cur03_fail_when_attestation_denies_current():
    attestation = {"firmware_currency": {"current": False}}
    cur03 = _by_id(current.evaluate("x", {"facts": _facts(), "attestation": attestation}).checks, "CUR-03")
    assert cur03.status == Status.FAIL


def test_cur04_pass_when_no_expired_certificates():
    cur04 = _by_id(current.evaluate("x", {"facts": _facts()}).checks, "CUR-04")
    assert cur04.status == Status.PASS


def test_cur04_fail_when_expired_certificates_found():
    facts = _facts(expired_certificates=[{"common_name": "old.example.com", "not_valid_after": "100"}])
    cur04 = _by_id(current.evaluate("x", {"facts": facts}).checks, "CUR-04")
    assert cur04.status == Status.FAIL
    assert "old.example.com" in cur04.detail


def test_control_refs_and_names_unchanged_from_stub():
    stub_checks = {c.check_id: c for c in current._stub_checks()}
    real_checks = {c.check_id: c for c in current.evaluate("x", {"facts": _facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
