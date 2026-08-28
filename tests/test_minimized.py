"""Tests for miccmac.checks.minimized's real detection logic. All tests
construct fake facts dicts directly -- no SSH/osquery/VM dependency."""
from miccmac.checks import minimized
from miccmac.model import Status


def _facts(**overrides):
    base = {
        "systemd_units": {"ufw.service": {"active_state": "active"}},
        "deb_packages": [{"name": "bash", "version": "5.2"}],
        "listening_ports": [{"port": "22", "protocol": "6", "address": "0.0.0.0"},
                            {"port": "5353", "protocol": "17", "address": "0.0.0.0"}],
        "hardening_sysctls": {
            "kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "1",
            "fs.suid_dumpable": "0", "net.ipv4.conf.all.rp_filter": "1",
        },
    }
    base.update(overrides)
    return base


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def test_no_facts_falls_back_to_original_stub_behavior():
    prop = minimized.evaluate("x", {})
    assert len(prop.checks) == 4
    for c in prop.checks:
        assert c.status == Status.NOT_IMPLEMENTED
        assert c.detail == "Check not yet implemented."


def test_min01_pass_when_no_legacy_services_active():
    min01 = _by_id(minimized.evaluate("x", {"facts": _facts()}).checks, "MIN-01")
    assert min01.status == Status.PASS


def test_min01_fail_when_legacy_service_active():
    units = {"rpcbind.service": {"active_state": "active"}}
    min01 = _by_id(minimized.evaluate("x", {"facts": _facts(systemd_units=units)}).checks, "MIN-01")
    assert min01.status == Status.FAIL


def test_min02_pass_when_no_legacy_packages():
    min02 = _by_id(minimized.evaluate("x", {"facts": _facts()}).checks, "MIN-02")
    assert min02.status == Status.PASS


def test_min02_fail_when_legacy_package_installed():
    facts = _facts(deb_packages=[{"name": "telnetd", "version": "1.0"}])
    min02 = _by_id(minimized.evaluate("x", {"facts": facts}).checks, "MIN-02")
    assert min02.status == Status.FAIL


def test_min02_does_not_false_positive_on_substring_match():
    """Regression test: 'nis' is a legacy package name, but must not match
    as a substring of unrelated packages like 'libunistring5' (found via
    live VM testing -- exact match required, not containment)."""
    facts = _facts(deb_packages=[{"name": "libunistring5", "version": "1.3"}])
    min02 = _by_id(minimized.evaluate("x", {"facts": facts}).checks, "MIN-02")
    assert min02.status == Status.PASS


def test_min03_pass_when_ufw_active_and_only_expected_ports():
    min03 = _by_id(minimized.evaluate("x", {"facts": _facts()}).checks, "MIN-03")
    assert min03.status == Status.PASS


def test_min03_partial_when_ufw_active_but_unexpected_port():
    facts = _facts(listening_ports=[
        {"port": "22", "protocol": "6", "address": "0.0.0.0"},
        {"port": "8080", "protocol": "6", "address": "0.0.0.0"},
    ])
    min03 = _by_id(minimized.evaluate("x", {"facts": facts}).checks, "MIN-03")
    assert min03.status == Status.PARTIAL


def test_min03_fail_when_ufw_inactive():
    units = {"ufw.service": {"active_state": "inactive"}}
    min03 = _by_id(minimized.evaluate("x", {"facts": _facts(systemd_units=units)}).checks, "MIN-03")
    assert min03.status == Status.FAIL


def test_min04_pass_when_all_sysctls_hardened():
    min04 = _by_id(minimized.evaluate("x", {"facts": _facts()}).checks, "MIN-04")
    assert min04.status == Status.PASS


def test_min04_partial_when_some_sysctls_hardened():
    facts = _facts(hardening_sysctls={
        "kernel.dmesg_restrict": "1", "kernel.kptr_restrict": "1",
        "fs.suid_dumpable": "2", "net.ipv4.conf.all.rp_filter": "2",
    })
    min04 = _by_id(minimized.evaluate("x", {"facts": facts}).checks, "MIN-04")
    assert min04.status == Status.PARTIAL


def test_min04_fail_when_no_sysctls_hardened():
    facts = _facts(hardening_sysctls={})
    min04 = _by_id(minimized.evaluate("x", {"facts": facts}).checks, "MIN-04")
    assert min04.status == Status.FAIL


def test_control_refs_and_names_unchanged_from_stub():
    stub_checks = {c.check_id: c for c in minimized._stub_checks()}
    real_checks = {c.check_id: c for c in minimized.evaluate("x", {"facts": _facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
