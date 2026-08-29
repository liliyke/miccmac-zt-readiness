"""Tests for the Windows branch (facts["os"]["platform"] == "windows") added
to miccmac.checks.monitored/inventoried/controlled/minimized/current. All
tests construct fake facts dicts directly -- no SSH/osquery/VM dependency.
claimed.py and assessed.py are attestation-only and platform-agnostic
already, so they have no Windows branch to test here."""
from miccmac.checks import controlled, current, inventoried, minimized, monitored
from miccmac.model import Status


def _by_id(checks, check_id):
    return next(c for c in checks if c.check_id == check_id)


def _win_facts(**overrides):
    base = {
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200"},
        "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                        "hardware_serial": "VMware-2"},
        "programs": [],
        "services": {},
        "local_admins": ["miccmac"],
        "builtin_admin_enabled": False,
        "firewall_all_profiles_enabled": True,
        "listening_ports": [{"port": "22", "protocol": "6", "address": "0.0.0.0"}],
        "legacy_features_enabled": [],
        "hardening_registry": {"EnableLUA": "1", "SMB1": "0",
                               "DisableRealtimeMonitoring": "0", "NoDriveTypeAutoRun": "255"},
        "last_update_installed_iso": None,
        "expired_certificates": [],
    }
    base.update(overrides)
    return base


def _svc(name, status="RUNNING"):
    return {name: {"status": status, "start_type": "AUTO_START"}}


# ---------- monitored.py ----------

def test_mon01_windows_pass_when_eventlog_running():
    mon01 = _by_id(monitored.evaluate("x", {"facts": _win_facts(services=_svc("EventLog"))}).checks, "MON-01")
    assert mon01.status == Status.PASS


def test_mon01_windows_fail_when_eventlog_not_running():
    mon01 = _by_id(monitored.evaluate("x", {"facts": _win_facts(services={})}).checks, "MON-01")
    assert mon01.status == Status.FAIL


def test_mon02_windows_pass_when_forwarding_agent_running():
    mon02 = _by_id(
        monitored.evaluate("x", {"facts": _win_facts(services=_svc("winlogbeat"))}).checks, "MON-02"
    )
    assert mon02.status == Status.PASS


def test_mon02_windows_fail_when_no_forwarding_agent():
    mon02 = _by_id(monitored.evaluate("x", {"facts": _win_facts(services={})}).checks, "MON-02")
    assert mon02.status == Status.FAIL


def test_mon03_windows_pass_when_osqueryd_running():
    mon03 = _by_id(monitored.evaluate("x", {"facts": _win_facts(services=_svc("osqueryd"))}).checks, "MON-03")
    assert mon03.status == Status.PASS


def test_mon04_windows_pass_when_sysmon_running():
    mon04 = _by_id(monitored.evaluate("x", {"facts": _win_facts(services=_svc("Sysmon"))}).checks, "MON-04")
    assert mon04.status == Status.PASS


def test_mon04_windows_partial_when_only_eventlog_running():
    mon04 = _by_id(monitored.evaluate("x", {"facts": _win_facts(services=_svc("EventLog"))}).checks, "MON-04")
    assert mon04.status == Status.PARTIAL


def test_mon04_windows_fail_when_nothing_running():
    mon04 = _by_id(monitored.evaluate("x", {"facts": _win_facts(services={})}).checks, "MON-04")
    assert mon04.status == Status.FAIL


def test_monitored_windows_control_refs_and_names_unchanged():
    stub_checks = {c.check_id: c for c in monitored._stub_checks()}
    real_checks = {c.check_id: c for c in monitored.evaluate("x", {"facts": _win_facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs


# ---------- inventoried.py ----------

def test_inv03_windows_pass_when_programs_present():
    inv03 = _by_id(
        inventoried.evaluate("x", {"facts": _win_facts(programs=[{"name": "7-Zip", "version": "23.01"}])}).checks,
        "INV-03",
    )
    assert inv03.status == Status.PASS
    assert "programs" in inv03.detail


def test_inv03_windows_fail_when_no_programs():
    inv03 = _by_id(inventoried.evaluate("x", {"facts": _win_facts(programs=[])}).checks, "INV-03")
    assert inv03.status == Status.FAIL


def test_inv02_windows_still_pass_via_shared_system_info_key():
    """INV-02 uses the shared system_info fact key -- no Windows branch
    needed, but confirm it still works when os.platform == windows."""
    inv02 = _by_id(inventoried.evaluate("x", {"facts": _win_facts()}).checks, "INV-02")
    assert inv02.status == Status.PASS


# ---------- controlled.py ----------

def test_ctl01_windows_pass_when_mdm_client_installed():
    ctl01 = _by_id(
        controlled.evaluate("x", {"facts": _win_facts(
            programs=[{"name": "Microsoft Intune Management Extension", "version": "1.0"}]
        )}).checks, "CTL-01",
    )
    assert ctl01.status == Status.PASS


def test_ctl01_windows_fail_when_no_mdm_client():
    ctl01 = _by_id(controlled.evaluate("x", {"facts": _win_facts(programs=[])}).checks, "CTL-01")
    assert ctl01.status == Status.FAIL


def test_ctl02_windows_pass_when_builtin_disabled_and_named_admins():
    ctl02 = _by_id(
        controlled.evaluate("x", {"facts": _win_facts(builtin_admin_enabled=False,
                                                       local_admins=["miccmac"])}).checks,
        "CTL-02",
    )
    assert ctl02.status == Status.PASS


def test_ctl02_windows_partial_when_builtin_disabled_but_no_named_admins():
    ctl02 = _by_id(
        controlled.evaluate("x", {"facts": _win_facts(builtin_admin_enabled=False, local_admins=[])}).checks,
        "CTL-02",
    )
    assert ctl02.status == Status.PARTIAL


def test_ctl02_windows_fail_when_builtin_admin_enabled():
    ctl02 = _by_id(
        controlled.evaluate("x", {"facts": _win_facts(builtin_admin_enabled=True,
                                                       local_admins=["miccmac"])}).checks,
        "CTL-02",
    )
    assert ctl02.status == Status.FAIL


def test_ctl04_windows_pass_when_hardening_tool_installed():
    ctl04 = _by_id(
        controlled.evaluate("x", {"facts": _win_facts(
            programs=[{"name": "Microsoft Security Compliance Toolkit", "version": "1.0"}]
        )}).checks, "CTL-04",
    )
    assert ctl04.status == Status.PASS


def test_ctl03_windows_still_uses_attestation():
    """CTL-03 is attestation-based on both platforms -- no Windows branch."""
    context = {"facts": _win_facts(), "attestation": {"identity_aware_access": {"enabled": True}}}
    ctl03 = _by_id(controlled.evaluate("x", context).checks, "CTL-03")
    assert ctl03.status == Status.PASS


def test_controlled_windows_control_refs_and_names_unchanged():
    stub_checks = {c.check_id: c for c in controlled._stub_checks()}
    real_checks = {c.check_id: c for c in controlled.evaluate("x", {"facts": _win_facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs


# ---------- minimized.py ----------

def test_min01_windows_fail_when_telnet_running():
    min01 = _by_id(minimized.evaluate("x", {"facts": _win_facts(services=_svc("Telnet"))}).checks, "MIN-01")
    assert min01.status == Status.FAIL


def test_min01_windows_pass_when_no_legacy_services():
    min01 = _by_id(minimized.evaluate("x", {"facts": _win_facts(services={})}).checks, "MIN-01")
    assert min01.status == Status.PASS


def test_min02_windows_fail_when_legacy_feature_enabled():
    min02 = _by_id(
        minimized.evaluate("x", {"facts": _win_facts(legacy_features_enabled=["TelnetClient"])}).checks,
        "MIN-02",
    )
    assert min02.status == Status.FAIL


def test_min02_windows_pass_when_no_legacy_features():
    min02 = _by_id(minimized.evaluate("x", {"facts": _win_facts(legacy_features_enabled=[])}).checks, "MIN-02")
    assert min02.status == Status.PASS


def test_min03_windows_pass_when_firewall_on_and_ports_expected():
    min03 = _by_id(
        minimized.evaluate("x", {"facts": _win_facts(
            firewall_all_profiles_enabled=True,
            listening_ports=[{"port": "22", "protocol": "6", "address": "0.0.0.0"}],
        )}).checks, "MIN-03",
    )
    assert min03.status == Status.PASS


def test_min03_windows_fail_when_firewall_off():
    min03 = _by_id(
        minimized.evaluate("x", {"facts": _win_facts(firewall_all_profiles_enabled=False)}).checks, "MIN-03"
    )
    assert min03.status == Status.FAIL


def test_min03_windows_partial_when_unexpected_port_listening():
    min03 = _by_id(
        minimized.evaluate("x", {"facts": _win_facts(
            firewall_all_profiles_enabled=True,
            listening_ports=[{"port": "22", "protocol": "6", "address": "0.0.0.0"},
                             {"port": "8080", "protocol": "6", "address": "0.0.0.0"}],
        )}).checks, "MIN-03",
    )
    assert min03.status == Status.PARTIAL


def test_min04_windows_pass_when_all_registry_settings_hardened():
    min04 = _by_id(minimized.evaluate("x", {"facts": _win_facts()}).checks, "MIN-04")
    assert min04.status == Status.PASS


def test_min04_windows_partial_when_some_registry_settings_not_hardened():
    min04 = _by_id(
        minimized.evaluate("x", {"facts": _win_facts(hardening_registry={"EnableLUA": "1"})}).checks, "MIN-04"
    )
    assert min04.status == Status.PARTIAL


def test_min04_windows_fail_when_no_registry_settings_hardened():
    min04 = _by_id(
        minimized.evaluate("x", {"facts": _win_facts(hardening_registry={})}).checks, "MIN-04"
    )
    assert min04.status == Status.FAIL


def test_minimized_windows_control_refs_and_names_unchanged():
    stub_checks = {c.check_id: c for c in minimized._stub_checks()}
    real_checks = {c.check_id: c for c in minimized.evaluate("x", {"facts": _win_facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs


# ---------- current.py ----------

def test_cur01_windows_pass_when_service_running_and_recent():
    import datetime
    recent = (datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=2)).isoformat()
    cur01 = _by_id(
        current.evaluate("x", {"facts": _win_facts(
            services=_svc("wuauserv"), last_update_installed_iso=recent,
        )}).checks, "CUR-01",
    )
    assert cur01.status == Status.PASS


def test_cur01_windows_fail_when_service_not_running():
    cur01 = _by_id(
        current.evaluate("x", {"facts": _win_facts(services={}, last_update_installed_iso=None)}).checks,
        "CUR-01",
    )
    assert cur01.status == Status.FAIL


def test_cur01_windows_partial_when_no_update_recorded():
    cur01 = _by_id(
        current.evaluate("x", {"facts": _win_facts(
            services=_svc("wuauserv"), last_update_installed_iso=None,
        )}).checks, "CUR-01",
    )
    assert cur01.status == Status.PARTIAL


def test_cur01_windows_fail_when_update_stale():
    import datetime
    stale = (datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=90)).isoformat()
    cur01 = _by_id(
        current.evaluate("x", {"facts": _win_facts(
            services=_svc("wuauserv"), last_update_installed_iso=stale,
        )}).checks, "CUR-01",
    )
    assert cur01.status == Status.FAIL


def test_cur02_windows_not_applicable_when_no_third_party_programs():
    cur02 = _by_id(
        current.evaluate("x", {"facts": _win_facts(
            programs=[{"name": "Windows Terminal", "publisher": "Microsoft Corporation"}]
        )}).checks, "CUR-02",
    )
    assert cur02.status == Status.NOT_APPLICABLE


def test_cur02_windows_partial_when_third_party_and_package_manager_present():
    cur02 = _by_id(
        current.evaluate("x", {"facts": _win_facts(programs=[
            {"name": "7-Zip", "publisher": "Igor Pavlov"},
            {"name": "Chocolatey", "publisher": "Chocolatey Software"},
        ])}).checks, "CUR-02",
    )
    assert cur02.status == Status.PARTIAL


def test_cur02_windows_fail_when_third_party_and_no_package_manager():
    cur02 = _by_id(
        current.evaluate("x", {"facts": _win_facts(
            programs=[{"name": "7-Zip", "publisher": "Igor Pavlov"}]
        )}).checks, "CUR-02",
    )
    assert cur02.status == Status.FAIL


def test_cur04_windows_still_works_via_shared_expired_certificates_key():
    cur04 = _by_id(
        current.evaluate("x", {"facts": _win_facts(
            expired_certificates=[{"common_name": "old.example.com", "not_valid_after": "100"}]
        )}).checks, "CUR-04",
    )
    assert cur04.status == Status.FAIL


def test_current_windows_control_refs_and_names_unchanged():
    stub_checks = {c.check_id: c for c in current._stub_checks()}
    real_checks = {c.check_id: c for c in current.evaluate("x", {"facts": _win_facts()}).checks}
    for check_id, stub in stub_checks.items():
        real = real_checks[check_id]
        assert real.name == stub.name
        assert real.control_refs == stub.control_refs
