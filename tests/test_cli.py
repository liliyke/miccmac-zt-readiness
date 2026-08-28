"""Tests for miccmac.cli: new --methodology/--config/--risk-register flags
and the list-checks subcommand. Run entirely in-process via cli.main();
no target/network dependency (target is always the label 'test-device')."""
import json
from unittest.mock import patch

import pytest

from miccmac.cli import main


def test_assess_default_output_unchanged(capsys):
    assert main(["assess", "test-device"]) == 0
    out = capsys.readouterr().out
    assert "MICCMAC ZERO TRUST DEVICE READINESS ASSESSMENT" in out
    assert "methodology" not in out.lower()
    assert "risk register" not in out.lower()


def test_assess_default_json_output_unchanged_keys(capsys):
    assert main(["assess", "test-device", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data.keys()) == {"target", "overall_score", "readiness_tier", "properties"}


def test_assess_with_methodology_flag_adds_methodology_json_key(capsys):
    assert main(["assess", "test-device", "--format", "json", "--methodology", "cmmi"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["methodology"]["name"] == "cmmi"


def test_assess_with_invalid_methodology_choice_rejected_by_argparse():
    with pytest.raises(SystemExit):
        main(["assess", "test-device", "--methodology", "bogus"])


def test_list_checks_text_and_json(capsys):
    assert main(["list-checks"]) == 0
    text_out = capsys.readouterr().out.strip().splitlines()
    assert len(text_out) == 26

    assert main(["list-checks", "--format", "json"]) == 0
    json_out = json.loads(capsys.readouterr().out)
    assert len(json_out) == 26
    assert set(json_out) == set(text_out)


def test_assess_with_config_excludes_checks(tmp_path, capsys):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("excluded_checks:\n  - MON-01\n", encoding="utf-8")

    assert main(["assess", "test-device", "--format", "json", "--config", str(config_path)]) == 0
    data = json.loads(capsys.readouterr().out)
    mon_ids = {c["check_id"] for p in data["properties"] if p["key"] == "monitored" for c in p["checks"]}
    assert "MON-01" not in mon_ids
    assert data["excluded_check_ids"] == ["MON-01"]


def test_assess_with_bad_config_path_errors_cleanly(tmp_path, capsys):
    rc = main(["assess", "test-device", "--config", str(tmp_path / "nope.yaml")])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_assess_with_unknown_excluded_check_errors_cleanly(tmp_path, capsys):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("excluded_checks:\n  - NOPE-99\n", encoding="utf-8")
    rc = main(["assess", "test-device", "--config", str(config_path)])
    assert rc == 2
    assert "unknown" in capsys.readouterr().err.lower()


def test_assess_with_risk_register_flag_appends_section(capsys):
    assert main(["assess", "test-device", "--risk-register"]) == 0
    out = capsys.readouterr().out
    assert "RISK REGISTER" in out
    # scaffold has no FAIL/PARTIAL checks yet -- register should say so, not error
    assert "nothing to remediate" in out.lower()


def test_assess_ssh_osquery_connector_requires_user_and_key(capsys):
    rc = main(["assess", "10.0.0.5", "--connector", "ssh-osquery"])
    assert rc == 2
    assert "--ssh-user" in capsys.readouterr().err


def test_assess_with_ssh_osquery_connector_uses_collected_facts(capsys):
    fake_facts = {
        "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "codename": "resolute"},
        "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                        "hardware_serial": "VMware-1"},
        "deb_packages": [{"name": "bash", "version": "5.2"}],
    }
    with patch("miccmac.connectors.ssh_osquery.SSHOsqueryConnector.collect_facts", return_value=fake_facts):
        rc = main([
            "assess", "10.0.0.5", "--format", "json",
            "--connector", "ssh-osquery", "--ssh-user", "miccmac", "--ssh-key", "/fake/key",
        ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    inv = next(p for p in data["properties"] if p["key"] == "inventoried")
    inv02 = next(c for c in inv["checks"] if c["check_id"] == "INV-02")
    assert inv02["status"] == "PASS"


def test_assess_with_inventory_record_feeds_inv01_and_inv04(tmp_path, capsys):
    import datetime
    record = {"device_id": "dev-1", "tracked": True,
              "last_reviewed": datetime.date.today().isoformat()}
    record_path = tmp_path / "inventory.json"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    fake_facts = {"os": {}, "system_info": {}, "deb_packages": []}
    with patch("miccmac.connectors.ssh_osquery.SSHOsqueryConnector.collect_facts", return_value=fake_facts):
        rc = main([
            "assess", "10.0.0.5", "--format", "json",
            "--connector", "ssh-osquery", "--ssh-user", "miccmac", "--ssh-key", "/fake/key",
            "--inventory-record", str(record_path),
        ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    inv = next(p for p in data["properties"] if p["key"] == "inventoried")
    inv01 = next(c for c in inv["checks"] if c["check_id"] == "INV-01")
    assert inv01["status"] == "PASS"


def test_assess_with_bad_inventory_record_json_errors_cleanly(tmp_path, capsys):
    record_path = tmp_path / "inventory.json"
    record_path.write_text("{not valid json", encoding="utf-8")
    rc = main(["assess", "test-device", "--inventory-record", str(record_path)])
    assert rc == 2
    assert "not valid json" in capsys.readouterr().err.lower()


def test_assess_connector_error_surfaces_as_exit_2(capsys):
    from miccmac.connectors.base import ConnectorError
    with patch("miccmac.connectors.ssh_osquery.SSHOsqueryConnector.collect_facts",
               side_effect=ConnectorError("could not SSH to 10.0.0.5: timed out")):
        rc = main([
            "assess", "10.0.0.5",
            "--connector", "ssh-osquery", "--ssh-user", "miccmac", "--ssh-key", "/fake/key",
        ])
    assert rc == 2
    assert "could not SSH" in capsys.readouterr().err


def test_assess_with_risk_register_and_json(capsys):
    assert main(["assess", "test-device", "--format", "json", "--risk-register"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "assessment" in data
    assert "risk_register" in data
    assert data["risk_register"] == []


def test_assess_with_attestation_feeds_ctl03(tmp_path, capsys):
    attestation = {"identity_aware_access": {"enabled": True}}
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")

    fake_facts = {"os": {}, "system_info": {}, "deb_packages": [], "systemd_units": {},
                  "rsyslog_forwarding_configured": False, "root_locked": True, "sudo_users": ["miccmac"]}
    with patch("miccmac.connectors.ssh_osquery.SSHOsqueryConnector.collect_facts", return_value=fake_facts):
        rc = main([
            "assess", "10.0.0.5", "--format", "json",
            "--connector", "ssh-osquery", "--ssh-user", "miccmac", "--ssh-key", "/fake/key",
            "--attestation", str(attestation_path),
        ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    ctl = next(p for p in data["properties"] if p["key"] == "controlled")
    ctl03 = next(c for c in ctl["checks"] if c["check_id"] == "CTL-03")
    assert ctl03["status"] == "PASS"


def test_assess_without_attestation_ctl03_not_applicable(capsys):
    fake_facts = {"os": {}, "system_info": {}, "deb_packages": [], "systemd_units": {},
                  "rsyslog_forwarding_configured": False, "root_locked": True, "sudo_users": ["miccmac"]}
    with patch("miccmac.connectors.ssh_osquery.SSHOsqueryConnector.collect_facts", return_value=fake_facts):
        rc = main([
            "assess", "10.0.0.5", "--format", "json",
            "--connector", "ssh-osquery", "--ssh-user", "miccmac", "--ssh-key", "/fake/key",
        ])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    ctl = next(p for p in data["properties"] if p["key"] == "controlled")
    ctl03 = next(c for c in ctl["checks"] if c["check_id"] == "CTL-03")
    assert ctl03["status"] == "NOT_APPLICABLE"


def test_assess_with_bad_attestation_json_errors_cleanly(tmp_path, capsys):
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_text("{not valid json", encoding="utf-8")
    rc = main(["assess", "test-device", "--attestation", str(attestation_path)])
    assert rc == 2
    assert "not valid json" in capsys.readouterr().err.lower()
