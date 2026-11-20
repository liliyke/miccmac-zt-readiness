"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for miccmac.cli: new --methodology/--config/--risk-register flags
and the list-checks subcommand. Run entirely in-process via cli.main();
no target/network dependency (target is always the label 'test-device').

In this file, AI assistance covers the input-file encoding tests at the end,
the two tests added with the reproducible-run options
(test_assess_without_target_still_defaults_to_localhost and
test_assess_connector_json_gains_provenance_text_unchanged), and the tests of
CMMI as the default lens and --methodology none (the first two tests were
rewritten for it: a default run now shows CMMI, and --methodology none gives
the original output, which tests/test_golden_stub.py compares byte for
byte). The --output safeguards are tested in tests/test_output_safety.py."""
from __future__ import annotations

import codecs
import hashlib
import json
from unittest.mock import patch

import pytest

from miccmac.cli import main


def test_assess_default_output_applies_cmmi(capsys):
    """Deliberately changed: CMMI is the default lens (it was opt-in), so a
    default run shows the CMMI lines; --methodology none prints the original
    output (tests/test_golden_stub.py)."""
    assert main(["assess", "test-device"]) == 0
    out = capsys.readouterr().out
    assert "MICCMAC ZERO TRUST DEVICE READINESS ASSESSMENT" in out
    assert "  CMMI            : Unassessed" in out
    assert "[CMMI: Unassessed]" in out
    assert "CMMI (Capability Maturity Model Integration) maturity levels" in out
    assert "risk register" not in out.lower()
    assert main(["assess", "test-device", "--methodology", "none"]) == 0
    out = capsys.readouterr().out
    assert "CMMI" not in out and "methodology" not in out.lower()


def test_assess_default_json_adds_the_cmmi_block_and_none_keeps_the_original_keys(capsys):
    """Deliberately changed: the default JSON has a methodology block (cmmi);
    with --methodology none it has exactly the original four keys."""
    assert main(["assess", "test-device", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data.keys()) == {"target", "overall_score", "readiness_tier", "properties", "methodology"}
    assert data["methodology"]["name"] == "cmmi"
    assert main(["assess", "test-device", "--format", "json", "-m", "none"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data.keys()) == {"target", "overall_score", "readiness_tier", "properties"}


def test_methodology_help_names_the_default_and_none(capsys):
    with pytest.raises(SystemExit):
        main(["assess", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "{cisa-ztmm,cmmi,none}" in help_text
    assert "(default: cmmi)" in help_text and "none turns the lens off" in help_text


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
    config_path.write_text(
        "excluded_checks:\n  - check_id: MON-01\n    reason: \"Not relevant to this pilot.\"\n",
        encoding="utf-8",
    )

    assert main(["assess", "test-device", "--format", "json", "--config", str(config_path)]) == 0
    data = json.loads(capsys.readouterr().out)
    mon = next(p for p in data["properties"] if p["key"] == "monitored")
    mon01 = next(c for c in mon["checks"] if c["check_id"] == "MON-01")
    assert mon01["status"] == "NOT_APPLICABLE"
    assert mon01["detail"] == "Excluded: Not relevant to this pilot."
    assert data["excluded_check_ids"] == ["MON-01"]


def test_assess_with_bad_config_path_errors_cleanly(tmp_path, capsys):
    rc = main(["assess", "test-device", "--config", str(tmp_path / "nope.yaml")])
    assert rc == 2
    assert "error" in capsys.readouterr().err.lower()


def test_assess_with_unknown_excluded_check_errors_cleanly(tmp_path, capsys):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "excluded_checks:\n  - check_id: NOPE-99\n    reason: \"typo'd id\"\n", encoding="utf-8",
    )
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


def test_assess_without_target_still_defaults_to_localhost(capsys):
    # The positional target now defaults to None so --facts can supply it;
    # live and stub runs still map a missing target to "localhost".
    assert main(["assess", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["target"] == "localhost"
    assert "provenance" not in data


def test_assess_connector_json_gains_provenance_text_unchanged(capsys):
    fake_facts = {"os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04"},
                  "system_info": {}, "deb_packages": []}
    with patch("miccmac.connectors.ssh_osquery.SSHOsqueryConnector.collect_facts",
               return_value=fake_facts) as collect:
        rc = main(["assess", "192.0.2.10", "--format", "json", "--connector", "ssh-osquery",
                   "--ssh-user", "assessor", "--ssh-key", "keys/id_ed25519"])
        assert rc == 0
        data = json.loads(capsys.readouterr().out)
        assert main(["assess", "192.0.2.10", "--connector", "ssh-osquery",
                     "--ssh-user", "assessor", "--ssh-key", "keys/id_ed25519"]) == 0
        text = capsys.readouterr().out
    collect.assert_called_with("192.0.2.10")  # no extended facts without --save-facts
    assert data["provenance"]["facts_source"] == "connector"
    assert data["provenance"]["connector"] == "ssh-osquery"
    assert "provenance" not in text.lower()


def test_custom_check_risk_metadata_flows_into_risk_register(tmp_path, capsys):
    """End-to-end: a custom check's declared RISK_METADATA rates it in the
    risk register instead of leaving it UNRATED."""
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (checks_dir / "acme.py").write_text('''
from miccmac.model import CheckResult, Status
CHECK_IDS = ["ACME-01"]
ATTACH_TO = "controlled"
RISK_METADATA = {"ACME-01": {"cis_ig": "IG1", "fair_frequency": "HIGH", "fair_magnitude": "HIGH"}}
def run_checks(target, context):
    return [CheckResult(check_id="ACME-01", name="Acme control", status=Status.FAIL, detail="failing")]
''', encoding="utf-8")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f'custom_checks_dir: "{checks_dir.as_posix()}"\n', encoding="utf-8")

    rc = main(["assess", "test-device", "--format", "json", "--config", str(config_path), "--risk-register"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    entry = next(e for e in data["risk_register"] if e["check_id"] == "ACME-01")
    assert entry["cis_ig"] == "IG1"
    assert entry["risk_rating"] == "CRITICAL"


# ---------------------------------------------------------------- input-file encodings (RD-07)
# Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.
# Windows PowerShell 5.1 saves text as UTF-8 with a byte-order mark
# (Out-File -Encoding utf8) or as UTF-16 LE with one ('>' and Out-File's
# default). Such input files load; the recorded SHA-256 is still that of the
# bytes as read. facts_file.load_envelope stays strict (tests/test_facts_replay.py).

ENCODED_ATTESTATION = {
    "business_owner": {"assigned": True, "name": "Synthetic Owner"},
    "system_administrator": {"assigned": True, "name": "assessor"},
    "business_purpose": {"documented": True, "data_classification": "internal"},
}
ENCODINGS = {
    "utf-8": lambda text: text.encode("utf-8"),
    "utf-8 with BOM": lambda text: text.encode("utf-8-sig"),
    "utf-16 LE with BOM": lambda text: codecs.BOM_UTF16_LE + text.encode("utf-16-le"),
    "utf-16 BE with BOM": lambda text: codecs.BOM_UTF16_BE + text.encode("utf-16-be"),
    "utf-16 LE without BOM": lambda text: text.encode("utf-16-le"),
    "utf-32 with BOM": lambda text: text.encode("utf-32"),
}


def _claimed(data: dict) -> dict:
    claimed = next(p for p in data["properties"] if p["key"] == "claimed")
    return {c["check_id"]: (c["status"], c["detail"]) for c in claimed["checks"]}


@pytest.mark.parametrize("encoding", sorted(ENCODINGS))
def test_input_json_saved_by_windows_powershell_loads(encoding, tmp_path, capsys):
    data = ENCODINGS[encoding](json.dumps(ENCODED_ATTESTATION, indent=2) + "\r\n")
    path = tmp_path / "attestation.json"
    path.write_bytes(data)
    assert main(["assess", "test-device", "--format", "json", "--attestation", str(path),
                 "--as-of", "2026-11-23"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["provenance"]["inputs"]["attestation"]["sha256"] == hashlib.sha256(data).hexdigest()
    reference = tmp_path / "reference.json"
    reference.write_text(json.dumps(ENCODED_ATTESTATION), encoding="utf-8")
    assert main(["assess", "test-device", "--format", "json", "--attestation", str(reference)]) == 0
    assert _claimed(result) == _claimed(json.loads(capsys.readouterr().out))
    assert {status for status, _ in _claimed(result).values()} == {"PASS"}


def test_an_inventory_record_with_a_bom_loads(tmp_path, capsys):
    path = tmp_path / "inventory.json"
    path.write_bytes(json.dumps({"device_id": "dev-1", "tracked": True}).encode("utf-8-sig"))
    fake_facts = {"os": {}, "system_info": {}, "deb_packages": []}
    with patch("miccmac.connectors.ssh_osquery.SSHOsqueryConnector.collect_facts", return_value=fake_facts):
        assert main(["assess", "10.0.0.5", "--format", "json", "--connector", "ssh-osquery",
                     "--ssh-user", "miccmac", "--ssh-key", "/fake/key", "--inventory-record", str(path)]) == 0
    inventoried = next(p for p in json.loads(capsys.readouterr().out)["properties"] if p["key"] == "inventoried")
    assert next(c for c in inventoried["checks"] if c["check_id"] == "INV-01")["status"] == "PASS"


@pytest.mark.parametrize("flag", ["--attestation", "--inventory-record"])
def test_input_json_in_another_encoding_is_a_clean_error(flag, tmp_path, capsys):
    path = tmp_path / "input.json"
    path.write_bytes('{"business_owner": {"assigned": true, "name": "Café Owner"}}'.encode("cp1252"))
    assert main(["assess", "test-device", "--format", "json", flag, str(path)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith(f"error: {flag} file is not valid UTF-8, UTF-16 or UTF-32 text "
                                   f"(save it as UTF-8): ")
    assert captured.out == ""
