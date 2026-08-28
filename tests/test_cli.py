"""Tests for miccmac.cli: new --methodology/--config/--risk-register flags
and the list-checks subcommand. Run entirely in-process via cli.main();
no target/network dependency (target is always the label 'test-device')."""
import json

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


def test_assess_with_risk_register_and_json(capsys):
    assert main(["assess", "test-device", "--format", "json", "--risk-register"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "assessment" in data
    assert "risk_register" in data
    assert data["risk_register"] == []
