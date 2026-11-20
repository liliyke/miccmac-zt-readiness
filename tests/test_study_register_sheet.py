"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for miccmac_study.register_sheet: risk-register review sheets that
stay sealed (ledger.seal_status) until every host's worksheet is hashed,
whatever --config lists, unless the host was withdrawn in the ledger, and
the one seal-opening ledger row each run that writes sheets appends.

Tool outputs are built by running miccmac.engine.run_assessment on fake
Windows facts with a provenance block per the miccmac-provenance/1 spec and
the register from miccmac.risk_register.build_risk_register. Everything is
synthetic and lives under tmp_path.

In this file, AI assistance also covers the tests added with missing-data
entries, next-level hints and the SP 800-30 fields: the new review-sheet
columns, missing-data and ERROR rows, an output written before those fields
existed, a malformed nested field, and a forced sheet without next-level
hints (test_forced_run_records_the_reason_in_the_ledger_first was updated for
the note that says so)."""
from __future__ import annotations

import csv
import json

import pytest

from miccmac.engine import enabled_check_ids, run_assessment
from miccmac.risk_register import build_risk_register
from miccmac_study import ledger, register_sheet
from miccmac_study.__main__ import main
from miccmac_study.formats import (
    MISSED_GAPS_COLUMNS,
    REGISTER_REVIEW_COLUMNS,
    StudyError,
    check_ids_fingerprint,
    config_template,
    read_csv,
    read_ledger,
)

TARGET = "192.0.2.10"
ATTESTATION = {
    "identity_aware_access": {"enabled": False},
    "business_owner": {"assigned": True, "name": "Synthetic Owner"},
    "system_administrator": {"assigned": False},
    "business_purpose": {"documented": True},
    "vulnerability_scanning": {"performed": False},
    "compliance_assessment": {"performed": True},
    "finding_remediation_sla": {"tracked": False},
    "firmware_currency": {"current": False},
}
JUDGMENT_COLUMNS = ("accurate", "actionable", "prioritized", "reason")


def _win_facts(**overrides):
    facts = {
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200"},
        "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                        "hardware_serial": ""},
        "programs": [{"name": "7-Zip", "publisher": "Igor Pavlov"}],
        "services": {"EventLog": {"status": "RUNNING"}},
        "local_admins": ["assessor"],
        "builtin_admin_enabled": True,
        "firewall_all_profiles_enabled": True,
        "listening_ports": [{"port": "3389", "protocol": "6", "address": "0.0.0.0"}],
        "legacy_features_enabled": ["TelnetClient"],
        "hardening_registry": {"EnableLUA": "1"},
        "last_update_installed_iso": None,
        "expired_certificates": [{"common_name": "old.example.test", "not_valid_after": "100"}],
    }
    facts.update(overrides)
    return facts


def _write_output(study, host, facts, methodology="cmmi", register=True):
    """A tool output as `miccmac assess --format json --risk-register` writes it."""
    assessment = run_assessment(TARGET, context={"facts": facts, "attestation": ATTESTATION,
                                                 "inventory_record": {"device_id": host, "tracked": True}},
                                methodology_name=methodology)
    data = assessment.to_dict()
    enabled = enabled_check_ids()
    data["provenance"] = {
        "provenance_format": "miccmac-provenance/1", "tool_version": "0.1.0",
        "tool_commit": "0123456789abcdef0123456789abcdef01234567", "tool_tree_clean": True,
        "python_version": "3.12.10", "platform": "synthetic", "run_at_utc": "2026-11-23T19:06:00Z",
        "as_of": "2026-11-23", "as_of_source": "cli", "methodology": methodology, "risk_register": register,
        "target": TARGET, "facts_source": "connector", "connector": "ssh-osquery-windows",
        "facts_collected_at_utc": "2026-11-23T19:05:00Z", "facts_file": None,
        "inputs": {"attestation": None, "inventory_record": None, "config": None},
        "enabled_check_ids": enabled, "enabled_check_ids_fingerprint": check_ids_fingerprint(enabled),
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200",
               "build": "26200"},
        "osquery_version": "5.12.1", "extended_facts": False,
    }
    payload = data
    entries = None
    if register:
        entries = [e.to_dict() for e in build_risk_register(assessment)]
        payload = {"assessment": data, "risk_register": entries}
    path = study / "outputs" / f"{host}-{methodology}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return entries


@pytest.fixture
def study(tmp_path):
    """Study folder for H1 and H2: config, filled worksheets, tool outputs.
    No worksheet is hashed yet."""
    folder = tmp_path / "study"
    (folder / "worksheets").mkdir(parents=True)
    (folder / "study.yaml").write_text(config_template(["H1", "H2"], synthetic=True), encoding="utf-8")
    for host in ("H1", "H2"):
        (folder / "worksheets" / f"{host}-worksheet.csv").write_text(
            f"row_type,item,value\nmeta,host_code,{host}\ncheck,MON-01,PASS\n", encoding="utf-8")
    _write_output(folder, "H1", _win_facts())
    _write_output(folder, "H2", _win_facts(services={}, firewall_all_profiles_enabled=False))
    return folder


def _hash_worksheets(study, *hosts):
    for host in hosts:
        ledger.record_files(study / "ledger.csv", host, "worksheet",
                            [study / "worksheets" / f"{host}-worksheet.csv"])


def _sheet(study, host, kind="register-review"):
    return study / "register" / f"{host}-{kind}.csv"


def _run(study, *extra):
    return main(["register-sheet", "--study-dir", str(study), *extra])


def _set_cell(path, row_index, column, value):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    if column not in rows[0]:
        rows[0].append(column)
        for row in rows[1:]:
            row.append("")
    rows[row_index][rows[0].index(column)] = value
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        csv.writer(fh).writerows(rows)


# ---------- the guard ----------

def test_refuses_while_a_host_has_no_hashed_worksheet(study, capsys):
    _hash_worksheets(study, "H1")
    assert _run(study) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: register sheets stay sealed until every worksheet is hashed and "
                                   "unchanged; not yet: H2 (worksheet not hashed: no ledger row of kind "
                                   "worksheet for worksheets/H2-worksheet.csv; hash it with 'ledger record --kind "
                                   "worksheet' once it is finished, or, if this host will not be assessed, "
                                   "record that with 'ledger withdraw').")
    assert "H1 (" not in captured.err
    assert f"python -m miccmac_study ledger record --ledger {study / 'ledger.csv'} --host H" in captured.err
    assert f"python -m miccmac_study ledger withdraw --ledger {study / 'ledger.csv'} --host H" in captured.err
    assert "--force-before-unseal --reason TEXT, which the ledger records" in captured.err
    assert "study.yaml" not in captured.err
    assert not (study / "register").exists()


def test_refuses_when_a_worksheet_changed_after_hashing(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    (study / "worksheets" / "H2-worksheet.csv").write_text("row_type,item,value\ncheck,MON-01,FAIL\n",
                                                           encoding="utf-8")
    assert _run(study) == 2
    err = capsys.readouterr().err
    # Reworded on purpose (V1-N1): the first row's archive copy is named in the advice itself.
    first = read_ledger(study / "ledger.csv")[1]
    assert (f"H2 (worksheet changed after it was hashed: worksheets/H2-worksheet.csv; restore the original bytes "
            f"from ledger-archive/{first.sha256}.csv (or your commit or e-mailed copy); a changed worksheet cannot "
            "be re-hashed)") in err
    assert "stay sealed" in err
    # Re-recording cannot help here, so the refusal does not suggest it.
    assert "ledger record --" not in err and "ledger withdraw" not in err
    assert not (study / "register").exists()


def test_refuses_when_a_hashed_worksheet_is_missing_or_not_written_yet(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    (study / "worksheets" / "H1-worksheet.csv").unlink()
    (study / "worksheets" / "H2-worksheet.csv").unlink()
    _write_output(study, "H3", _win_facts())
    assert _run(study) == 2
    err = capsys.readouterr().err
    assert ("H1 (hashed worksheet is missing: worksheets/H1-worksheet.csv; restore the original bytes from your "
            "commit, e-mail or ledger-archive copy") in err
    assert ("H3 (no worksheet yet: worksheets/H3-worksheet.csv not found; if this host will not be assessed, "
            "record that with 'ledger withdraw')") in err
    assert "ledger withdraw --ledger" in err and "ledger record --ledger" not in err


def test_guard_runs_before_any_tool_output_is_opened(study, capsys):
    (study / "outputs" / "H1-cmmi.json").write_text("not json", encoding="utf-8")
    assert _run(study) == 2
    err = capsys.readouterr().err
    assert "sealed" in err and "not valid JSON" not in err


def test_sealed_hosts_library_function(study):
    _hash_worksheets(study, "H2")
    assert register_sheet.sealed_hosts(study, ["H1", "H2"]) == {"H1": "no worksheet row in the ledger"}
    with pytest.raises(register_sheet.SealedError):
        register_sheet.generate_register_sheets(study)


# ---------- forcing ----------

@pytest.mark.parametrize("args", [
    ["--force-before-unseal"],
    ["--force-before-unseal", "--reason", "   "],
    ["--reason", "no force flag"],
])
def test_force_needs_a_reason_and_a_reason_needs_force(study, capsys, args):
    assert _run(study, *args) == 2
    assert "--reason" in capsys.readouterr().err
    assert not (study / "ledger.csv").exists()
    assert not (study / "register").exists()


def test_forced_run_records_the_reason_in_the_ledger_first(study, capsys):
    _hash_worksheets(study, "H1")
    assert _run(study, "--force-before-unseal", "--reason", "pipeline dry run on synthetic data") == 0
    assert len(capsys.readouterr().out.splitlines()) == 4
    rows = read_ledger(study / "ledger.csv")
    assert len(rows) == 2                     # the FORCE row only, no seal-opening row
    forced = rows[-1]
    assert (forced.host_code, forced.kind, forced.path) == (ledger.STUDY_HOST_CODE, "other", "study.yaml")
    # Deliberately changed: the note says that the forced sheets show no next-level hint.
    assert forced.note == ("register sheets generated before every worksheet was hashed: pipeline dry run on "
                           "synthetic data (next_level cells left blank: the seal was closed)")
    assert forced.note.startswith(register_sheet.FORCE_NOTE_PREFIX)
    assert [state for _, state in ledger.verify_rows(study / "ledger.csv")] == [ledger.OK, ledger.OK]
    assert ledger.archive_path(study / "ledger.csv", forced).is_file()
    assert _sheet(study, "H2").exists()


def test_a_run_that_writes_sheets_appends_one_seal_opening_row(study, capsys):
    """RD-03, V1-N2: the ledger shows when the register (tool findings) became
    visible: exactly one row per run that writes sheets, none for a refusal."""
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    rows = read_ledger(study / "ledger.csv")
    assert len(rows) == 3
    opened = rows[-1]
    assert (opened.host_code, opened.kind, opened.path) == ("STUDY", "protocol", "study.yaml")
    assert opened.note == "seal opened by register-sheet: hosts H1, H2; withdrawn: none"
    assert opened.note.startswith(ledger.SEAL_OPENED_NOTE_PREFIX)
    assert ledger.archive_path(study / "ledger.csv", opened).is_file()
    assert ledger.first_seal_opening(rows) == (2, opened)
    assert [state for _, state in ledger.verify_rows(study / "ledger.csv")] == [ledger.OK] * 3
    capsys.readouterr()

    assert _run(study) == 2                                       # refused: the sheets exist
    assert "refusing to overwrite" in capsys.readouterr().err
    assert len(read_ledger(study / "ledger.csv")) == 3
    assert _run(study, "--overwrite") == 0                        # written again: a second opening
    rows = read_ledger(study / "ledger.csv")
    assert len(rows) == 4 and rows[-1].note == opened.note


def test_a_refused_run_records_no_seal_opening(study, capsys):
    _hash_worksheets(study, "H1")
    assert _run(study) == 2                                       # sealed
    _hash_worksheets(study, "H2")
    _write_output(study, "H2", _win_facts(), register=False)
    assert _run(study) == 2                                       # an output without a register
    assert "risk_register" in capsys.readouterr().err
    rows = read_ledger(study / "ledger.csv")
    assert [r.kind for r in rows] == ["worksheet", "worksheet"] and ledger.first_seal_opening(rows) is None


def test_the_seal_opening_names_every_host_of_the_seal_and_the_config_used(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    h1_only = study / "h1-only.yaml"
    h1_only.write_text("hosts: [H1]\n", encoding="utf-8")
    assert _run(study, "--config", str(h1_only)) == 0
    opened = read_ledger(study / "ledger.csv")[-1]
    assert (opened.path, opened.sha256) == ("h1-only.yaml", ledger.sha256_file(h1_only))
    assert opened.note == "seal opened by register-sheet: hosts H1, H2; withdrawn: none"


def test_a_study_yaml_edited_after_it_was_recorded_keeps_the_sheets_sealed(study, capsys):
    """V1-N2 (a): a temporary edit of the hosts never opens the seal."""
    ledger.record_files(study / "ledger.csv", "STUDY", "other", [study / "study.yaml"], note="study configuration")
    _hash_worksheets(study, "H1", "H2")
    config = study / "study.yaml"
    original = config.read_bytes()
    config.write_text(config_template(["H1"], synthetic=True), encoding="utf-8")
    assert _run(study) == 2
    err = capsys.readouterr().err
    assert "STUDY (study.yaml changed since it was last recorded (ledger line 2, " in err
    assert "editing study.yaml never opens the seal" in err
    assert not (study / "register").exists() and len(read_ledger(study / "ledger.csv")) == 3
    config.write_bytes(original)
    assert _run(study) == 0


def test_force_note_prefix_lives_in_the_ledger_module():
    assert register_sheet.FORCE_NOTE_PREFIX is ledger.FORCE_NOTE_PREFIX
    assert ledger.FORCE_NOTE_PREFIX == "register sheets generated before every worksheet was hashed: "


def test_force_with_every_worksheet_hashed_records_a_seal_opening_and_no_force_row(study, capsys):
    # Changed on purpose (RD-03, V1-N2): every run that writes sheets now records the opening. With the
    # seal open, --force-before-unseal overrides nothing, so the row is the normal seal-opening row.
    _hash_worksheets(study, "H1", "H2")
    assert _run(study, "--force-before-unseal", "--reason", "not needed") == 0
    rows = read_ledger(study / "ledger.csv")
    assert len(rows) == 3
    assert rows[-1].note == "seal opened by register-sheet: hosts H1, H2; withdrawn: none"


def test_forced_run_that_cannot_proceed_records_nothing(study, capsys):
    _write_output(study, "H2", _win_facts(), register=False)
    assert _run(study, "--force-before-unseal", "--reason", "dry run") == 2
    assert "H2" in capsys.readouterr().err
    assert not (study / "ledger.csv").exists()
    assert not (study / "register").exists()


# ---------- the sheets ----------

def test_review_rows_match_the_register_with_blank_judgments(study, capsys):
    entries = {"H1": _write_output(study, "H1", _win_facts()),
               "H2": _write_output(study, "H2", _win_facts(services={}))}
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    expected_paths = [_sheet(study, "H1"), _sheet(study, "H1", "missed-gaps"),
                      _sheet(study, "H2"), _sheet(study, "H2", "missed-gaps")]
    assert capsys.readouterr().out.splitlines() == [str(p) for p in expected_paths]

    for host in ("H1", "H2"):
        assert entries[host], "the fixture must produce register entries"
        header = _sheet(study, host).read_text(encoding="utf-8-sig").splitlines()[0]
        assert header == ",".join(REGISTER_REVIEW_COLUMNS)
        rows = read_csv(_sheet(study, host), REGISTER_REVIEW_COLUMNS)
        assert len(rows) == len(entries[host])
        for number, (row, entry) in enumerate(zip(rows, entries[host]), start=1):
            assert row["host_code"] == host
            assert row["entry_no"] == str(number)
            assert (row["check_id"], row["property"], row["name"], row["tool_status"]) == (
                entry["check_id"], entry["property_key"], entry["name"], entry["status"])
            assert (row["cis_ig"], row["fair_frequency"], row["fair_magnitude"], row["risk_rating"]) == (
                entry["cis_ig"] or "", entry["fair_frequency"] or "", entry["fair_magnitude"] or "",
                entry["risk_rating"])
            assert (row["detail"], row["recommended_fix"]) == (entry["detail"], entry["remediation"] or "")
            assert all(row[c] == "" for c in JUDGMENT_COLUMNS)

        gaps = read_csv(_sheet(study, host, "missed-gaps"), MISSED_GAPS_COLUMNS)
        assert [(g["host_code"], g["gap_no"]) for g in gaps] == [(host, str(n)) for n in range(1, 6)]
        assert all(g["check_id"] == g["description"] == g["evidence"] == "" for g in gaps)


def test_empty_register_gives_a_header_only_review_sheet(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    data = json.loads((study / "outputs" / "H2-cmmi.json").read_text(encoding="utf-8"))
    data["risk_register"] = []
    (study / "outputs" / "H2-cmmi.json").write_text(json.dumps(data), encoding="utf-8")
    assert _run(study) == 0
    assert _sheet(study, "H2").read_text(encoding="utf-8-sig").splitlines() == [",".join(REGISTER_REVIEW_COLUMNS)]


def test_missing_output_or_register_is_refused_and_nothing_is_written(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    _write_output(study, "H2", _win_facts(), register=False)
    assert _run(study) == 2
    err = capsys.readouterr().err
    assert "H2" in err and "risk_register" in err
    assert not (study / "register").exists()

    (study / "outputs" / "H2-cmmi.json").unlink()
    assert _run(study) == 2
    assert "H2-cmmi.json" in capsys.readouterr().err
    assert not (study / "register").exists()


def test_a_subset_config_is_refused_while_other_hosts_have_rows_or_files(study, capsys):
    """BI-01/RD-03: a --config naming fewer hosts never opens the seal
    (formerly this succeeded with only H1 hashed)."""
    _hash_worksheets(study, "H1")
    other_config = study / "h1-only.yaml"
    other_config.write_text("hosts: [H1]\nprimary_methodology: cisa-ztmm\n", encoding="utf-8")
    _write_output(study, "H1", _win_facts(services={}), methodology="cisa-ztmm")
    assert _run(study, "--config", str(other_config)) == 2
    err = capsys.readouterr().err
    assert "stay sealed" in err and "H2 (worksheet not hashed" in err
    assert not (study / "register").exists()
    assert len(read_ledger(study / "ledger.csv")) == 1


def test_uses_the_primary_methodology_and_the_config_option(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    other_config = study / "h1-only.yaml"
    other_config.write_text("hosts: [H1]\nprimary_methodology: cisa-ztmm\n", encoding="utf-8")
    entries = _write_output(study, "H1", _win_facts(services={}), methodology="cisa-ztmm")
    assert _run(study, "--config", str(other_config)) == 0
    rows = read_csv(_sheet(study, "H1"), REGISTER_REVIEW_COLUMNS)
    assert [r["check_id"] for r in rows] == [e["check_id"] for e in entries]
    assert not _sheet(study, "H2").exists()


def _add_h3(study, source):
    """Make H3 known to the study through one source only."""
    if source == "study.yaml":
        (study / "study.yaml").write_text(config_template(["H1", "H2", "H3"], synthetic=True), encoding="utf-8")
    elif source == "ledger row":
        (study / "inputs").mkdir()
        (study / "inputs" / "H3-attestation.json").write_text("{}", encoding="utf-8")
        ledger.record_files(study / "ledger.csv", "H3", "input", [study / "inputs" / "H3-attestation.json"])
    elif source == "worksheet file":
        (study / "worksheets" / "H3-worksheet.csv").write_text("row_type,item,value\n", encoding="utf-8")
    elif source == "facts file":
        (study / "outputs" / "H3-facts.json").write_text('{"facts_format": "miccmac-facts/1"}', encoding="utf-8")
    elif source == "tool output":
        _write_output(study, "H3", _win_facts(), methodology="cisa-ztmm")
    else:
        raise AssertionError(source)


@pytest.mark.parametrize("source", ["study.yaml", "ledger row", "worksheet file", "facts file", "tool output"])
def test_every_host_of_the_study_keeps_the_seal_closed(study, capsys, source):
    _hash_worksheets(study, "H1", "H2")
    subset = study / "h1-h2.yaml"
    subset.write_text("hosts: [H1, H2]\n", encoding="utf-8")
    _add_h3(study, source)
    assert _run(study, "--config", str(subset)) == 2
    err = capsys.readouterr().err
    assert "stay sealed" in err and "not yet: H3 (" in err
    assert "H1 (" not in err and "H2 (" not in err
    assert not (study / "register").exists()


def test_host_codes_and_methodologies_with_dashes_are_parsed_from_file_names(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    _write_output(study, "LAB-1", _win_facts(), methodology="cisa-ztmm")
    assert _run(study) == 2
    err = capsys.readouterr().err
    assert "not yet: LAB-1 (no worksheet yet: worksheets/LAB-1-worksheet.csv not found" in err
    assert "LAB-1-cisa (" not in err


def test_a_withdrawn_host_leaves_the_seal_and_gets_no_sheets(study, capsys):
    _hash_worksheets(study, "H1")
    assert main(["ledger", "withdraw", "--ledger", str(study / "ledger.csv"), "--host", "H2",
                 "--reason", "VM could not be restored"]) == 0
    capsys.readouterr()
    assert _run(study) == 0
    assert capsys.readouterr().out.splitlines() == [str(_sheet(study, "H1")), str(_sheet(study, "H1", "missed-gaps"))]
    assert not _sheet(study, "H2").exists()
    rows = read_ledger(study / "ledger.csv")
    # Changed on purpose (RD-03): the run that wrote the sheets appended its seal-opening row.
    assert [(r.host_code, r.kind) for r in rows] == [("H1", "worksheet"), ("H2", "protocol"), ("STUDY", "protocol")]
    assert rows[-1].note == "seal opened by register-sheet: hosts H1; withdrawn: H2"


def test_every_host_withdrawn_is_refused(study, capsys):
    for host in ("H1", "H2"):
        ledger.withdraw_host(study / "ledger.csv", host, "dropped")
    assert _run(study) == 2
    err = capsys.readouterr().err
    assert "every host in" in err and "is withdrawn in the ledger; there are no sheets to generate" in err
    assert not (study / "register").exists()


# ---------- overwrite protection ----------

def test_existing_sheets_are_kept_without_overwrite(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    before = _sheet(study, "H1").read_bytes()
    assert _run(study) == 2
    assert "refusing to overwrite" in capsys.readouterr().err
    assert _sheet(study, "H1").read_bytes() == before


def test_overwrite_replaces_sheets_whose_judgment_cells_are_blank(study, capsys):
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    _set_cell(_sheet(study, "H1"), 1, "detail", "garbled by a spreadsheet")
    capsys.readouterr()
    assert _run(study, "--overwrite") == 0
    assert len(capsys.readouterr().out.splitlines()) == 4
    assert "garbled" not in _sheet(study, "H1").read_text(encoding="utf-8-sig")


@pytest.mark.parametrize("kind, column, value", [
    ("register-review", "accurate", "Y"),
    ("register-review", "actionable", "N"),
    ("register-review", "prioritized", "UNSURE"),
    ("register-review", "reason", "matches the console"),
    ("register-review", "my_notes", "recheck"),
    ("missed-gaps", "description", "RDP open to every network"),
    ("missed-gaps", "evidence", "netstat output"),
    ("missed-gaps", "check_id", "MIN-03"),
])
def test_overwrite_refuses_sheets_with_judgments(study, capsys, kind, column, value):
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    path = _sheet(study, "H2", kind)
    _set_cell(path, 1, column, value)
    before = {p: p.read_bytes() for p in (study / "register").iterdir()}
    capsys.readouterr()
    assert _run(study, "--overwrite") == 2
    captured = capsys.readouterr()
    assert captured.out == "" and str(path) in captured.err
    assert {p: p.read_bytes() for p in (study / "register").iterdir()} == before


def test_library_entry_point_returns_paths(study):
    _hash_worksheets(study, "H1", "H2")
    paths = register_sheet.generate_register_sheets(study)
    assert [p.name for p in paths] == ["H1-register-review.csv", "H1-missed-gaps.csv",
                                       "H2-register-review.csv", "H2-missed-gaps.csv"]
    with pytest.raises(StudyError, match="non-empty --reason"):
        register_sheet.generate_register_sheets(study, force_reason="  ")


# ---------- missing-data entries, hints and the SP 800-30 columns ----------
# Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

def _write_output_with_inputs(study, host, attestation, inventory_record, methodology="cmmi"):
    """A tool output whose register has missing-data entries."""
    context = {"facts": _win_facts(), "attestation": attestation}
    if inventory_record is not None:
        context["inventory_record"] = inventory_record
    assessment = run_assessment(TARGET, context=context, methodology_name=methodology)
    entries = [e.to_dict() for e in build_risk_register(assessment)]
    path = study / "outputs" / f"{host}-{methodology}.json"
    path.write_text(json.dumps({"assessment": assessment.to_dict(), "risk_register": entries}, indent=2),
                    encoding="utf-8")
    return entries


def test_missing_data_entries_get_review_rows_with_the_new_columns(study, capsys):
    attestation = {k: v for k, v in ATTESTATION.items() if k != "firmware_currency"}
    attestation["vulnerability_scanning"] = {"performed": True, "last_scan": "23/11/2026", "interval_days": 30}
    entries = _write_output_with_inputs(study, "H1", attestation, None)
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    rows = read_csv(_sheet(study, "H1"), REGISTER_REVIEW_COLUMNS)
    assert [r["check_id"] for r in rows] == [e["check_id"] for e in entries]
    by_id = {r["check_id"]: r for r in rows}
    kinds = {e["check_id"]: e["entry_type"] for e in entries}
    assert {kinds[c] for c in ("CUR-03", "INV-01", "INV-04", "ASM-01")} == {"missing-data"}
    assert by_id["ASM-01"]["tool_status"] == "ERROR"            # an ERROR row reaches the sheet
    for entry in entries:
        row = by_id[entry["check_id"]]
        assert row["entry_type"] == entry["entry_type"]
        assert row["recommended_fix"] == entry["sp800_30"]["response"]
        assert row["next_level"] == entry["next_level"]["text"]
        assert (row["threat_source_type"], row["threat_event"], row["sp800_30_review"]) == (
            entry["sp800_30"]["threat_source_type"], entry["sp800_30"]["threat_event"], entry["sp800_30"]["review"])
        if entry["entry_type"] == "missing-data":
            assert row["rating_basis"] == "if the control is absent"
            assert (row["missing_data"], row["how_to_supply"]) == (entry["missing_data"]["what"],
                                                                  entry["missing_data"]["how_to_supply"])
            assert row["recommended_fix"].startswith(entry["missing_data"]["how_to_supply"])
        else:
            assert row["rating_basis"] == "finding" and row["missing_data"] == row["how_to_supply"] == ""
            assert row["recommended_fix"] == (entry["remediation"] or "")    # findings: unchanged
        assert all(row[c] == "" for c in register_sheet.REVIEW_JUDGMENT_COLUMNS)
    assert by_id["CUR-03"]["missing_data"] == ('The attestation file has no "firmware_currency" entry, so CUR-03 '
                                               "could not be evaluated.")
    assert by_id["INV-01"]["missing_data"].startswith("No inventory-system record was given")


def test_an_output_from_before_the_new_fields_still_gives_a_sheet(study, capsys):
    data = json.loads((study / "outputs" / "H1-cmmi.json").read_text(encoding="utf-8"))
    for entry in data["risk_register"]:
        for key in ("entry_type", "missing_data", "next_level", "sp800_30"):
            entry.pop(key)
    data["risk_register"].append(dict(data["risk_register"][0], check_id="X-99", status="ERROR"))
    (study / "outputs" / "H1-cmmi.json").write_text(json.dumps(data), encoding="utf-8")
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    rows = read_csv(_sheet(study, "H1"), REGISTER_REVIEW_COLUMNS)
    assert {r["entry_type"] for r in rows[:-1]} == {"finding"} and rows[-1]["entry_type"] == "missing-data"
    assert all(r["recommended_fix"] == e["remediation"] for r, e in zip(rows, data["risk_register"]))
    assert all(r["next_level"] == r["threat_event"] == "" for r in rows)


@pytest.mark.parametrize("key, value", [("missing_data", "absent"), ("next_level", ["text"]), ("sp800_30", 3)])
def test_a_malformed_nested_field_is_refused_and_nothing_is_written(study, capsys, key, value):
    data = json.loads((study / "outputs" / "H1-cmmi.json").read_text(encoding="utf-8"))
    data["risk_register"][0][key] = value
    (study / "outputs" / "H1-cmmi.json").write_text(json.dumps(data), encoding="utf-8")
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 2
    err = capsys.readouterr().err
    assert f"H1: risk register entry 1 in " in err and f"is malformed: its {key} is a" in err
    assert not (study / "register").exists()


def test_a_forced_sheet_shows_no_next_level_hint(study, capsys):
    """Critique: a sheet forced before the seal opened must not show the
    tool's maturity levels; once the seal is open the hints appear."""
    _hash_worksheets(study, "H1")
    assert _run(study, "--force-before-unseal", "--reason", "early look") == 0
    rows = read_csv(_sheet(study, "H1"), REGISTER_REVIEW_COLUMNS)
    assert rows and all(r["next_level"] == "" for r in rows)
    assert all(r["threat_event"] for r in rows)
    _hash_worksheets(study, "H2")
    assert _run(study, "--overwrite") == 0
    rows = read_csv(_sheet(study, "H1"), REGISTER_REVIEW_COLUMNS)
    assert all(r["next_level"].startswith(("Fixing this check", "Controlled", "Monitored", "Inventoried", "Claimed",
                                           "Minimized", "Assessed", "Current", "If this check")) for r in rows)


@pytest.mark.parametrize("column", ["next_level_accurate", "threat_plausible"])
def test_the_optional_judgment_columns_are_protected_too(study, capsys, column):
    _hash_worksheets(study, "H1", "H2")
    assert _run(study) == 0
    _set_cell(_sheet(study, "H1"), 1, column, "Y")
    assert _run(study, "--overwrite") == 2
    assert f"{column} is filled in" in capsys.readouterr().err
