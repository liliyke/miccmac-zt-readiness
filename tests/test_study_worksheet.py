"""Tests for miccmac_study.worksheet: blank per-host manual worksheets.

Covers the sheet layout and its instructions, the level ranges (full, or
the study's manual_max_level with --study-config), the note when the study
configuration declares no manual level rule yet, the no-leak guarantee (no
tool results in check or level rows; no queries, thresholds, day counts,
cutoffs, risk metadata or remediation text anywhere), the stub-mode
assertion, list-checks validation, and overwrite protection. Fixtures are
synthetic and built under tmp_path."""
from __future__ import annotations

import csv
import json

import pytest

from miccmac.checks import monitored
from miccmac.config import Config
from miccmac.engine import enabled_check_ids, run_assessment
from miccmac.metadata import load_check_metadata
from miccmac.model import CheckResult, Status
from miccmac_study import worksheet
from miccmac_study.__main__ import main
from miccmac_study.formats import (
    LEVEL_SCOPES,
    META_FIELDS,
    StudyError,
    WORKSHEET_COLUMNS,
    WORKSHEET_FORMAT,
    check_ids_fingerprint,
    parse_utc_timestamp,
    read_csv,
)

ENTRY_COLUMNS = ("value", "pass_criterion", "evidence_procedure", "procedure_source",
                 "evidence_notes", "unassessed_reason")

PLUGIN_SOURCE = '''
from miccmac.model import CheckResult, Status

CHECK_IDS = ["LAB-01"]
ATTACH_TO = "controlled"
RISK_METADATA = {"LAB-01": {"cis_ig": "IG2", "fair_frequency": "LOW", "fair_magnitude": "LOW",
                            "remediation": "Synthetic remediation text for LAB-01."}}


def run_checks(target, context):
    return [CheckResult(check_id="LAB-01", name="Synthetic lab control in place",
                        status=Status.%s, detail="Synthetic detail text for LAB-01.",
                        control_refs=["Lab Policy 1.2", "CIS v8 4.1"])]
'''


# ---------- fixtures ----------

def _write_list(path, ids):
    path.write_text(json.dumps(ids, indent=2), encoding="utf-8")
    return path


def _builtin_list(tmp_path):
    return _write_list(tmp_path / "list-checks.json", enabled_check_ids())


def _plugin_config(tmp_path, status="NOT_IMPLEMENTED", excluded=None):
    plugin_dir = tmp_path / "custom_checks"
    plugin_dir.mkdir(exist_ok=True)
    (plugin_dir / "lab_checks.py").write_text(PLUGIN_SOURCE % status, encoding="utf-8")
    lines = ["custom_checks_dir: ./custom_checks"]
    if excluded:
        lines.append("excluded_checks:")
        for check_id in excluded:
            lines += [f"  - check_id: {check_id}", '    reason: "Not in the synthetic lab."']
    config_path = tmp_path / "miccmac-config.yaml"
    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config_path


def _generate(tmp_path, *extra, hosts="H1", list_path=None):
    list_path = list_path or _builtin_list(tmp_path)
    return main(["worksheet", "--list-checks", str(list_path), "--hosts", hosts,
                 "--out", str(tmp_path / "worksheets"), *extra])


def _rows(path, row_type=None):
    rows = read_csv(path, WORKSHEET_COLUMNS)
    return [r for r in rows if row_type is None or r["row_type"] == row_type]


def _meta(path):
    return {r["item"]: r["value"] for r in _rows(path, "meta")}


def _set_cell(path, row_type, item, column, value, scope=None):
    """Edit one cell the way an assessor would, keeping the UTF-8 BOM."""
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    header = rows[0]
    if column not in header:
        header.append(column)
        for row in rows[1:]:
            row.append("")
    for row in rows[1:]:
        if row[0] == row_type and row[1] == item and (scope is None or row[2] == scope):
            row[header.index(column)] = value
            break
    else:
        raise AssertionError(f"no {row_type} row {item}")
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        csv.writer(fh).writerows(rows)


# ---------- layout ----------

def test_writes_one_sheet_per_host_and_prints_only_paths(tmp_path, capsys):
    rc = _generate(tmp_path, "--session-date", "2026-11-23", "--methodology", "cmmi",
                   "--methodology", "cisa-ztmm", hosts="H1,H2")
    assert rc == 0
    expected = [tmp_path / "worksheets" / "H1-worksheet.csv", tmp_path / "worksheets" / "H2-worksheet.csv"]
    assert capsys.readouterr().out.splitlines() == [str(p) for p in expected]
    assert all(p.exists() for p in expected)
    assert _meta(expected[1])["host_code"] == "H2"


def test_meta_rows_in_order_with_instructions(tmp_path):
    _generate(tmp_path, "--session-date", "2026-11-23", "--methodology", "cmmi", "--methodology", "cisa-ztmm")
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    meta_rows = _rows(path, "meta")
    assert [r["item"] for r in meta_rows] == list(META_FIELDS)
    assert all(r["description"] for r in meta_rows)
    by_item = {r["item"]: r for r in meta_rows}
    ids = enabled_check_ids()
    assert by_item["worksheet_format"]["value"] == WORKSHEET_FORMAT
    assert by_item["host_code"]["value"] == "H1"
    assert by_item["session_date"]["value"] == "2026-11-23"
    assert by_item["session_date"]["description"] == \
        "Session date, YYYY-MM-DD. The tool's --as-of uses the same date."
    assert by_item["assessor"]["value"] == ""
    assert by_item["level_rule"]["value"] == ""
    assert by_item["level_rule"]["description"] == "The manual level rule you applied (protocol section 6)."
    # RD-17: the sheet itself says what may be entered (pinned on purpose).
    assert by_item["worksheet_format"]["description"] == (
        "Sheet format, set by the generator. How to fill each check row: in value, your verdict: PASS, PARTIAL, "
        "FAIL, N/A (not applicable), or UNASSESSED with the reason in unassessed_reason. In pass_criterion, what "
        "had to be true for a pass; in evidence_procedure, the steps you followed; in procedure_source, the "
        "external source of those steps (for example a CIS Benchmark audit step or vendor documentation), or "
        "NONE when no external procedure exists; in evidence_notes, what you observed. Each level row states "
        "the levels you may enter.")
    assert by_item["methodologies"]["value"] == "cmmi;cisa-ztmm"
    assert by_item["enabled_checks_fingerprint"]["value"] == check_ids_fingerprint(ids)
    parse_utc_timestamp(by_item["generated_at_utc"]["value"])
    assert by_item["synthetic"]["value"] == "no"
    for row in meta_rows:
        assert all(row[c] == "" for c in ENTRY_COLUMNS[1:])


def test_check_rows_follow_list_order_with_names_and_control_refs_only(tmp_path):
    ids = list(reversed(enabled_check_ids()))  # any order the list gives is kept
    list_path = _write_list(tmp_path / "list.json", ids)
    assert _generate(tmp_path, list_path=list_path) == 0
    check_rows = _rows(tmp_path / "worksheets" / "H1-worksheet.csv", "check")

    stub = run_assessment("x", context={})
    expected = {c.check_id: (p.key, c.name, "; ".join(c.control_refs))
                for p in stub.properties for c in p.checks}
    assert [r["item"] for r in check_rows] == ids
    for row in check_rows:
        assert (row["property"], row["description"], row["control_refs"]) == expected[row["item"]]
        assert all(row[c] == "" for c in ENTRY_COLUMNS)
    assert _meta(tmp_path / "worksheets" / "H1-worksheet.csv")["enabled_checks_fingerprint"] == \
        check_ids_fingerprint(ids)


def test_level_rows_for_each_methodology_and_scope(tmp_path):
    _generate(tmp_path, "--methodology", "cmmi", "--methodology", "cisa-ztmm")
    level_rows = _rows(tmp_path / "worksheets" / "H1-worksheet.csv", "level")
    assert [(r["item"], r["property"]) for r in level_rows] == \
        [(m, s) for m in ("cmmi", "cisa-ztmm") for s in LEVEL_SCOPES]
    by_key = {(r["item"], r["property"]): r for r in level_rows}
    # Without --study-config every row states the methodology's full range (text updated on purpose).
    assert by_key[("cmmi", "monitored")]["description"] == (
        "Manual CMMI level for Monitored (whole number 1-5, or UNASSESSED with a reason in unassessed_reason). "
        "Levels: 1 Initial, 2 Managed, 3 Defined, 4 Quantitatively Managed, 5 Optimizing.")
    assert by_key[("cisa-ztmm", "current")]["description"] == (
        "Manual CISA ZTMM stage for Current (whole number 1-4, or UNASSESSED with a reason in unassessed_reason). "
        "Stages: 1 Traditional, 2 Initial, 3 Advanced, 4 Optimal.")
    excl = by_key[("cmmi", "overall_excl_input_driven")]["description"]
    assert excl.startswith("Optional") and "excluding Claimed and Assessed" in excl
    assert excl.endswith("(whole number 1-5, or UNASSESSED with a reason in unassessed_reason; may stay blank). "
                         "Levels: 1 Initial, 2 Managed, 3 Defined, 4 Quantitatively Managed, 5 Optimizing.")
    assert by_key[("cmmi", "overall")]["description"].startswith("Manual CMMI level overall (whole number 1-5,")
    assert all(r[c] == "" for r in level_rows for c in ENTRY_COLUMNS)


def _study_config(tmp_path, text):
    path = tmp_path / "study.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_study_config_caps_the_level_range_on_every_level_row(tmp_path, capsys):
    """BI-13: under the approved cap of 4, '5 Optimizing' is never offered."""
    config = _study_config(tmp_path, "hosts: [H1, H2]\nsecondary_methodologies: [cisa-ztmm]\n"
                                     "manual_max_level: {cmmi: 4, cisa-ztmm: 3}\n")
    assert _generate(tmp_path, "--study-config", str(config), hosts="H1,H2") == 0
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    assert _meta(path)["methodologies"] == "cmmi;cisa-ztmm"  # the study's methodologies by default
    level_rows = _rows(path, "level")
    assert [(r["item"], r["property"]) for r in level_rows] == \
        [(m, s) for m in ("cmmi", "cisa-ztmm") for s in LEVEL_SCOPES]
    by_key = {(r["item"], r["property"]): r["description"] for r in level_rows}
    assert by_key[("cmmi", "monitored")] == (
        "Manual CMMI level for Monitored (whole number 1-4, or UNASSESSED with a reason in unassessed_reason; "
        "the study configuration allows levels up to 4). Levels: 1 Initial, 2 Managed, 3 Defined, "
        "4 Quantitatively Managed.")
    assert by_key[("cisa-ztmm", "overall")] == (
        "Manual CISA ZTMM stage overall (whole number 1-3, or UNASSESSED with a reason in unassessed_reason; "
        "the study configuration allows stages up to 3). Stages: 1 Traditional, 2 Initial, 3 Advanced.")
    for (methodology, _), text in by_key.items():
        assert "Optimizing" not in text and "1-5" not in text
        if methodology == "cisa-ztmm":
            assert "Optimal" not in text


def test_study_config_at_the_full_range_states_it_without_a_cap_note(tmp_path):
    config = _study_config(tmp_path, "hosts: [H1]\nmanual_max_level: {cmmi: 5}\n")
    assert _generate(tmp_path, "--study-config", str(config)) == 0
    text = _rows(tmp_path / "worksheets" / "H1-worksheet.csv", "level")[0]["description"]
    assert "whole number 1-5" in text and "allows" not in text and text.endswith("5 Optimizing.")


def test_study_config_methodologies_must_all_get_level_rows(tmp_path, capsys):
    config = _study_config(tmp_path, "hosts: [H1]\nsecondary_methodologies: [cisa-ztmm]\n")
    assert _generate(tmp_path, "--study-config", str(config), "--methodology", "cmmi") == 2
    assert "needs level rows for cisa-ztmm" in capsys.readouterr().err
    assert not (tmp_path / "worksheets").exists()
    assert _generate(tmp_path, "--study-config", str(config), "--methodology", "cisa-ztmm",
                     "--methodology", "cmmi") == 0
    assert _meta(tmp_path / "worksheets" / "H1-worksheet.csv")["methodologies"] == "cisa-ztmm;cmmi"


def test_study_config_refuses_a_host_not_in_the_study(tmp_path, capsys):
    """A stray sheet would join the seal (ledger.seal_status) until it is hashed or withdrawn."""
    config = _study_config(tmp_path, "hosts: [H1, H2]\n")
    assert _generate(tmp_path, "--study-config", str(config), hosts="H1,H6") == 2
    err = capsys.readouterr().err
    assert "H6 not in the hosts of" in err and "H1, H2" in err
    assert not (tmp_path / "worksheets").exists()


@pytest.mark.parametrize("content, message", [
    ("hosts: [H1, H2\n", "invalid YAML"),
    ("hosts: []\n", "non-empty 'hosts' list"),
    ("hosts: [H1]\nmanual_max_level: {cmmi: 7}\n", "manual_max_level"),
])
def test_unreadable_study_config_is_refused(tmp_path, capsys, content, message):
    path = _study_config(tmp_path, content)
    assert _generate(tmp_path, "--study-config", str(path)) == 2
    assert message in capsys.readouterr().err
    assert not (tmp_path / "worksheets").exists()


def test_a_study_config_saved_as_ansi_gives_no_traceback(tmp_path, capsys):
    path = tmp_path / "study.yaml"
    path.write_bytes("hosts: [H1]\n# café\n".encode("cp1252"))
    rc = _generate(tmp_path, "--study-config", str(path))
    assert rc in (0, 2)  # 0 if formats.load_study_config decodes ANSI, else a clear error
    if rc == 2:
        assert "UTF-8" in capsys.readouterr().err


NO_MANUAL_RULE = ("note: study.yaml declares no level_rule.manual yet (decision 4); ledger record will refuse to hash "
                  "a filled worksheet until it does")
NO_OVERALL_RULE = ("note: study.yaml declares no level_rule.overall, which the approved manual rule needs for the "
                   "overall levels (decision 4); ledger record will refuse to hash a filled worksheet until it does")


@pytest.mark.parametrize("text, note", [
    ("hosts: [H1]\n", NO_MANUAL_RULE),
    ("hosts: [H1]\nlevel_rule: {manual: null, tool_side: tool-cutoffs, overall: null}\n", NO_MANUAL_RULE),
    ("hosts: [H1]\nmanual_max_level: {cmmi: 4}\nlevel_rule: {manual: approved}\n", NO_OVERALL_RULE),
    ("hosts: [H1]\nmanual_max_level: {cmmi: 4}\nlevel_rule: {manual: approved, overall: pooled-checks}\n", None),
    ("hosts: [H1]\nlevel_rule: {manual: tool-cutoffs}\n", None),
])
def test_study_config_without_a_manual_level_rule_gets_a_note(tmp_path, capsys, text, note):
    """V2-N2, V3-N1: a missing decision 4 shows up when the blank sheet is made, not after it is hashed."""
    config = _study_config(tmp_path, text)
    assert _generate(tmp_path, "--study-config", str(config)) == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [str(tmp_path / "worksheets" / "H1-worksheet.csv")]
    assert captured.err == ("" if note is None else note + "\n")


def test_the_template_study_config_gets_the_note_and_no_study_config_gets_none(tmp_path, capsys):
    from miccmac_study.formats import config_template, load_study_config

    config = _study_config(tmp_path, config_template(["H1"]))
    assert _generate(tmp_path, "--study-config", str(config)) == 0
    assert capsys.readouterr().err == NO_MANUAL_RULE + "\n"
    assert worksheet.level_rule_note(load_study_config(config), "settings.yaml").startswith(
        "note: settings.yaml declares no level_rule.manual yet")
    (tmp_path / "worksheets" / "H1-worksheet.csv").unlink()
    assert _generate(tmp_path) == 0
    assert capsys.readouterr().err == ""


def test_level_description_library_function():
    titles = worksheet.property_titles()
    assert worksheet.level_description("cmmi", "current", titles) == worksheet.level_description(
        "cmmi", "current", titles, max_level=5)
    assert "1-2," in worksheet.level_description("cmmi", "current", titles, max_level=2)


def test_defaults_cmmi_blank_session_date_and_synthetic_flag(tmp_path):
    assert _generate(tmp_path, "--synthetic") == 0
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    meta = _meta(path)
    assert meta["methodologies"] == "cmmi"
    assert meta["session_date"] == ""
    assert meta["synthetic"] == "yes"
    assert {r["item"] for r in _rows(path, "level")} == {"cmmi"}


# ---------- no leak ----------

def _win_facts():
    return {
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200"},
        "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                        "hardware_serial": "VMware-2"},
        "programs": [{"name": "7-Zip", "publisher": "Igor Pavlov"}],
        "services": {"EventLog": {"status": "RUNNING"}, "wuauserv": {"status": "RUNNING"}},
        "local_admins": ["assessor"], "builtin_admin_enabled": False,
        "firewall_all_profiles_enabled": True,
        "listening_ports": [{"port": "22", "protocol": "6", "address": "0.0.0.0"},
                            {"port": "8080", "protocol": "6", "address": "0.0.0.0"}],
        "legacy_features_enabled": [], "hardening_registry": {"EnableLUA": "1"},
        "last_update_installed_iso": "2026-01-02T00:00:00+00:00",
        "expired_certificates": [{"common_name": "old.example.test", "not_valid_after": "100"}],
    }


ATTESTATION = {
    "identity_aware_access": {"enabled": False},
    "business_owner": {"assigned": True, "name": "Synthetic Owner"},
    "system_administrator": {"assigned": False},
    "business_purpose": {"documented": True},
    "vulnerability_scanning": {"performed": True, "last_scan": "2026-01-01", "interval_days": 30},
    "compliance_assessment": {"performed": True},
    "finding_remediation_sla": {"tracked": True, "sla_days": 30},
    "firmware_currency": {"current": False},
}
INVENTORY = {"device_id": "H1", "tracked": True, "last_reviewed": "2026-01-01"}


def _tool_result_strings():
    """Every detail and evidence string the tool produces for some synthetic hosts."""
    contexts = [
        {"facts": _win_facts(), "attestation": ATTESTATION, "inventory_record": INVENTORY},
        {"facts": {"os": {"platform": "linux"}}, "attestation": ATTESTATION, "inventory_record": INVENTORY},
        {"facts": {"os": {"platform": "linux"}}},
    ]
    strings = set()
    for context in contexts:
        assessment = run_assessment("192.0.2.10", context=context, methodology_name="cmmi")
        for prop in assessment.properties:
            for check in prop.checks:
                strings.update(s for s in (check.detail, check.evidence) if s)
    return strings


TOOL_STATUS_WORDS = ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "NOT_IMPLEMENTED", "ERROR")


@pytest.mark.parametrize("extra", [[], ["--study-config"]])
def test_sheet_contains_no_tool_results_queries_thresholds_or_risk_metadata(tmp_path, extra):
    """No tool status in any check or level row (nor in any meta row other
    than the instructions, which name the protocol's verdict values and are
    pinned to META_HELP), and no query, threshold, day count, cutoff, risk
    metadata, remediation or tool detail anywhere."""
    config_path = _plugin_config(tmp_path)
    list_path = _write_list(tmp_path / "list.json", enabled_check_ids(Config.from_file(config_path)))
    if extra:
        study = _study_config(tmp_path, "hosts: [H1, H2]\nsecondary_methodologies: [cisa-ztmm]\n"
                                        "manual_max_level: {cmmi: 4, cisa-ztmm: 4}\n")
        extra = extra + [str(study)]
    assert _generate(tmp_path, "--methodology", "cmmi", "--methodology", "cisa-ztmm",
                     "--session-date", "2026-11-23", "--miccmac-config", str(config_path), *extra,
                     hosts="H1,H2", list_path=list_path) == 0
    paths = sorted((tmp_path / "worksheets").glob("*.csv"))
    assert len(paths) == 2

    metadata = load_check_metadata()
    forbidden = set()
    forbidden.update(m.remediation for m in metadata.values())
    forbidden.update(v for m in metadata.values() for v in (m.cis_ig, m.fair_frequency, m.fair_magnitude))
    forbidden.update(["IG1", "IG2", "IG3", "LOW", "MEDIUM", "HIGH", "UNRATED", "MODERATE", "CRITICAL"])
    forbidden.update(["NOT_APPLICABLE", "NOT_IMPLEMENTED", "ERROR"])
    forbidden.update(["Check not yet implemented", "Excluded:", "SELECT", "FROM ", "day(s)", "7-day",
                      "30-day", "90-day", " days", "policy:", "20/40/70/90", "20.0", "40.0", "70.0", "90.0",
                      "20%", "40%", "70%", "90%", "Zero Trust Ready", "Defensible", "Developing", "Not Ready",
                      "Synthetic remediation", "Synthetic detail", "cis_ig", "fair_frequency", "fair_magnitude",
                      "risk_rating", "recommended_fix"])
    forbidden.update(_tool_result_strings())
    for path in paths:
        text = path.read_text(encoding="utf-8-sig")
        leaked = sorted(s for s in forbidden if s in text)
        assert leaked == []
        assert "osquery" not in text.lower()
        assert "score" not in text.lower() and "tier" not in text.lower()
        for row in _rows(path):
            cells = " ".join(row.values())
            if row["row_type"] == "meta" and row["item"] == "worksheet_format":
                assert row["description"] == worksheet.META_HELP["worksheet_format"]
                cells = row["value"]
            assert [word for word in TOOL_STATUS_WORDS if word in cells] == [], row


# ---------- stub mode ----------

def test_stub_mode_assertion_refuses_a_check_that_runs_logic_without_facts(tmp_path, monkeypatch, capsys):
    def leaky_stubs():
        return [CheckResult(check_id=cid, name="x", status=Status.PASS, detail="ran without facts")
                for cid in ("MON-01", "MON-02", "MON-03", "MON-04")]

    monkeypatch.setattr(monitored, "_stub_checks", leaky_stubs)
    assert _generate(tmp_path) == 2
    err = capsys.readouterr().err
    assert "NOT_IMPLEMENTED" in err and "MON-01" in err
    assert not (tmp_path / "worksheets").exists()
    with pytest.raises(worksheet.StubModeError):
        worksheet.stub_check_info()


def test_stub_mode_assertion_covers_custom_checks(tmp_path, capsys):
    config_path = _plugin_config(tmp_path, status="PASS")
    list_path = _write_list(tmp_path / "list.json", enabled_check_ids(Config.from_file(config_path)))
    assert _generate(tmp_path, "--miccmac-config", str(config_path), list_path=list_path) == 2
    assert "LAB-01" in capsys.readouterr().err
    assert not (tmp_path / "worksheets").exists()


def test_custom_check_that_cannot_run_without_facts_is_reported_cleanly(tmp_path, capsys):
    config_path = _plugin_config(tmp_path)
    source = (tmp_path / "custom_checks" / "lab_checks.py").read_text(encoding="utf-8")
    source = source.replace("def run_checks(target, context):\n",
                            "def run_checks(target, context):\n    context['facts']['os']\n")
    (tmp_path / "custom_checks" / "lab_checks.py").write_text(source, encoding="utf-8")
    list_path = _write_list(tmp_path / "list.json", enabled_check_ids() + ["LAB-01"])
    assert _generate(tmp_path, "--miccmac-config", str(config_path), list_path=list_path) == 2
    assert "stub-mode run (no facts) raised KeyError" in capsys.readouterr().err
    assert not (tmp_path / "worksheets").exists()


def test_stub_check_info_names_every_check_in_stub_mode():
    info = worksheet.stub_check_info()
    assert list(info) == enabled_check_ids()
    assert info["CTL-03"].control_refs == ("NIST 800-207 Tenet 4", "NIST 800-53 AC-3", "CIS v8 6.7")
    assert info["CLM-01"].property_key == "claimed"


# ---------- list-checks and config ----------

def test_custom_checks_need_the_miccmac_config(tmp_path, capsys):
    config_path = _plugin_config(tmp_path)
    list_path = _write_list(tmp_path / "list.json", enabled_check_ids(Config.from_file(config_path)))
    assert _generate(tmp_path, list_path=list_path) == 2
    assert "LAB-01" in capsys.readouterr().err

    assert _generate(tmp_path, "--miccmac-config", str(config_path), list_path=list_path) == 0
    lab = [r for r in _rows(tmp_path / "worksheets" / "H1-worksheet.csv", "check") if r["item"] == "LAB-01"]
    assert [(r["property"], r["description"], r["control_refs"]) for r in lab] == [
        ("controlled", "Synthetic lab control in place", "Lab Policy 1.2; CIS v8 4.1")]


def test_list_checks_must_match_the_miccmac_config(tmp_path, capsys):
    config_path = _plugin_config(tmp_path, excluded=["MON-02"])
    every_id = _write_list(tmp_path / "every.json", enabled_check_ids() + ["LAB-01"])
    assert _generate(tmp_path, "--miccmac-config", str(config_path), list_path=every_id) == 2
    err = capsys.readouterr().err
    assert "MON-02" in err and "not enabled by the config" in err

    enabled = enabled_check_ids(Config.from_file(config_path))
    assert "MON-02" not in enabled
    list_path = _write_list(tmp_path / "list.json", enabled)
    assert _generate(tmp_path, "--miccmac-config", str(config_path), list_path=list_path) == 0
    ids = [r["item"] for r in _rows(tmp_path / "worksheets" / "H1-worksheet.csv", "check")]
    assert ids == enabled


@pytest.mark.parametrize("content, message", [
    ("[]", "non-empty"),
    ('{"checks": ["MON-01"]}', "non-empty JSON list"),
    ('["MON-01", "MON-01"]', "repeats"),
    ('["MON-01", 7]', "only non-empty check-id strings"),
    ('["MON-01", " MON-02"]', "only non-empty check-id strings"),
    ("MON-01\nMON-02\n", "not valid JSON"),
    ('["MON-01", "NOPE-99"]', "unknown check id"),
])
def test_list_checks_validation(tmp_path, capsys, content, message):
    list_path = tmp_path / "list.json"
    list_path.write_text(content, encoding="utf-8")
    assert _generate(tmp_path, list_path=list_path) == 2
    assert message in capsys.readouterr().err
    assert not (tmp_path / "worksheets").exists()


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_list_checks_saved_by_a_powershell_redirect_is_accepted(tmp_path, encoding):
    list_path = tmp_path / "list.json"
    list_path.write_text(json.dumps(enabled_check_ids(), indent=2), encoding=encoding)
    assert worksheet.read_list_checks(list_path) == enabled_check_ids()


@pytest.mark.parametrize("args", [
    ["--session-date", "2026-13-01"],
    ["--session-date", "23/11/2026"],
])
def test_bad_session_date_is_refused(tmp_path, capsys, args):
    assert _generate(tmp_path, *args) == 2
    assert "YYYY-MM-DD" in capsys.readouterr().err


def test_duplicate_or_invalid_hosts_are_refused(tmp_path, capsys):
    assert _generate(tmp_path, hosts="H1,H1") == 2
    assert _generate(tmp_path, hosts="H1,../H2") == 2
    assert not (tmp_path / "worksheets").exists()


# ---------- overwrite protection ----------

def test_existing_sheet_is_never_replaced_without_overwrite(tmp_path, capsys):
    assert _generate(tmp_path) == 0
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    before = path.read_bytes()
    assert _generate(tmp_path) == 2
    assert str(path) in capsys.readouterr().err
    assert path.read_bytes() == before


def test_overwrite_replaces_a_sheet_that_is_still_blank(tmp_path, capsys):
    assert _generate(tmp_path, "--session-date", "2026-11-23") == 0
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    _set_cell(path, "check", "MON-01", "description", "garbled by a spreadsheet")
    capsys.readouterr()

    assert _generate(tmp_path, "--session-date", "2026-11-23", "--overwrite") == 0
    assert capsys.readouterr().out.splitlines() == [str(path)]
    mon01 = [r for r in _rows(path, "check") if r["item"] == "MON-01"][0]
    assert mon01["description"] == "Endpoint security logging enabled"


def test_overwrite_accepts_a_session_date_resaved_by_excel(tmp_path):
    assert _generate(tmp_path, "--session-date", "2026-11-23") == 0
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    _set_cell(path, "meta", "session_date", "value", "11/23/2026")
    assert _generate(tmp_path, "--session-date", "2026-11-23", "--overwrite") == 0
    assert _meta(path)["session_date"] == "2026-11-23"


@pytest.mark.parametrize("row_type, item, column, value, scope", [
    ("check", "MON-01", "value", "PARTIAL", None),
    ("check", "CUR-04", "pass_criterion", "No certificate past its expiry date", None),
    ("check", "INV-02", "evidence_procedure", "Read the BIOS screen", None),
    ("check", "INV-02", "procedure_source", "Vendor manual", None),
    ("check", "ASM-01", "evidence_notes", "Scan log seen", None),
    ("check", "ASM-02", "unassessed_reason", "No access to the GRC tool", None),
    ("level", "cmmi", "value", "3", "monitored"),
    ("level", "cmmi", "evidence_notes", "borderline", "overall"),
    ("meta", "assessor", "value", "assessor", None),
    ("meta", "level_rule", "value", "approved rule", None),
    ("meta", "session_date", "value", "2026-11-24", None),
    ("check", "MON-02", "my_notes", "remember to recheck", None),
])
def test_overwrite_refuses_a_sheet_with_any_entry(tmp_path, capsys, row_type, item, column, value, scope):
    assert _generate(tmp_path, "--session-date", "2026-11-23") == 0
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    _set_cell(path, row_type, item, column, value, scope=scope)
    before = path.read_bytes()
    capsys.readouterr()

    assert _generate(tmp_path, "--session-date", "2026-11-23", "--overwrite") == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(path) in captured.err and "refusing to overwrite" in captured.err
    assert path.read_bytes() == before


def test_overwrite_checks_every_sheet_before_writing_any(tmp_path):
    assert _generate(tmp_path, hosts="H1,H2") == 0
    h1 = tmp_path / "worksheets" / "H1-worksheet.csv"
    h2 = tmp_path / "worksheets" / "H2-worksheet.csv"
    _set_cell(h1, "check", "MON-01", "description", "garbled")
    _set_cell(h2, "check", "MON-01", "value", "FAIL")
    before = h1.read_bytes()
    assert _generate(tmp_path, "--overwrite", hosts="H1,H2") == 2
    assert h1.read_bytes() == before


def test_worksheet_entry_library_function(tmp_path):
    assert _generate(tmp_path, "--session-date", "2026-11-23") == 0
    path = tmp_path / "worksheets" / "H1-worksheet.csv"
    assert worksheet.worksheet_entry(path, "2026-11-23") is None
    assert "session_date" in worksheet.worksheet_entry(path, None)
    _set_cell(path, "check", "CLM-03", "value", "N/A")
    assert worksheet.worksheet_entry(path, "2026-11-23") == "check CLM-03: value is filled in"
    with pytest.raises(StudyError, match="refusing to overwrite"):
        worksheet.generate_worksheets(tmp_path / "list-checks.json", ["H1"], tmp_path / "worksheets",
                                      session_date="2026-11-23", overwrite=True)
