"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for miccmac_study.health: the sealed-output health check, its
comparison with a host's ledger rows (--ledger/--host) and the pre-study
check of the input files' dates (--inputs).

Tool outputs are built by running miccmac.engine.run_assessment on fake
Windows facts (in the style of tests/test_windows_checks.py), with a
provenance block per the miccmac-provenance/1 spec and the register from
miccmac.risk_register.build_risk_register. Everything is synthetic and lives
under tmp_path; nothing connects anywhere."""
from __future__ import annotations

import csv
import datetime as dt
import json

import pytest

from miccmac.config import Config, ConfigError
from miccmac.engine import enabled_check_ids, run_assessment
from miccmac.metadata import load_check_metadata
from miccmac.methodology import REGISTRY
from miccmac.risk_register import build_risk_register
from miccmac_study import health
from miccmac_study.__main__ import main
from miccmac_study.formats import LEDGER_COLUMNS, check_ids_fingerprint, sha256_file

TARGET = "192.0.2.10"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
AS_OF = "2026-11-23"

ATTESTATION = {
    "identity_aware_access": {"enabled": False},
    "business_owner": {"assigned": True, "name": "Synthetic Owner"},
    "system_administrator": {"assigned": False},
    "business_purpose": {"documented": True},
    "vulnerability_scanning": {"performed": True, "last_scan": "2026-01-01", "interval_days": 30},
    "compliance_assessment": {"performed": True},
    "finding_remediation_sla": {"tracked": True, "sla_days": 30},
}
INVENTORY = {"device_id": "H1", "tracked": True, "last_reviewed": "2026-01-01"}


def _win_facts(**overrides):
    facts = {
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200"},
        "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "VMware Virtual Platform",
                        "hardware_serial": "VMware-2"},
        "programs": [{"name": "7-Zip", "publisher": "Igor Pavlov"}],
        "services": {"EventLog": {"status": "RUNNING"}, "wuauserv": {"status": "RUNNING"}},
        "local_admins": ["assessor"],
        "builtin_admin_enabled": False,
        "firewall_all_profiles_enabled": True,
        "listening_ports": [{"port": "22", "protocol": "6", "address": "0.0.0.0"},
                            {"port": "8080", "protocol": "6", "address": "0.0.0.0"}],
        "legacy_features_enabled": [],
        "hardening_registry": {"EnableLUA": "1"},
        "last_update_installed_iso": "2026-01-02T00:00:00+00:00",
        "expired_certificates": [],
        # --save-facts always collects an extended section; no check reads it.
        "extra": {"osquery_info": {"ok": True, "data": [{"version": "5.12.1"}]}},
    }
    facts.update(overrides)
    return facts


def _write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _write_facts(study, host, facts, as_of=AS_OF, **overrides):
    envelope = {
        "facts_format": "miccmac-facts/1", "tool_version": "0.1.0", "tool_commit": COMMIT,
        "connector": "ssh-osquery-windows", "target": TARGET,
        "collected_at_utc": "2026-11-23T19:05:00Z", "as_of": as_of, "facts": facts,
    }
    envelope.update(overrides)
    return _write_json(study / "outputs" / f"{host}-facts.json", envelope)


def _write_output(study, host, facts, methodology="cmmi", as_of=AS_OF, register=True,
                  attestation=None, target=TARGET, excluded=(), **provenance_overrides):
    """A tool output as `miccmac assess --format json` writes it, run from the
    study folder with --save-facts outputs/<H>-facts.json."""
    attestation = ATTESTATION if attestation is None else attestation
    inputs = study / "inputs"
    attestation_path = _write_json(inputs / f"{host}-attestation.json", attestation)
    inventory_path = _write_json(inputs / f"{host}-inventory.json", INVENTORY)
    facts_path = study / "outputs" / f"{host}-facts.json"
    config = Config(excluded_checks={c: "Not in the synthetic lab." for c in excluded})
    assessment = run_assessment(target, context={"facts": facts, "attestation": attestation,
                                                 "inventory_record": INVENTORY},
                                config=config, methodology_name=methodology)
    data = assessment.to_dict()
    enabled = enabled_check_ids(config)
    data["provenance"] = {
        "provenance_format": "miccmac-provenance/1", "tool_version": "0.1.0", "tool_commit": COMMIT,
        "tool_tree_clean": True, "python_version": "3.12.10", "platform": "synthetic",
        "run_at_utc": "2026-11-23T19:06:00Z", "as_of": as_of, "as_of_source": "cli",
        "methodology": methodology, "risk_register": register, "target": target,
        "facts_source": "connector", "connector": "ssh-osquery-windows",
        "facts_collected_at_utc": "2026-11-23T19:05:00Z",
        "facts_file": ({"path": f"outputs/{host}-facts.json", "sha256": sha256_file(facts_path), "role": "saved"}
                       if facts_path.exists() else None),
        "inputs": {
            "attestation": {"path": f"inputs/{host}-attestation.json", "sha256": sha256_file(attestation_path)},
            "inventory_record": {"path": f"inputs/{host}-inventory.json", "sha256": sha256_file(inventory_path)},
            "config": None,
        },
        "enabled_check_ids": enabled,
        "enabled_check_ids_fingerprint": check_ids_fingerprint(enabled),
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200",
               "build": "26200"},
        "osquery_version": "5.12.1", "extended_facts": False,
    }
    data["provenance"].update(provenance_overrides)
    if register:
        payload = {"assessment": data, "risk_register": [e.to_dict() for e in build_risk_register(assessment)]}
    else:
        payload = data
    return _write_json(study / "outputs" / f"{host}-{methodology}.json", payload)


@pytest.fixture
def study(tmp_path, monkeypatch):
    """A study folder with H1 facts plus CMMI and CISA ZTMM outputs from the
    same facts, used as the current folder (as the operator would)."""
    folder = tmp_path / "study"
    facts = _win_facts()
    _write_facts(folder, "H1", facts)
    _write_output(folder, "H1", facts, "cmmi")
    _write_output(folder, "H1", facts, "cisa-ztmm")
    _write_json(folder / "inputs" / "list-checks.json", enabled_check_ids())
    monkeypatch.chdir(folder)
    return folder


def _health(capsys, *args):
    rc = main(["health", *args])
    return rc, capsys.readouterr().out.splitlines()


def _problems(lines):
    return [line for line in lines if line.startswith("PROBLEM ")]


def _edit(path, change):
    data = json.loads(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


ALL_OPTIONS = ["--expect-as-of", AS_OF, "--expect-commit", COMMIT[:12],
               "--list-checks", "inputs/list-checks.json"]


# ---------- good files ----------

def test_good_facts_and_outputs_are_all_ok(study, capsys):
    rc, lines = _health(capsys, *ALL_OPTIONS, "--pair", "outputs/H1-facts.json",
                        "outputs/H1-cmmi.json", "outputs/H1-cisa-ztmm.json")
    assert rc == 0
    assert _problems(lines) == []
    assert all(line.startswith("ok      ") for line in lines)
    assert "ok      outputs/H1-facts.json: facts format miccmac-facts/1" in lines
    assert "ok      outputs/H1-facts.json: extended facts: 1 of 1 items collected" in lines
    assert "ok      outputs/H1-cmmi.json: check ids match --list-checks" in lines
    assert "ok      outputs/H1-cmmi.json: ERROR or NOT_IMPLEMENTED present: no" in lines
    assert f"ok      outputs/H1-cmmi.json: as_of is {AS_OF}" in lines
    assert f"ok      outputs/H1-cmmi.json: tool_commit starts with {COMMIT[:12]}" in lines
    assert "ok      outputs/H1-cmmi.json: methodology present (cmmi)" in lines
    assert "ok      outputs/H1-cmmi.json: facts file hash matches" in lines
    assert "ok      outputs/H1-cmmi.json: enabled check ids fingerprint matches the checks" in lines
    assert "ok      outputs/H1-cmmi.json: risk register present: yes" in lines
    assert lines[-5:] == [
        "ok      pair: same target",
        "ok      pair: per-check statuses identical: yes",
        "ok      pair: facts_file.sha256 identical: yes",
        "ok      pair: input hashes identical: yes",
        "ok      pair: as_of identical: yes",
    ]


def test_without_options_reports_values_the_operator_chose_and_the_check_count(study, capsys):
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert rc == 0
    assert "ok      outputs/H1-cmmi.json: 26 checks (no --list-checks given)" in lines
    assert f"ok      outputs/H1-cmmi.json: as_of present ({AS_OF})" in lines
    assert f"ok      outputs/H1-cmmi.json: tool_commit recorded ({COMMIT[:12]})" in lines


def test_library_returns_one_result_per_test(study):
    results = health.run_health(["outputs/H1-cmmi.json"], expect_as_of=AS_OF)
    assert results and all(isinstance(r, health.HealthResult) and r.ok for r in results)
    assert results[0].line() == "ok      outputs/H1-cmmi.json: assessment JSON readable"


# ---------- blinding ----------

def _known_content(study):
    """Every result value the outputs hold, which health must never print."""
    statuses, scores, names, texts = set(), set(), set(), set()
    for name in ("H1-cmmi.json", "H1-cisa-ztmm.json", "H2-cmmi.json"):
        data = json.loads((study / "outputs" / name).read_text(encoding="utf-8"))
        assessment = data["assessment"]
        scores.add(str(assessment["overall_score"]))
        for prop in assessment["properties"]:
            scores.add(str(prop["score"]))
            for check in prop["checks"]:
                statuses.add(check["status"])
                names.add(check["name"])
                texts.update(s for s in (check["detail"], check["evidence"]) if s)
        for entry in data["risk_register"]:
            texts.update(s for s in (entry["detail"], entry["remediation"]) if s)
        for value in assessment["methodology"]["properties"].values():
            scores.add(str(value["percentage"]))
    return statuses, scores, names, texts


def test_output_never_reveals_results(study, capsys):
    other = _win_facts(services={}, firewall_all_profiles_enabled=False)
    _write_facts(study, "H2", other)
    _write_output(study, "H2", other, "cmmi")
    statuses, scores, names, texts = _known_content(study)
    assert {"PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE"} <= statuses  # the fixture is a real mix

    rc, lines = _health(capsys, *ALL_OPTIONS, "--pair", "outputs/H1-facts.json", "outputs/H1-cmmi.json",
                        "outputs/H1-cisa-ztmm.json", "outputs/H2-facts.json", "outputs/H2-cmmi.json")
    output = "\n".join(lines)
    assert rc == 1  # H2 differs from H1, so --pair reports problems; still nothing may leak
    for status in ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE"):
        assert status not in output
    level_labels = {label for m in REGISTRY.values() for label in m.levels} | {"Unassessed"}
    assert level_labels == {"Initial", "Managed", "Defined", "Quantitatively Managed", "Optimizing",
                            "Traditional", "Advanced", "Optimal", "Unassessed"}
    tiers = {"Zero Trust Ready", "Defensible", "Developing", "Not Ready"}
    for word in level_labels | tiers:
        assert word.lower() not in output.lower()
    assert [s for s in scores if s != "None" and s in output] == []
    assert [n for n in names if n in output] == []
    assert [t for t in texts if t in output] == []
    for value in ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNRATED", "MEDIUM", "IG1", "IG2"):
        assert value not in output
    remediations = {m.remediation for m in load_check_metadata().values()}
    assert [r for r in remediations if r in output] == []
    assert "entr" not in output.lower()  # no register entries or entry counts
    assert all(line.startswith(("ok      ", "PROBLEM ")) for line in lines)


# ---------- facts envelope ----------

def test_broken_facts_file_reports_each_problem(study, capsys):
    _write_facts(study, "H1", {"services": {}}, as_of=None, facts_format="miccmac-facts/0",
                 collected_at_utc="yesterday", connector="")
    rc, lines = _health(capsys, "outputs/H1-facts.json")
    assert rc == 1
    assert _problems(lines) == [
        "PROBLEM outputs/H1-facts.json: facts format miccmac-facts/1: unexpected facts_format",
        "PROBLEM outputs/H1-facts.json: collected_at_utc is a UTC timestamp: missing or not a timestamp",
        "PROBLEM outputs/H1-facts.json: as_of present: missing or not a YYYY-MM-DD date",
        "PROBLEM outputs/H1-facts.json: connector and target recorded: connector or target missing",
        "PROBLEM outputs/H1-facts.json: facts include os.platform: facts missing, or without os.platform",
        "PROBLEM outputs/H1-facts.json: extended facts present: "
        "no extended section (facts saved with --save-facts always have one)",
    ]


def test_facts_as_of_must_match_the_expected_session_date(study, capsys):
    rc, lines = _health(capsys, "--expect-as-of", "2026-11-24", "outputs/H1-facts.json")
    assert rc == 1
    assert _problems(lines) == [f"PROBLEM outputs/H1-facts.json: as_of is 2026-11-24: found {AS_OF}"]


def test_extended_facts_not_collected_are_information_not_problems(study, capsys):
    """RD-10: a failed extended item (for example auditpol without elevation)
    is reported on an ok line, named but never shown; formerly it was a
    PROBLEM with exit 1."""
    extra = {
        "bitlocker_status": {"ok": False, "error": "Access is denied for synthetic-secret-path"},
        "secure_boot": {"ok": True, "data": {"enabled": "synthetic-data-value"}},
        "tpm_info": {"ok": False, "error": "timed out"},
    }
    _write_facts(study, "H1", _win_facts(extra=extra))
    rc, lines = _health(capsys, "outputs/H1-facts.json")
    output = "\n".join(lines)
    assert rc == 0
    assert _problems(lines) == []
    assert ("ok      outputs/H1-facts.json: extended facts: 1 of 3 items collected "
            "(not collected: bitlocker_status, tpm_info)") in lines
    for secret in ("Access is denied", "synthetic-secret-path", "synthetic-data-value", "timed out", "secure_boot"):
        assert secret not in output


def test_extended_facts_all_collected(study, capsys):
    _write_facts(study, "H1", _win_facts(extra={"secure_boot": {"ok": True, "data": {}}}))
    rc, lines = _health(capsys, "outputs/H1-facts.json")
    assert rc == 0
    assert "ok      outputs/H1-facts.json: extended facts: 1 of 1 items collected" in lines


@pytest.mark.parametrize("facts, reason", [
    ({"os": {"platform": "windows"}}, "no extended section (facts saved with --save-facts always have one)"),
    ({"os": {"platform": "windows"}, "extra": ["osquery_info"]}, "extra is not a mapping"),
])
def test_facts_without_an_extended_section_is_a_problem(study, capsys, facts, reason):
    _write_facts(study, "H1", facts)
    rc, lines = _health(capsys, "outputs/H1-facts.json")
    assert rc == 1
    assert _problems(lines) == [f"PROBLEM outputs/H1-facts.json: extended facts present: {reason}"]


# ---------- tool output ----------

@pytest.mark.parametrize("change, expected", [
    (lambda d: d["assessment"]["provenance"].update(as_of="2026-11-22"),
     f"as_of is {AS_OF}: found 2026-11-22"),
    (lambda d: d["assessment"]["provenance"].update(tool_commit="f" * 40),
     f"tool_commit starts with {COMMIT[:12]}: found ffffffffffff"),
    (lambda d: d["assessment"]["provenance"].update(tool_commit=None),
     f"tool_commit starts with {COMMIT[:12]}: tool_commit not recorded"),
    (lambda d: d["assessment"]["provenance"].update(tool_tree_clean=False),
     "tool_tree_clean is true: the tool's working tree had uncommitted changes"),
    (lambda d: d["assessment"]["provenance"].update(provenance_format="miccmac-provenance/0"),
     "provenance present (miccmac-provenance/1): unexpected provenance_format"),
    (lambda d: d["assessment"]["provenance"].update(enabled_check_ids_fingerprint="0" * 16),
     "enabled check ids fingerprint matches the checks: fingerprint does not match the output's checks"),
    (lambda d: d["assessment"]["provenance"].update(enabled_check_ids=["MON-01"]),
     "enabled check ids fingerprint matches the checks: enabled_check_ids does not match the output's checks"),
    (lambda d: d["assessment"]["provenance"].update(methodology="cisa-ztmm"),
     "methodology present (cmmi): provenance names a different methodology"),
    (lambda d: d["assessment"]["provenance"].update(facts_file=None),
     "facts file hash matches: no facts file recorded in provenance (run with --save-facts)"),
    (lambda d: d["assessment"]["provenance"]["facts_file"].update(path="elsewhere/H9-facts.json"),
     "facts file hash matches: facts file not found"),
    (lambda d: d["assessment"]["provenance"].update(risk_register=False),
     "risk register present: yes: provenance records the opposite"),
    (lambda d: d["assessment"].pop("methodology"),
     "methodology present: no methodology block (run with --methodology)"),
])
def test_tool_output_problems(study, capsys, change, expected):
    _edit(study / "outputs" / "H1-cmmi.json", change)
    rc, lines = _health(capsys, *ALL_OPTIONS, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _problems(lines) == [f"PROBLEM outputs/H1-cmmi.json: {expected}"]


def test_missing_provenance_is_one_problem(study, capsys):
    _edit(study / "outputs" / "H1-cmmi.json", lambda d: d["assessment"].pop("provenance"))
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _problems(lines) == [
        "PROBLEM outputs/H1-cmmi.json: provenance present (miccmac-provenance/1): no provenance block"]


def test_facts_file_changed_or_missing(study, capsys):
    facts_path = study / "outputs" / "H1-facts.json"
    facts_path.write_text(facts_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _problems(lines) == [
        "PROBLEM outputs/H1-cmmi.json: facts file hash matches: facts file differs from the hash recorded at run time"]
    facts_path.unlink()
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert _problems(lines) == ["PROBLEM outputs/H1-cmmi.json: facts file hash matches: facts file not found"]


def test_facts_file_found_from_another_folder(study, capsys, monkeypatch):
    monkeypatch.chdir(study.parent)
    rc, lines = _health(capsys, "study/outputs/H1-cmmi.json")
    assert rc == 0
    assert "ok      study/outputs/H1-cmmi.json: facts file hash matches" in lines


def test_error_or_not_implemented_is_flagged_without_naming_checks(study, capsys):
    broken = dict(ATTESTATION, vulnerability_scanning={"performed": True, "last_scan": "soon", "interval_days": 30})
    _write_output(study, "H1", _win_facts(), "cmmi", attestation=broken)
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _problems(lines) == ["PROBLEM outputs/H1-cmmi.json: ERROR or NOT_IMPLEMENTED present: yes"]
    assert "ASM-01" not in "\n".join(lines)


def test_unknown_status_is_flagged_without_naming_it(study, capsys):
    def change(data):
        data["assessment"]["properties"][2]["checks"][1]["status"] = "MAYBE"
    _edit(study / "outputs" / "H1-cmmi.json", change)
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _problems(lines) == [
        "PROBLEM outputs/H1-cmmi.json: every status is a known value: a check has an unrecognized status"]
    assert "MAYBE" not in "\n".join(lines) and "CTL-02" not in "\n".join(lines)


def test_property_order_and_check_list_shape(study, capsys):
    def change(data):
        props = data["assessment"]["properties"]
        props[0], props[1] = props[1], props[0]
    _edit(study / "outputs" / "H1-cmmi.json", change)
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert rc == 1
    assert "PROBLEM outputs/H1-cmmi.json: 7 properties in MICCMAC order: properties out of order or unknown" in lines

    _edit(study / "outputs" / "H1-cmmi.json", lambda d: d["assessment"]["properties"][0]["checks"].append("x"))
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert "PROBLEM outputs/H1-cmmi.json: check list readable: a property or check entry is malformed" in lines


def test_list_checks_mismatch_names_only_check_ids(study, capsys):
    (study / "inputs" / "list-checks.json").write_text(
        json.dumps([c for c in enabled_check_ids() if c != "CUR-04"] + ["LAB-01"]), encoding="utf-8")
    rc, lines = _health(capsys, "--list-checks", "inputs/list-checks.json", "outputs/H1-cmmi.json")
    assert rc == 1
    assert _problems(lines) == [
        "PROBLEM outputs/H1-cmmi.json: check ids match --list-checks: not enabled in the output: LAB-01; "
        "enabled in the output but not in --list-checks: CUR-04"]
    (study / "inputs" / "list-checks.json").write_text(json.dumps(enabled_check_ids()[::-1]), encoding="utf-8")
    rc, lines = _health(capsys, "--list-checks", "inputs/list-checks.json", "outputs/H1-cmmi.json")
    assert _problems(lines) == [
        "PROBLEM outputs/H1-cmmi.json: check ids match --list-checks: same check ids in a different order"]


def test_excluded_checks_are_not_counted_as_enabled(study, capsys):
    _write_output(study, "H1", _win_facts(), "cmmi", excluded=("MON-02",))
    enabled = [c for c in enabled_check_ids() if c != "MON-02"]
    (study / "inputs" / "list-checks.json").write_text(json.dumps(enabled), encoding="utf-8")
    rc, lines = _health(capsys, "--list-checks", "inputs/list-checks.json", "outputs/H1-cmmi.json")
    assert rc == 0
    assert _problems(lines) == []


def test_output_without_risk_register(study, capsys):
    _write_output(study, "H1", _win_facts(), "cmmi", register=False)
    rc, lines = _health(capsys, "outputs/H1-cmmi.json")
    assert rc == 0
    assert "ok      outputs/H1-cmmi.json: risk register present: no" in lines


# ---------- --pair ----------

def test_pair_disagreement_reports_no_without_details(study, capsys):
    other = _win_facts(services={}, firewall_all_profiles_enabled=False)
    _write_facts(study, "H2", other, as_of="2026-11-24")
    _write_output(study, "H2", other, "cmmi", as_of="2026-11-24", target="192.0.2.11",
                  attestation=dict(ATTESTATION, business_owner={"assigned": False}))
    rc, lines = _health(capsys, "--pair", "outputs/H1-cmmi.json", "outputs/H2-cmmi.json")
    assert rc == 1
    assert lines[-5:] == [
        "PROBLEM pair: same target: the outputs are not all for the same target",
        "PROBLEM pair: per-check statuses identical: no",
        "PROBLEM pair: facts_file.sha256 identical: no",
        "PROBLEM pair: input hashes identical: no",
        "PROBLEM pair: as_of identical: no",
    ]
    assert "192.0.2.11" not in "\n".join(lines)


def test_pair_needs_two_readable_outputs(study, capsys):
    rc, lines = _health(capsys, "--pair", "outputs/H1-facts.json", "outputs/H1-cmmi.json")
    assert rc == 1
    assert lines[-1] == "PROBLEM pair: needs at least two readable tool outputs"


def test_pair_without_facts_file_is_not_recorded(study, capsys):
    _edit(study / "outputs" / "H1-cisa-ztmm.json", lambda d: d["assessment"]["provenance"].update(facts_file=None))
    rc, lines = _health(capsys, "--pair", "outputs/H1-cmmi.json", "outputs/H1-cisa-ztmm.json")
    assert "PROBLEM pair: facts_file.sha256 identical: not recorded in every output" in lines


# ---------- unreadable files and options ----------

def test_unreadable_files_are_problems_not_crashes(study, capsys):
    (study / "outputs" / "report.txt").write_text("MICCMAC ZERO TRUST DEVICE READINESS ASSESSMENT\n", encoding="utf-8")
    (study / "outputs" / "list.json").write_text("[1, 2]", encoding="utf-8")
    (study / "outputs" / "bom.json").write_bytes(b"\xef\xbb\xbf{}")
    (study / "outputs" / "utf16.json").write_text('{"properties": []}', encoding="utf-16")
    (study / "outputs" / "bad.json").write_text('{"properties": "x"}', encoding="utf-8")
    rc, lines = _health(capsys, "outputs/missing.json", "outputs/report.txt", "outputs/list.json",
                        "outputs/bom.json", "outputs/utf16.json", "outputs/bad.json")
    assert rc == 1
    assert lines == [
        "PROBLEM outputs/missing.json: readable JSON file: file not found",
        "PROBLEM outputs/report.txt: readable JSON file: not valid JSON",
        "PROBLEM outputs/list.json: file type: neither a facts file nor a tool output",
        "PROBLEM outputs/bom.json: readable JSON file: starts with a byte-order mark; save it as plain UTF-8",
        "PROBLEM outputs/utf16.json: readable JSON file: not UTF-8 text",
        "PROBLEM outputs/bad.json: assessment JSON readable: not a miccmac assessment JSON file",
    ]


@pytest.mark.parametrize("args", [
    ["--expect-as-of", "2026/11/23"],
    ["--expect-commit", "not-hex"],
    ["--expect-commit", "abc"],
    ["--list-checks", "inputs/missing.json"],
    ["--ledger", "ledger.csv"],
    ["--host", "H1"],
    ["--ledger", "missing.csv", "--host", "H1"],
    ["--ledger", "ledger.csv", "--host", "STUDY"],
    ["--ledger", "ledger.csv", "--host", "H 1"],
    ["--as-of", "2026-11-23"],
    ["--inputs", "--pair"],
    ["--inputs", "--expect-as-of", "2026-11-23"],
    ["--inputs", "--ledger", "ledger.csv", "--host", "H1"],
    ["--inputs", "--as-of", "2026/11/23"],
])
def test_bad_options_are_usage_errors(study, capsys, args):
    _protocol_ledger(study)
    rc = main(["health", *args, "outputs/H1-cmmi.json"])
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.startswith("error: ")


# ---------- --ledger FILE --host H ----------

def _write_ledger(study, rows):
    """study/ledger.csv from rows of (recorded_at_utc, host, kind, path relative
    to the study); each row gets its file's current hash."""
    ledger_file = study / "ledger.csv"
    with open(ledger_file, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(LEDGER_COLUMNS)
        for when, host, kind, rel in rows:
            path = study / rel
            writer.writerow([when, host, kind, rel, sha256_file(path) if path.is_file() else "0" * 64, "1", ""])
    return ledger_file


def _protocol_ledger(study, worksheet_time="2026-11-23T18:00:00Z", inputs=True, facts=True):
    """H1's rows in protocol order: inputs at setup, the worksheet before the
    run (provenance: facts collected 19:05:00, run 19:06:00), then the outputs."""
    (study / "worksheets").mkdir(exist_ok=True)
    (study / "worksheets" / "H1-worksheet.csv").write_text("row_type,item,value\n", encoding="utf-8")
    rows = []
    if inputs:
        rows += [("2026-11-23T09:00:00Z", "H1", "input", "inputs/H1-attestation.json"),
                 ("2026-11-23T09:00:00Z", "H1", "input", "inputs/H1-inventory.json")]
    rows.append((worksheet_time, "H1", "worksheet", "worksheets/H1-worksheet.csv"))
    if facts:
        rows.append(("2026-11-23T19:10:00Z", "H1", "facts", "outputs/H1-facts.json"))
    rows.append(("2026-11-23T19:10:00Z", "H1", "tool-output", "outputs/H1-cmmi.json"))
    return _write_ledger(study, rows)


def _ledger_lines(lines, label="outputs/H1-cmmi.json"):
    tests = ("inputs match the ledger", "inputs given", "facts file matches the ledger",
             "worksheet hashed before this run", "matches the ledger for")
    return [line for line in lines if line.split(": ", 1)[0].endswith(label)
            and any(f": {test}" in line for test in tests)]


LEDGER_OPTIONS = ["--ledger", "ledger.csv", "--host", "H1"]


def test_ledger_mode_reports_yes_when_the_run_used_the_hashed_files(study, capsys):
    _protocol_ledger(study)
    rc, lines = _health(capsys, *ALL_OPTIONS, *LEDGER_OPTIONS, "--pair", "outputs/H1-facts.json",
                        "outputs/H1-cmmi.json", "outputs/H1-cisa-ztmm.json")
    assert rc == 0, lines
    assert _ledger_lines(lines) == [
        "ok      outputs/H1-cmmi.json: inputs match the ledger for H1: yes",
        "ok      outputs/H1-cmmi.json: inputs given: yes",
        "ok      outputs/H1-cmmi.json: facts file matches the ledger: yes",
        "ok      outputs/H1-cmmi.json: worksheet hashed before this run: yes",
    ]
    assert len(_ledger_lines(lines, "outputs/H1-cisa-ztmm.json")) == 4
    assert not [line for line in lines if "H1-facts.json: inputs" in line]  # tool outputs only


def test_ledger_mode_catches_another_hosts_input_files(study, capsys):
    """BI-04: H1 scored with H2's attestation passed every other test."""
    other = dict(ATTESTATION, business_owner={"assigned": False})
    path = study / "inputs" / "H2-attestation.json"
    path.write_text(json.dumps(other), encoding="utf-8")
    _protocol_ledger(study)
    _edit(study / "outputs" / "H1-cmmi.json", lambda d: d["assessment"]["provenance"]["inputs"].update(
        attestation={"path": "inputs/H2-attestation.json", "sha256": sha256_file(path)}))
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _ledger_lines(lines)[:2] == [
        "PROBLEM outputs/H1-cmmi.json: inputs match the ledger for H1: no (attestation)",
        "ok      outputs/H1-cmmi.json: inputs given: yes",
    ]


@pytest.mark.parametrize("nulls, given", [(("attestation", "inventory_record"), 0), (("inventory_record",), 1)])
def test_ledger_mode_flags_inputs_not_given(study, capsys, nulls, given):
    _protocol_ledger(study)
    _edit(study / "outputs" / "H1-cmmi.json",
          lambda d: d["assessment"]["provenance"]["inputs"].update({key: None for key in nulls}))
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _ledger_lines(lines)[:2] == [
        "ok      outputs/H1-cmmi.json: inputs match the ledger for H1: yes",
        f"PROBLEM outputs/H1-cmmi.json: inputs given: no (the ledger holds 2 input file(s) for H1, but the run "
        f"had {given} of --attestation and --inventory-record)",
    ]


def test_ledger_mode_without_input_rows_says_so(study, capsys):
    _protocol_ledger(study, inputs=False)
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _ledger_lines(lines) == [
        "PROBLEM outputs/H1-cmmi.json: inputs match the ledger for H1: no input rows for H1 in the ledger",
        "ok      outputs/H1-cmmi.json: facts file matches the ledger: yes",
        "ok      outputs/H1-cmmi.json: worksheet hashed before this run: yes",
    ]


def test_ledger_mode_inputs_of_another_host_in_the_ledger_do_not_count(study, capsys):
    ledger_file = _protocol_ledger(study)
    text = ledger_file.read_text(encoding="utf-8-sig").replace(",H1,input,", ",H2,input,")
    ledger_file.write_text(text, encoding="utf-8-sig")
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert _ledger_lines(lines)[0] == ("PROBLEM outputs/H1-cmmi.json: inputs match the ledger for H1: "
                                       "no input rows for H1 in the ledger")


def test_ledger_mode_a_miccmac_config_may_match_a_study_row(study, capsys):
    config = study / "inputs" / "miccmac-config.yaml"
    config.write_text("excluded_checks: []\n", encoding="utf-8")
    _protocol_ledger(study)
    _edit(study / "outputs" / "H1-cmmi.json", lambda d: d["assessment"]["provenance"]["inputs"].update(
        config={"path": "inputs/miccmac-config.yaml", "sha256": sha256_file(config)}))
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert "PROBLEM outputs/H1-cmmi.json: inputs match the ledger for H1: no (config)" in lines
    with open(study / "ledger.csv", "a", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerow(["2026-11-23T09:00:00Z", "STUDY", "other", "inputs/miccmac-config.yaml",
                                 sha256_file(config), "1", ""])
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert "ok      outputs/H1-cmmi.json: inputs match the ledger for H1: yes" in lines


@pytest.mark.parametrize("change, facts_rows, expected", [
    (None, False, "PROBLEM outputs/H1-cmmi.json: facts file matches the ledger: no facts rows for H1 in the ledger"),
    (lambda d: d["assessment"]["provenance"].update(facts_file=None), True,
     "PROBLEM outputs/H1-cmmi.json: facts file matches the ledger: no facts file recorded in provenance"),
    (lambda d: d["assessment"]["provenance"]["facts_file"].update(sha256="ab" * 32), True,
     "PROBLEM outputs/H1-cmmi.json: facts file matches the ledger: no"),
])
def test_ledger_mode_facts_file(study, capsys, change, facts_rows, expected):
    _protocol_ledger(study, facts=facts_rows)
    if change is not None:
        _edit(study / "outputs" / "H1-cmmi.json", change)
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert rc == 1
    assert _ledger_lines(lines)[2] == expected


@pytest.mark.parametrize("worksheet_time, ok", [
    ("2026-11-23T19:04:59Z", True),   # before the facts were collected (19:05:00) and the run (19:06:00)
    ("2026-11-23T19:05:00Z", False),  # the same second as the collection is not before it
    ("2026-11-23T19:05:30Z", False),  # after the collection, before the run
    ("2026-11-23T19:07:00Z", False),  # after the run
])
def test_ledger_mode_worksheet_hashed_strictly_before_the_run(study, capsys, worksheet_time, ok):
    _protocol_ledger(study, worksheet_time=worksheet_time)
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    line = _ledger_lines(lines)[3]
    if ok:
        assert line == "ok      outputs/H1-cmmi.json: worksheet hashed before this run: yes"
    else:
        assert line == "PROBLEM outputs/H1-cmmi.json: worksheet hashed before this run: no"


def test_ledger_mode_counts_only_the_hosts_own_worksheet_path(study, capsys):
    _write_ledger(study, [("2026-11-23T09:00:00Z", "H1", "input", "inputs/H1-attestation.json"),
                          ("2026-11-23T18:00:00Z", "H1", "worksheet", "inputs/H1-attestation.json")])
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert _ledger_lines(lines)[-1] == ("PROBLEM outputs/H1-cmmi.json: worksheet hashed before this run: "
                                        "no worksheet row for worksheets/H1-worksheet.csv in the ledger")


def test_ledger_mode_without_provenance_is_one_problem(study, capsys):
    _protocol_ledger(study)
    _edit(study / "outputs" / "H1-cmmi.json", lambda d: d["assessment"].pop("provenance"))
    rc, lines = _health(capsys, *LEDGER_OPTIONS, "outputs/H1-cmmi.json")
    assert _ledger_lines(lines) == ["PROBLEM outputs/H1-cmmi.json: matches the ledger for H1: no provenance block"]


def test_ledger_mode_never_reveals_results(study, capsys):
    other = _win_facts(services={}, firewall_all_profiles_enabled=False)
    _write_facts(study, "H2", other)
    _write_output(study, "H2", other, "cmmi")
    statuses, scores, names, texts = _known_content(study)
    _protocol_ledger(study, worksheet_time="2026-11-23T19:30:00Z")
    rc, lines = _health(capsys, *ALL_OPTIONS, *LEDGER_OPTIONS, "outputs/H1-cmmi.json", "outputs/H2-cmmi.json")
    output = "\n".join(lines)
    assert rc == 1
    for status in ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE"):
        assert status not in output
    assert [s for s in scores if s != "None" and s in output] == []
    assert [n for n in names if n in output] == []
    assert [t for t in texts if t in output] == []
    assert all(line.startswith(("ok      ", "PROBLEM ")) for line in lines)


# ---------- --inputs ----------

def _input_file(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return str(path)


def test_inputs_with_readable_dates_are_ok(tmp_path, capsys):
    att = _input_file(tmp_path, "att.json", ATTESTATION)
    inv = _input_file(tmp_path, "inv.json", INVENTORY)
    rc, lines = _health(capsys, "--inputs", "--as-of", AS_OF, att, inv)
    assert rc == 0
    assert lines == [f"ok      {att}: every date the checks read is readable",
                     f"ok      {inv}: every date the checks read is readable"]
    rc, lines = _health(capsys, "--inputs", att)
    assert rc == 0 and lines == [f"ok      {att}: every date the checks read is readable"]


def test_inputs_name_each_unreadable_date_with_its_field_and_value(tmp_path, capsys):
    att = _input_file(tmp_path, "att.json", dict(
        ATTESTATION,
        vulnerability_scanning={"performed": True, "last_scan": "11/03/2026", "interval_days": 30},
        compliance_assessment={"performed": True, "last_assessment": "2026-13-01", "interval_days": 30}))
    inv = _input_file(tmp_path, "inv.json", dict(INVENTORY, last_reviewed="Nov 3"))
    rc, lines = _health(capsys, "--inputs", "--as-of", AS_OF, att, inv)
    assert rc == 1
    assert lines == [
        f"PROBLEM {att}: ASM-01 cannot read a date: Attestation's last_scan='11/03/2026' is not a valid ISO date.",
        f"PROBLEM {att}: ASM-02 cannot read a date: Attestation's last_assessment='2026-13-01' is not a valid "
        "ISO date.",
        f"PROBLEM {inv}: INV-04 cannot read a date: Supplied inventory record's last_reviewed='Nov 3' is not a "
        "valid ISO date.",
    ]


def test_inputs_report_a_file_the_checks_cannot_run_with(tmp_path, capsys):
    att = _input_file(tmp_path, "att.json", dict(
        ATTESTATION, vulnerability_scanning={"performed": True, "last_scan": "2026-11-01", "interval_days": "30"}))
    listed = _input_file(tmp_path, "list.json", [1, 2])
    rc, lines = _health(capsys, "--inputs", att, listed)
    assert rc == 1
    assert lines[0].startswith(f"PROBLEM {att}: miccmac's checks run with this file: TypeError: ")
    assert lines[1].startswith(f"PROBLEM {listed}: miccmac's checks run with this file: AttributeError: ")


def test_inputs_are_read_as_miccmac_reads_them(tmp_path, capsys):
    from miccmac.cli import _load_json_file

    files = {
        "bom.json": b"\xef\xbb\xbf" + json.dumps(INVENTORY).encode("utf-8"),
        "utf16.json": json.dumps(INVENTORY).encode("utf-16"),
        "ansi.json": b'{"device_id": "caf\xe9", "tracked": true}',
        "text.json": b"not json",
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
        try:
            _load_json_file(str(tmp_path / name), "input")
            tool_reads_it = True
        except ConfigError:
            tool_reads_it = False
        rc, lines = _health(capsys, "--inputs", str(tmp_path / name))
        assert (rc == 0) == tool_reads_it, (name, lines)
        if not tool_reads_it:
            assert lines[0].startswith(f"PROBLEM {tmp_path / name}: readable input file: input file ")
    rc, lines = _health(capsys, "--inputs", str(tmp_path / "missing.json"))
    assert rc == 1 and lines[0].startswith(f"PROBLEM {tmp_path / 'missing.json'}: readable input file: cannot read")


def test_inputs_never_print_another_status_score_or_detail(tmp_path, capsys):
    """The check runs every input-driven check (with PASS, PARTIAL, FAIL and
    N/A results among them); only ERROR details of the three date checks
    may be printed."""
    attestations = [
        ATTESTATION,
        dict(ATTESTATION, vulnerability_scanning={"performed": True}, compliance_assessment={"performed": False},
             finding_remediation_sla={"tracked": False}),
        dict(ATTESTATION, vulnerability_scanning={"performed": True, "last_scan": "2020-01-01", "interval_days": 1},
             compliance_assessment={"performed": True, "last_assessment": "1/2/2026", "interval_days": 30}),
        {"identity_aware_access": {"enabled": True}},
    ]
    inventories = [INVENTORY, dict(INVENTORY, tracked=False, last_reviewed="2020-01-01"),
                   dict(INVENTORY, last_reviewed=""), {"device_id": "H1"}]
    paths = [_input_file(tmp_path, f"a{i}.json", data) for i, data in enumerate(attestations)]
    paths += [_input_file(tmp_path, f"i{i}.json", data) for i, data in enumerate(inventories)]

    statuses, details, names = set(), set(), set()
    for data in attestations + inventories:
        context = {"facts": {}, "attestation": data, "inventory_record": data,
                   "as_of": dt.date.fromisoformat(AS_OF)}
        for prop in run_assessment("x", context=context).properties:
            for check in prop.checks:
                statuses.add(check.status.value)
                names.add(check.name)
                if check.status.value != "ERROR":
                    details.add(check.detail)
    assert {"PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "ERROR"} <= statuses

    rc, lines = _health(capsys, "--inputs", "--as-of", AS_OF, *paths)
    output = "\n".join(lines)
    assert rc == 1
    assert [line for line in lines if line.startswith("PROBLEM ")] == [
        f"PROBLEM {paths[2]}: ASM-02 cannot read a date: Attestation's last_assessment='1/2/2026' is not a valid "
        "ISO date."]
    for word in ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "NOT_IMPLEMENTED", "ERROR", "UNASSESSED"):
        assert word not in output
    assert [d for d in details if d and d in output] == []
    assert [n for n in names if n in output] == []
    assert "day(s)" not in output and "policy" not in output and "score" not in output.lower()
    assert all(line.startswith(("ok      ", "PROBLEM ")) for line in lines)


def test_inputs_library_function(tmp_path):
    att = _input_file(tmp_path, "att.json", ATTESTATION)
    results = health.check_input_files([att], as_of=AS_OF)
    assert [(r.ok, r.line()) for r in results] == [(True, f"ok      {att}: every date the checks read is readable")]
    with pytest.raises(health.StudyError, match="YYYY-MM-DD"):
        health.check_input_files([att], as_of="23/11/2026")
