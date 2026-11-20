"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

End-to-end pipeline tests: the synthetic kit (miccmac_study.synthetic) and
the guide's own flow on a non-synthetic study folder.

One synthetic study is built for the module in tmp_path with
`python -m miccmac_study synthetic`, and `agreement` is run on it. The tests
then run every other instrument on that folder in the protocol's order
(health on each facts file and tool output, health --pair and --ledger per
host, health --inputs, ledger verify), check the analysis outputs, recount
H1 by hand, show that a hashed worksheet that was edited keeps the seal
closed until it is restored from ledger-archive/, show that a --facts replay
reproduces a tool output, and confirm that the blank worksheets carry no
tool-derived text. The kit's printed next command is run in PowerShell
where one is installed (Windows PowerShell, or PowerShell 7 on any
platform, such as the CI's Ubuntu runner).

A second study, not synthetic (study.yaml synthetic: false, worksheets
marked synthetic no), is built from the kit's facts, inputs and dummy
entries with the guide's commands, in the protocol's order and with paths
typed relative to the study folder: Setup (folders, list-checks, the
study.yaml template edited for the decisions, health --inputs, the hashes),
then per host the worksheet with --study-config, the lint and hash, the
tool run, the output hashes and health --ledger. Only the live collection
of step 5 is replaced: the kit's facts are saved as the host's facts file
(what --save-facts writes) and scored with --facts. With it the real seal
is shown at work: mid-study (two hosts not hashed) register-sheet and
agreement refuse, also with a configuration listing fewer hosts, or with
study.yaml edited (recorded again after the first tool run, the earlier
version's hosts stay in the seal); the lint refuses a level that does not
follow the declared rule; an edited, hashed worksheet is never recorded
again, and its archive copy restores it; withdrawing a host lets the rest
proceed and is reported; and the complete study opens the seal and exits
0, or 3 when a facts file still carries the synthetic kit's marker. After
the seal has opened, a host added and hashed, a withdrawal (which needs
--after-unseal), and a configuration other than the pre-registered one are
CRITICAL; swapped, duplicated or later-recorded input files are a health
PROBLEM and CRITICAL; and a study run with no -o prints nothing.

Everything is synthetic and nothing connects anywhere. The tool's build
state (tool_commit, tool_tree_clean) is pinned to what a clean checkout
reports, so the health checks do not depend on the git state of the
working copy that runs the tests.

In this file, AI assistance also covers the changes made with the
register's missing-data entries and CMMI as the default lens: the kit's H3
leaves firmware_currency out of its attestation, so health --inputs gets
--allow-missing firmware_currency here and in GuideStudy.setup (each test
says so), H3's CUR-03 missing-data entry is followed through both outputs,
the review sheet and H2, missed gaps are compared with findings only, the
blinding checks cover the new register texts, and every guide line that
writes a tool output names the methodology its file name names.
"""
from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import copy
import csv
import datetime as dt
import importlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, List, Optional, Sequence

import pytest

import miccmac
import miccmac_study
from miccmac import clock, facts_file, provenance
from miccmac.cli import build_parser as miccmac_parser
from miccmac.cli import main as miccmac_main
from miccmac.engine import enabled_check_ids, run_assessment
from miccmac.metadata import load_check_metadata, load_register_metadata
from miccmac_study import agreement as study_agreement
from miccmac_study import ledger as study_ledger
from miccmac_study import synthetic
from miccmac_study.__main__ import COMMANDS
from miccmac_study.__main__ import main
from miccmac_study.formats import (
    LEVEL_SCOPES,
    MISSED_GAPS_COLUMNS,
    OVERALL,
    OVERALL_EXCL,
    REGISTER_REVIEW_COLUMNS,
    SYNTHETIC_BANNER,
    WORKSHEET_COLUMNS,
    config_template,
    facts_name,
    load_study_config,
    load_tool_output,
    normalize_verdict,
    normalize_yes_no,
    parse_utc_timestamp,
    read_csv,
    read_ledger,
    sha256_file,
    tool_output_name,
    worksheet_name,
    write_csv,
    write_json,
)
from miccmac_study.worksheet import META_HELP

SESSION = synthetic.DEFAULT_SESSION_DATE
HOSTS = ["H1", "H2", "H3", "H4", "H5"]
METHODOLOGIES = ("cmmi", "cisa-ztmm")
COMMIT = "0123456789abcdef0123456789abcdef01234567"
DATE_CHECKS = ("INV-04", "ASM-01", "ASM-02", "CUR-01")
INPUT_PROPERTIES = ("claimed", "assessed")
ANALYSIS_FILES = [
    "summary.md", "summary.json", "host_levels.csv", "agreement_h1.csv", "pooled.csv", "check_verdicts.csv",
    "check_agreement.csv", "confusion_levels_cmmi.csv", "confusion_levels_cisa-ztmm.csv",
    "confusion_verdicts.csv", "register_h2.csv", "disagreements.csv",
]
JUDGMENT_COLUMNS = ("value", "pass_criterion", "evidence_procedure", "procedure_source", "evidence_notes",
                    "unassessed_reason")
# What the tool says about a host, which no refusal before unsealing may show.
STATUS_WORDS = ("PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "NOT_IMPLEMENTED")
TIER_WORDS = ("Zero Trust Ready", "Defensible", "Developing", "Not Ready")


# ------------------------------------------------------------------ fixtures and helpers
def _pin_build(mp) -> None:
    """The tool's build state as a clean checkout reports it."""
    mp.setattr(provenance, "tool_commit", lambda: COMMIT)
    mp.setattr(provenance, "tool_tree_clean", lambda: True)


@pytest.fixture(autouse=True)
def pinned_build(monkeypatch):
    _pin_build(monkeypatch)


def _run(entry_point, argv):
    """(exit code, stdout, stderr) of a command-line entry point."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = entry_point(argv)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def _cwd(path: Path) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(str(path))
    try:
        yield
    finally:
        os.chdir(previous)


@pytest.fixture(scope="module")
def pipeline(tmp_path_factory):
    """The synthetic study after `synthetic` and then `agreement` have run."""
    root = tmp_path_factory.mktemp("pipeline") / "synthetic-study"
    with pytest.MonkeyPatch.context() as mp:
        _pin_build(mp)
        code, out, err = _run(main, ["synthetic", "--out", str(root)])
        assert code == 0, err
        agreement_code, agreement_out, agreement_err = _run(main, ["agreement", "--study-dir", str(root)])
    return SimpleNamespace(root=root.resolve(), out=out, err=err, agreement_code=agreement_code,
                           agreement_out=agreement_out, agreement_err=agreement_err)


def _analysis(root: Path, name: str) -> Path:
    return root / "analysis" / ("SYNTHETIC-" + name)


def _rows(path: Path):
    return read_csv(path, ())


def _worksheet_rows(path: Path):
    return read_csv(path, WORKSHEET_COLUMNS)


def _sheet(root: Path, host: str, blank: bool = False) -> Path:
    folder = synthetic.BLANK_WORKSHEETS_DIR if blank else "worksheets"
    return root / folder / worksheet_name(host)


def _output(root: Path, host: str, methodology: str = "cmmi"):
    return load_tool_output(root / "outputs" / tool_output_name(host, methodology))


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _set_cell(path: Path, row_type: str, item: str, column: str, value: str, prop: Optional[str] = None) -> None:
    """Edit one cell the way an assessor would, keeping the UTF-8 BOM (the
    first row with that row_type and item, and that property if given)."""
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    index = rows[0].index(column)
    for row in rows[1:]:
        if row[0] == row_type and row[1] == item and (prop is None or row[2] == prop):
            row[index] = value
            break
    else:
        raise AssertionError(f"no {row_type} row {item} {prop or ''}")
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        csv.writer(fh).writerows(rows)


def _wilson(k: int, n: int):
    """95% Wilson interval, written out independently of miccmac_study.stats."""
    z = 1.959963984540054
    p = k / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z / denominator * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (0.0 if k == 0 else centre - half), (1.0 if k == n else centre + half)


def _approved_level(verdicts) -> str:
    """The approved 4-bucket rule, written out independently of synthetic.py."""
    scorable = [v for v in verdicts if v in ("PASS", "PARTIAL", "FAIL")]
    if not scorable:
        return "UNASSESSED"
    ratio = Fraction(sum({"PASS": 2, "PARTIAL": 1, "FAIL": 0}[v] for v in scorable), 2 * len(scorable))
    return "1" if ratio == 0 else "2" if ratio < Fraction(1, 2) else "3" if ratio < 1 else "4"


def _critical(summary: dict) -> List[tuple]:
    return sorted((r["check"], r["host"]) for r in summary["integrity"]["checks"] if r["result"] == "CRITICAL")


def _register_texts(entries) -> set:
    """Every text a register entry carries: detail, fix, what is missing and
    how to supply it, the next-level hint, the threat event and the response."""
    found = set()
    for e in entries or []:
        missing, hint, sp800_30 = (e.get(k) or {} for k in ("missing_data", "next_level", "sp800_30"))
        found.update(s for s in (e["detail"], e["remediation"], missing.get("what"), missing.get("how_to_supply"),
                                 hint.get("text"), sp800_30.get("threat_event"), sp800_30.get("response")) if s)
    return found


def _tool_texts(root: Path, hosts: Sequence[str]) -> set:
    """Every result string the tool wrote for these hosts: details, evidence,
    register text, plus the status and tier words."""
    found = set(STATUS_WORDS) | set(TIER_WORDS)
    for host in hosts:
        for methodology in METHODOLOGIES:
            output = _output(root, host, methodology)
            found.update(s for c in output.checks() for s in (c["detail"], c["evidence"]) if s)
            found.update(_register_texts(output.risk_register))
    return found


# ------------------------------------------------------------------ the synthetic command
def test_synthetic_prints_only_the_folder_and_the_next_command(pipeline):
    quote = synthetic.powershell_quote
    repo = Path(synthetic.__file__).resolve().parent.parent
    assert (repo / "miccmac_study" / "__main__.py").is_file()
    command = (f"$env:PYTHONPATH = {quote(str(repo))}; & {quote(sys.executable)} -m miccmac_study agreement "
               f"--study-dir {quote(str(pipeline.root))}")
    assert pipeline.out.splitlines() == [str(pipeline.root), command]
    assert synthetic.next_command(pipeline.root) == command
    assert pipeline.err == ""


@pytest.mark.parametrize("text, quoted", [
    (r"C:\Users\me\Study Data\synthetic", r'"C:\Users\me\Study Data\synthetic"'),
    (r"C:\$Data\kit", r'"C:\`$Data\kit"'),
    (r"C:\a`b\kit", r'"C:\a``b\kit"'),
    ('C:\\a"b', '"C:\\a`"b"'),
])
def test_powershell_quoting_keeps_a_path_literal(text, quoted):
    assert synthetic.powershell_quote(text) == quoted


def _powershell() -> Optional[str]:
    for name in ("powershell", "pwsh"):
        found = shutil.which(name)
        if found:
            return found
    return None


@pytest.mark.skipif(_powershell() is None, reason="needs Windows PowerShell or PowerShell 7")
def test_the_printed_next_command_runs_as_printed_in_powershell(tmp_path):
    """The second printed line, pasted into PowerShell in another folder with
    no PYTHONPATH set, runs agreement on the new folder (a path with a space
    and a $ in it, which PowerShell would otherwise expand), exit 0 with no
    CRITICAL.

    This also runs under PowerShell 7 (pwsh) on Linux, as on the CI's Ubuntu
    runner: the line uses only what pwsh does the same on every platform
    ($env: assignment, inherited by the child; double-quoted strings with
    backtick escapes; the & call operator, which passes each quoted string
    as one argument), and the paths it quotes are this platform's own
    (sys.executable, the repository folder, tmp_path)."""
    study = tmp_path / "kit $x 1"
    code, out, err = _run(main, ["synthetic", "--out", str(study), "--hosts", "1"])
    assert code == 0, err
    line = out.splitlines()[1]
    script = line + "; exit $LASTEXITCODE"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    env = {name: value for name, value in os.environ.items() if name.upper() != "PYTHONPATH"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    result = subprocess.run([_powershell(), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            cwd=str(elsewhere), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=300)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "agreement: wrote " in result.stdout and "CRITICAL" not in result.stdout
    assert _analysis(study.resolve(), "summary.md").is_file()


def test_folder_follows_the_study_layout_and_is_labelled_synthetic(pipeline):
    root = pipeline.root
    config = load_study_config(root / "study.yaml")
    assert config.hosts == HOSTS
    assert (config.threshold, config.primary_methodology, config.secondary_methodologies) == (
        Fraction(4, 5), "cmmi", ["cisa-ztmm"])
    assert config.manual_max_level == {"cmmi": 4, "cisa-ztmm": 4}
    assert config.level_rule == synthetic.SYNTHETIC_LEVEL_RULE_CONFIG == {
        "manual": "approved", "tool_side": "tool-cutoffs", "overall": "pooled-checks"}
    assert config.weighted_kappa is True and config.synthetic is True
    readme = (root / synthetic.README_NAME).read_text(encoding="utf-8")
    assert readme.startswith(SYNTHETIC_BANNER) and "not study results" in readme
    assert "ledger-archive/" in readme and "level_rule" in readme
    flowing = " ".join(readme.split())
    assert ('register-sheet and agreement record each seal opening there too: a "seal opened by ..." row'
            in flowing)
    assert json.loads((root / "inputs" / "list-checks.json").read_text(encoding="utf-8")) == enabled_check_ids()

    platforms = set()
    for host in HOSTS:
        for name in (synthetic.attestation_name(host), synthetic.inventory_name(host)):
            assert _json(root / "inputs" / name)["synthetic"] is True
        envelope = _json(root / "outputs" / facts_name(host))
        assert (envelope["facts_format"], envelope["connector"], envelope["target"], envelope["as_of"]) == (
            "miccmac-facts/1", "synthetic", f"synthetic-{host}", SESSION)
        if dt.date.fromisoformat(SESSION) >= dt.datetime.now(dt.timezone.utc).date():
            assert envelope["collected_at_utc"].startswith(SESSION)
        platforms.add(envelope["facts"]["os"]["platform"])
        for path in (_sheet(root, host), _sheet(root, host, blank=True),
                     root / "register" / f"{host}-register-review.csv", root / "register" / f"{host}-missed-gaps.csv"):
            assert path.is_file(), path
        for methodology in METHODOLOGIES:
            output = _output(root, host, methodology)
            assert output.methodology_name == methodology and output.risk_register is not None
    assert platforms == {"ubuntu", "windows"}
    attestations = [(root / "inputs" / synthetic.attestation_name(h)).read_bytes() for h in HOSTS]
    assert len(set(attestations)) == len(HOSTS)


def test_synthetic_marker_is_ignored_by_every_check():
    """The "synthetic": true keys in the attestation and inventory record
    change no verdict and no detail."""
    session = dt.date.fromisoformat(SESSION)
    for index, host in enumerate(HOSTS):
        plan = synthetic.plan_host(host, index, synthetic.DEFAULT_SEED, session)
        results = []
        for marked in (True, False):
            attestation, inventory = copy.deepcopy(plan.attestation), copy.deepcopy(plan.inventory_record)
            if not marked:
                del attestation["synthetic"], inventory["synthetic"]
            assessment = run_assessment("x", context={"facts": copy.deepcopy(plan.facts), "attestation": attestation,
                                                      "inventory_record": inventory, "as_of": session})
            results.append([(c.check_id, c.status, c.detail) for p in assessment.properties for c in p.checks])
        assert results[0] == results[1], host


def test_every_hashed_file_has_its_byte_for_byte_archive_copy(pipeline):
    ledger = pipeline.root / "ledger.csv"
    rows = read_ledger(ledger)
    for row in rows:
        archived = study_ledger.archive_path(ledger, row)
        assert archived.parent == pipeline.root / "ledger-archive"
        assert archived.name == row.sha256 + Path(row.path).suffix
        assert sha256_file(archived) == row.sha256, row
    names = {p.name for p in (pipeline.root / "ledger-archive").iterdir()}
    assert names == {study_ledger.archive_path(ledger, row).name for row in rows}


def test_dummy_worksheets_pass_the_pre_hash_lint(pipeline, tmp_path):
    """study.yaml declares the rule the dummy levels are made with, so the
    lint that `ledger record --kind worksheet` runs finds nothing, and no
    worksheet row was recorded with --force. The lint does check every
    level against that rule: one level changed on a copy is reported."""
    config = load_study_config(pipeline.root / "study.yaml")
    assert config.manual_level_rule == "approved" and config.overall_rule == "pooled-checks"
    for host in HOSTS:
        assert study_agreement.lint_worksheet(_sheet(pipeline.root, host), config, host) == [], host
    notes = [r.note for r in read_ledger(pipeline.root / "ledger.csv") if r.kind == "worksheet"]
    assert len(notes) == len(HOSTS)
    assert not [n for n in notes if study_agreement.LINT_NOTE_PREFIX in n]

    for host in HOSTS:
        copy_path = tmp_path / worksheet_name(host)
        shutil.copyfile(str(_sheet(pipeline.root, host)), str(copy_path))
        typed = {r["property"]: r["value"] for r in _worksheet_rows(copy_path)
                 if r["row_type"] == "level" and r["item"] == "cisa-ztmm"}
        wrong = "4" if typed[OVERALL] != "4" else "1"
        _set_cell(copy_path, "level", "cisa-ztmm", "value", wrong, prop=OVERALL)
        findings = study_agreement.lint_worksheet(copy_path, config, host)
        assert [severity for severity, _ in findings] == ["WARNING"], (host, findings)
        assert findings[0][1].startswith(f"cisa-ztmm overall: level {wrong} entered"), findings


# ------------------------------------------------------------------ health, ledger, agreement
def test_health_is_ok_for_every_facts_file_and_tool_output(pipeline, monkeypatch):
    monkeypatch.chdir(pipeline.root)
    files = [f"outputs/{facts_name(h)}" for h in HOSTS]
    files += [f"outputs/{tool_output_name(h, m)}" for h in HOSTS for m in METHODOLOGIES]
    code, out, _ = _run(main, ["health", "--expect-as-of", SESSION, "--list-checks", "inputs/list-checks.json",
                               *files])
    lines = out.splitlines()
    assert code == 0, out
    assert len(lines) > len(files) and all(line.startswith("ok ") for line in lines)
    # A Windows 11 host's facts lack one extended item: reported, and still ok.
    assert (f"ok      outputs/H2-facts.json: extended facts: 10 of 11 items collected "
            f"(not collected: {synthetic.NOT_COLLECTED_ITEM})") in lines
    for host in HOSTS:
        group = [f"outputs/{facts_name(host)}"] + [f"outputs/{tool_output_name(host, m)}" for m in METHODOLOGIES]
        code, out, _ = _run(main, ["health", "--expect-as-of", SESSION, "--list-checks", "inputs/list-checks.json",
                                   "--pair", "--ledger", "ledger.csv", "--host", host, *group])
        lines = out.splitlines()
        assert code == 0, out
        assert all(line.startswith("ok ") for line in lines), out
        assert "ok      pair: per-check statuses identical: yes" in lines
        for methodology in METHODOLOGIES:
            label = f"outputs/{tool_output_name(host, methodology)}"
            for test in (f"inputs match the ledger for {host}: yes", "inputs given: yes",
                         "facts file matches the ledger: yes", "worksheet hashed before this run: yes"):
                assert f"ok      {label}: {test}" in lines, (host, test)


def test_health_inputs_finds_every_date_readable(pipeline, monkeypatch):
    """Deliberately changed: a file named by its role also gets the entry
    line, and the kit's H3 attestation leaves firmware_currency out, which
    is a PROBLEM unless named with --allow-missing."""
    monkeypatch.chdir(pipeline.root)
    files = [f"inputs/{name(h)}" for h in HOSTS for name in (synthetic.attestation_name, synthetic.inventory_name)]
    code, out, _ = _run(main, ["health", "--inputs", "--as-of", SESSION, "--allow-missing", "firmware_currency",
                               *files])
    assert code == 0, out
    expected = []
    for f in files:
        role = "an attestation" if f.endswith("-attestation.json") else "an inventory record"
        entries = f"ok      {f}: every entry the checks read from {role} is given"
        if f == "inputs/H3-attestation.json":
            entries += ", apart from firmware_currency (--allow-missing)"
        expected += [f"ok      {f}: every date the checks read is readable", entries]
    assert out.splitlines() == expected
    code, out, _ = _run(main, ["health", "--inputs", "--as-of", SESSION, *files])
    assert code == 1
    assert [line for line in out.splitlines() if line.startswith("PROBLEM")] == [
        "PROBLEM inputs/H3-attestation.json: every entry the checks read from an attestation is given: no, absent: "
        "firmware_currency (each leaves its check not evaluated, as missing data; add each one, or name one left out "
        "on purpose with --allow-missing NAME)"]


def test_h3s_missing_firmware_entry_runs_through_the_register_and_h2(pipeline):
    """The kit's missing-owner host has no firmware_currency attestation: CUR-03
    is a missing-data entry in both outputs, in the same place, and gets a
    judged review row that counts in H2."""
    plan = synthetic.plan_host("H3", 2, synthetic.DEFAULT_SEED, dt.date.fromisoformat(SESSION))
    assert plan.profile == "missing-owner" and synthetic.OMITTED_ATTESTATION_ENTRY not in plan.attestation
    registers = {m: _output(pipeline.root, "H3", m).risk_register for m in METHODOLOGIES}
    for methodology, register in registers.items():
        entry = next(e for e in register if e["check_id"] == "CUR-03")
        assert (entry["entry_type"], entry["status"]) == ("missing-data", "NOT_APPLICABLE"), methodology
        assert entry["missing_data"]["field"] == "firmware_currency"
        assert entry["next_level"]["methodology"] == methodology
    assert [e["check_id"] for e in registers["cmmi"]] == [e["check_id"] for e in registers["cisa-ztmm"]]
    review = read_csv(pipeline.root / "register" / "H3-register-review.csv", REGISTER_REVIEW_COLUMNS)
    row = next(r for r in review if r["check_id"] == "CUR-03")
    assert (row["entry_type"], row["rating_basis"]) == ("missing-data", "if the control is absent")
    assert row["missing_data"].startswith('The attestation file has no "firmware_currency" entry')
    assert normalize_yes_no(row["accurate"]) and normalize_yes_no(row["actionable"])
    h2 = {r["host"]: r for r in _rows(_analysis(pipeline.root, "register_h2.csv"))}
    assert (h2["H3"]["missing_data_entries"], h2["TOTAL"]["missing_data_entries"]) == ("1", "1")
    assert int(h2["TOTAL"]["finding_judged"]) + int(h2["TOTAL"]["missing_data_judged"]) == int(h2["TOTAL"]["n"])
    for host in ("H1", "H2", "H4", "H5"):
        assert all(e["entry_type"] == "finding" for e in _output(pipeline.root, host).risk_register), host


def test_ledger_verifies_and_every_worksheet_was_hashed_before_its_tool_outputs(pipeline):
    ledger = pipeline.root / "ledger.csv"
    code, out, _ = _run(main, ["ledger", "verify", "--ledger", str(ledger)])
    assert code == 0, out
    assert out.splitlines() and all(line.startswith("OK ") for line in out.splitlines())
    rows = read_ledger(ledger)
    for host in HOSTS:
        mine = [r for r in rows if r.host_code == host]
        assert {r.kind for r in mine} == {"input", "worksheet", "facts", "tool-output", "register-review",
                                         "missed-gaps"}
        hashed = max(parse_utc_timestamp(r.recorded_at_utc) for r in mine if r.kind == "worksheet")
        for row in mine:
            if row.kind in ("facts", "tool-output", "register-review", "missed-gaps"):
                assert parse_utc_timestamp(row.recorded_at_utc) > hashed, row
        for methodology in METHODOLOGIES:
            prov = _output(pipeline.root, host, methodology).provenance
            assert parse_utc_timestamp(prov["run_at_utc"]) > hashed
            assert parse_utc_timestamp(prov["facts_collected_at_utc"]) > hashed
    # Changed on purpose (round 2): register-sheet, while building the kit, and the
    # fixture's agreement run each appended their seal-opening row (STUDY, protocol).
    assert {r.kind for r in rows if r.host_code == "STUDY"} == {"other", "list-checks", "protocol"}
    openings = [(index, r) for index, r in enumerate(rows) if study_ledger.is_seal_opening(r)]
    everyone = ", ".join(HOSTS)
    assert [r.note for _, r in openings] == [f"seal opened by register-sheet: hosts {everyone}; withdrawn: none",
                                             f"seal opened by agreement: hosts {everyone}; withdrawn: none"]
    assert all((r.kind, r.path) == ("protocol", "study.yaml") for _, r in openings)
    last_sheet = max(index for index, r in enumerate(rows) if r.kind == "worksheet")
    last_output = max(index for index, r in enumerate(rows) if r.kind in ("facts", "tool-output"))
    first_register = min(index for index, r in enumerate(rows) if r.kind in ("register-review", "missed-gaps"))
    assert last_sheet < last_output < openings[0][0] < first_register < openings[1][0]


def test_kit_inputs_are_named_by_role(pipeline):
    """The identical-inputs check tells an attestation from an inventory
    record by the recorded file name: every input row of the kit has the
    role its name says, and each host has one file of each role."""
    rows = read_ledger(pipeline.root / "ledger.csv")
    for host in HOSTS:
        named = {study_ledger.input_role(r.path): r.path for r in rows if r.kind == "input" and r.host_code == host}
        assert named == {study_ledger.ATTESTATION_ROLE: f"inputs/{synthetic.attestation_name(host)}",
                         study_ledger.INVENTORY_ROLE: f"inputs/{synthetic.inventory_name(host)}"}, host


def test_agreement_runs_clean_and_labels_every_output_synthetic(pipeline):
    """The synthetic kit passes the real seal (there is no synthetic
    exemption) and every integrity check, with WARNINGs at most."""
    root = pipeline.root
    assert pipeline.agreement_code == 0, pipeline.agreement_err
    assert "CRITICAL" not in pipeline.agreement_out
    assert sorted(p.name for p in (root / "analysis").iterdir()) == sorted("SYNTHETIC-" + n for n in ANALYSIS_FILES)
    assert _analysis(root, "summary.md").read_text(encoding="utf-8").startswith(SYNTHETIC_BANNER + "\n")
    summary = json.loads(_analysis(root, "summary.json").read_text(encoding="utf-8"))
    assert list(summary)[0] == "banner" and summary["banner"] == SYNTHETIC_BANNER
    assert summary["integrity"]["status"] in ("OK", "WARNING")
    assert _critical(summary) == []
    warned = {r["check"] for r in summary["integrity"]["checks"] if r["result"] == "WARNING"}
    assert warned <= {"build", "analysis_code"}, warned
    assert summary["config"]["level_rule"] == synthetic.SYNTHETIC_LEVEL_RULE_CONFIG
    assert summary["config"]["withdrawn"] == {} and summary["ledger"]["not_ok"] == []
    assert summary["h2"]["available"] is True
    assert summary["run"]["level_rules"] == [f"{synthetic.SYNTHETIC_LEVEL_RULE} ({', '.join(HOSTS)})"]
    disagreements = _rows(_analysis(root, "disagreements.csv"))
    assert disagreements, "the dummy verdicts should disagree with the tool somewhere"
    assert all(r["root_cause"] == r["action"] == r["assessor_error_note"] == "" for r in disagreements)


@pytest.mark.parametrize("methodology, scope", [("cmmi", OVERALL), ("cmmi", "inventoried")])
def test_h1_recount_from_host_levels_matches_agreement_h1(pipeline, methodology, scope):
    root = pipeline.root
    rows = [r for r in _rows(_analysis(root, "host_levels.csv"))
            if r["methodology"] == methodology and r["scope"] == scope]
    assert [r["host"] for r in rows] == HOSTS
    n = sum(1 for r in rows if r["within_one"] in ("yes", "no"))
    k = sum(1 for r in rows if r["within_one"] == "yes")
    reported = next(r for r in _rows(_analysis(root, "agreement_h1.csv"))
                    if r["methodology"] == methodology and r["scope"] == scope and r["measure"] == "within_one")
    assert (reported["k"], reported["n"]) == (str(k), str(n))
    low, high = _wilson(k, n)
    assert (reported["wilson_low"], reported["wilson_high"]) == (f"{low:.4f}", f"{high:.4f}")
    assert reported["meets_threshold"] == ("yes" if Fraction(k, n) >= Fraction(4, 5) else "no")


def test_a_changed_worksheet_keeps_the_seal_closed_until_restored_from_the_archive(pipeline, tmp_path):
    """Editing a hashed worksheet closes the seal again (agreement and
    register-sheet refuse, nothing is written). Copying back the archived
    copy the refusal names, as the guide says, makes verify OK again."""
    study = tmp_path / "edited-study"
    shutil.copytree(str(pipeline.root), str(study), ignore=shutil.ignore_patterns("analysis"))
    sheet = _sheet(study, "H1")
    original = sheet.read_bytes()
    before = {r["item"]: r["value"] for r in _worksheet_rows(sheet) if r["row_type"] == "check"}
    _set_cell(sheet, "check", "MON-01", "value", "PASS" if before["MON-01"] != "PASS" else "FAIL")
    ledger = study / "ledger.csv"

    code, out, _ = _run(main, ["ledger", "verify", "--ledger", str(ledger)])
    assert code == 1 and "CHANGED worksheets/H1-worksheet.csv  (worksheet)" in out.splitlines()
    row = next(r for r in read_ledger(ledger) if r.kind == "worksheet" and r.host_code == "H1")
    archived = study / "ledger-archive" / f"{row.sha256}.csv"
    assert archived.read_bytes() == original
    # Changed on purpose (round 2): the refusal now names the archive copy first.
    hint = f"restore the original bytes from ledger-archive/{row.sha256}.csv (or your commit or e-mailed copy)"
    rows_before = len(read_ledger(ledger))

    code, out, err = _run(main, ["agreement", "--study-dir", str(study)])
    assert (code, out) == (2, "")
    assert "tool outputs stay sealed" in err and hint in err
    assert "H1 (worksheet changed after it was hashed: worksheets/H1-worksheet.csv" in err
    assert not (study / "analysis").exists()
    code, out, err = _run(main, ["register-sheet", "--study-dir", str(study), "--overwrite"])
    assert (code, out) == (2, "")
    assert "stay sealed" in err and hint in err and "cannot be re-hashed" in err
    assert len(read_ledger(ledger)) == rows_before    # a refused run records no seal opening

    shutil.copyfile(str(archived), str(sheet))  # the guide's "If a hashed file changed"
    code, out, _ = _run(main, ["ledger", "verify", "--ledger", str(ledger)])
    assert code == 0 and all(line.startswith("OK ") for line in out.splitlines()), out
    code, out, err = _run(main, ["agreement", "--study-dir", str(study)])
    assert code == 0, out + err


@pytest.mark.parametrize("host, methodology", [("H1", "cmmi"), ("H2", "cisa-ztmm")])
def test_facts_replay_reproduces_the_output_apart_from_run_at_utc(pipeline, tmp_path, monkeypatch,
                                                                   host, methodology):
    monkeypatch.chdir(pipeline.root)
    again = tmp_path / "again.json"
    code, _, err = _run(miccmac_main, synthetic.replay_argv(host, methodology, SESSION, output=str(again)))
    assert code == 0, err
    first = _json(pipeline.root / "outputs" / tool_output_name(host, methodology))
    second = _json(again)
    for data in (first, second):
        parse_utc_timestamp(data["assessment"]["provenance"].pop("run_at_utc"))
    assert first == second
    assert first["assessment"]["provenance"]["facts_file"]["role"] == "replayed"


def test_a_second_replay_to_the_same_file_is_refused(pipeline, tmp_path, monkeypatch):
    """Study runs never overwrite a file: the guide's scratch replay needs a
    new name (or --overwrite, for scratch files only)."""
    monkeypatch.chdir(pipeline.root)
    target = tmp_path / "replay.json"
    argv = synthetic.replay_argv("H1", "cmmi", SESSION, output=str(target))
    assert _run(miccmac_main, argv)[0] == 0
    first = target.read_bytes()
    code, out, err = _run(miccmac_main, argv)
    assert (code, out) == (2, "")
    assert f"refusing to replace {target}: study runs never overwrite a file" in err
    assert target.read_bytes() == first
    assert _run(miccmac_main, argv + ["--overwrite"])[0] == 0


def test_as_of_moves_only_the_date_dependent_checks(pipeline, tmp_path, monkeypatch):
    """The README demonstration: H1 (a "current" host, whatever the seed)
    under the session date and a date 200 days later. Only the four
    date-dependent checks change, each from PASS to FAIL."""
    monkeypatch.chdir(pipeline.root)
    later = (dt.date.fromisoformat(SESSION) + dt.timedelta(days=200)).isoformat()
    results = []
    for day in (SESSION, later):
        target = tmp_path / f"as-of-{day}.json"
        argv = synthetic.replay_argv("H1", "cmmi", day, output=str(target))
        assert _run(miccmac_main, argv)[0] == 0
        assessment = _json(target)["assessment"]
        results.append({c["check_id"]: (c["status"], c["detail"])
                        for p in assessment["properties"] for c in p["checks"]})
    changed = sorted(c for c in results[0] if results[0][c] != results[1][c])
    assert changed == sorted(DATE_CHECKS)
    for check_id in DATE_CHECKS:
        assert (results[0][check_id][0], results[1][check_id][0]) == ("PASS", "FAIL"), check_id
        assert results[0][check_id][1].endswith(f" (as of {SESSION})")
        assert results[1][check_id][1].endswith(f" (as of {later})")


# ------------------------------------------------------------------ worksheets
def test_blank_worksheets_contain_no_tool_derived_text(pipeline):
    """No tool status, threshold, query, cutoff, CIS IG, FAIR value, detail
    or remediation text anywhere in a blank sheet. The one exception is the
    sheet's own instruction row, which names the protocol's verdict values
    (PASS, PARTIAL, FAIL, N/A, UNASSESSED): it is checked to be exactly
    that instruction, and every other cell is scanned."""
    root = pipeline.root
    metadata = load_check_metadata()
    forbidden = set()
    forbidden.update(m.remediation for m in metadata.values())
    forbidden.update(["IG1", "IG2", "IG3", "LOW", "MEDIUM", "HIGH", "UNRATED", "MODERATE", "CRITICAL"])
    # The SP 800-30 fields of the register: threat events, source types, review states.
    forbidden.update(m.threat_event for m in load_register_metadata().values())
    forbidden.update(["adversarial", "accidental", "structural", "environmental", "drafted", "missing-data",
                      "if the control is absent", "threat_source_type", "threat_event", "next_level"])
    # Tool statuses only: UNASSESSED is an assessor's option, named in the sheet's own instructions.
    forbidden.update(["PASS", "PARTIAL", "FAIL", "NOT_APPLICABLE", "NOT_IMPLEMENTED", "ERROR"])
    forbidden.update(["Check not yet implemented", "Excluded:", "SELECT", "FROM ", "day(s)", "7-day", "30-day",
                      "90-day", "policy:", "20/40/70/90", "20.0", "40.0", "70.0", "90.0", "(as of",
                      "Zero Trust Ready", "Defensible", "Developing", "Not Ready", "cis_ig", "fair_frequency",
                      "fair_magnitude", "risk_rating", "recommended_fix", "5 Optimizing"])
    for host in HOSTS:
        forbidden.add(f"synthetic-{host}")
        for methodology in METHODOLOGIES:
            output = _output(root, host, methodology)
            forbidden.update(s for c in output.checks() for s in (c["detail"], c["evidence"]) if s)
            forbidden.update(_register_texts(output.risk_register))

    instruction = META_HELP["worksheet_format"]
    assert all(word in instruction for word in ("PASS", "PARTIAL", "FAIL", "N/A", "UNASSESSED", "NONE"))
    for host in HOSTS:
        path = _sheet(root, host, blank=True)
        rows = _worksheet_rows(path)
        meta_help = [r["description"] for r in rows if r["row_type"] == "meta" and r["item"] == "worksheet_format"]
        assert meta_help == [instruction]
        cells = [value for r in rows for column, value in r.items()
                 if not (r["row_type"] == "meta" and r["item"] == "worksheet_format" and column == "description")]
        text = "\n".join(cells)
        assert sorted(s for s in forbidden if s in text) == [], host
        assert "osquery" not in text.lower()
        assert "score" not in text.lower() and "tier" not in text.lower()
        meta = {r["item"]: r["value"] for r in rows if r["row_type"] == "meta"}
        assert (meta["host_code"], meta["session_date"], meta["synthetic"]) == (host, SESSION, "yes")
        assert meta["assessor"] == meta["level_rule"] == ""
        assert all(r["value"] == "" for r in rows if r["row_type"] in ("check", "level"))
        # --study-config: each level row offers only the study's levels (manual_max_level 4).
        levels = [r["description"] for r in rows if r["row_type"] == "level"]
        assert len(levels) == len(METHODOLOGIES) * len(LEVEL_SCOPES)
        assert all("whole number 1-4" in text for text in levels)


def test_filled_worksheets_differ_from_the_blank_ones_only_in_judgment_cells(pipeline):
    for host in HOSTS:
        blank = _worksheet_rows(_sheet(pipeline.root, host, blank=True))
        filled = _worksheet_rows(_sheet(pipeline.root, host))
        assert len(blank) == len(filled)
        for before, after in zip(blank, filled):
            fixed = [c for c in WORKSHEET_COLUMNS if c not in JUDGMENT_COLUMNS]
            assert [before[c] for c in fixed] == [after[c] for c in fixed]
            if before["row_type"] == "meta":
                assert all(after[c] == "" for c in JUDGMENT_COLUMNS[1:])
                if before["item"] not in ("assessor", "level_rule"):
                    assert after["value"] == before["value"]
        meta = {r["item"]: r["value"] for r in filled if r["row_type"] == "meta"}
        assert (meta["assessor"], meta["level_rule"]) == ("synthetic", synthetic.SYNTHETIC_LEVEL_RULE)


def test_dummy_verdicts_and_levels_follow_the_generation_rules(pipeline):
    unassessed, changed, compared = [], 0, 0
    for host in HOSTS:
        rows = _worksheet_rows(_sheet(pipeline.root, host))
        checks = [r for r in rows if r["row_type"] == "check"]
        statuses = _output(pipeline.root, host).statuses()
        verdicts = {}
        for row in checks:
            verdict = normalize_verdict(row["value"])
            verdicts[row["item"]] = (row["property"], verdict)
            if verdict == "UNASSESSED":
                assert row["unassessed_reason"].startswith("synthetic:")
                unassessed.append((host, row["item"]))
            else:
                assert row["unassessed_reason"] == ""
                compared += 1
                changed += verdict != statuses[row["item"]]
        expected = {key: _approved_level(v for p, v in verdicts.values() if p == key)
                    for key in LEVEL_SCOPES if key not in (OVERALL, OVERALL_EXCL)}
        expected[OVERALL] = _approved_level(v for _, v in verdicts.values())
        expected[OVERALL_EXCL] = _approved_level(v for p, v in verdicts.values() if p not in INPUT_PROPERTIES)
        for methodology in METHODOLOGIES:
            levels = {r["property"]: r["value"] for r in rows if r["row_type"] == "level" and r["item"] == methodology}
            assert levels == expected, (host, methodology)
    assert len(unassessed) == 1
    assert 0.05 <= changed / compared <= 0.30


# ------------------------------------------------------------------ register sheets
def test_register_sheets_hold_valid_dummy_judgments(pipeline):
    total_gaps = 0
    for host in HOSTS:
        register = _output(pipeline.root, host).risk_register
        review = read_csv(pipeline.root / "register" / f"{host}-register-review.csv", REGISTER_REVIEW_COLUMNS)
        assert [r["check_id"] for r in review] == [e["check_id"] for e in register]
        for row in review:
            assert normalize_yes_no(row["accurate"]) and normalize_yes_no(row["actionable"])
            assert normalize_yes_no(row["prioritized"], allow_unsure=True)
            assert row["reason"].startswith("synthetic:")
        gaps = read_csv(pipeline.root / "register" / f"{host}-missed-gaps.csv", MISSED_GAPS_COLUMNS)
        assert [r["gap_no"] for r in gaps] == ["1", "2", "3", "4", "5"]
        filled = [r for r in gaps if r["description"]]
        assert len(filled) <= 2 and all(r["description"].startswith("synthetic:") for r in filled)
        # A missed gap has no finding in the register (deliberately changed: a check with only a
        # missing-data entry reports no gap, so it can be a missed gap).
        findings = {e["check_id"] for e in register if e["entry_type"] == "finding"}
        assert not ({r["check_id"] for r in filled if r["check_id"]} & findings)
        total_gaps += len(filled)
    assert total_gaps > 0


# ------------------------------------------------------------------ determinism and refusals
def _comparable(root: Path) -> dict:
    """Everything in a synthetic folder except timestamps and the run's
    provenance. ledger-archive/ is left out: its copies are named by their
    hash, and the hashed worksheets and outputs hold timestamps (each copy
    is checked against its ledger row in another test)."""
    data = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        name = path.relative_to(root).as_posix()
        if name.startswith(study_ledger.ARCHIVE_DIR + "/"):
            continue
        if name == "ledger.csv":
            data[name] = [(r.host_code, r.kind, r.path, r.sha256 if not r.path.startswith(("worksheets/", "outputs/"))
                           else "") for r in read_ledger(path)]
        elif name.endswith("-facts.json"):
            data[name] = _json(path)["facts"]
        elif name.startswith("outputs/"):
            content = _json(path)
            content["assessment"].pop("provenance")
            data[name] = content
        elif name.endswith("-worksheet.csv"):
            data[name] = [r for r in _worksheet_rows(path) if r["item"] != "generated_at_utc"]
        else:
            data[name] = path.read_bytes()
    return data


def test_same_seed_gives_the_same_data_and_another_seed_does_not(tmp_path):
    folders = []
    for name, seed in (("a", "7"), ("b", "7"), ("c", "8")):
        code, _, err = _run(main, ["synthetic", "--out", str(tmp_path / name), "--hosts", "3", "--seed", seed])
        assert code == 0, err
        folders.append(_comparable(tmp_path / name))
    assert folders[0] == folders[1]
    assert folders[0]["inputs/H1-attestation.json"] != folders[2]["inputs/H1-attestation.json"]
    assert set(folders[0]) == set(folders[2])
    for name in ("a", "b", "c"):
        ledger = tmp_path / name / "ledger.csv"
        assert all(sha256_file(study_ledger.archive_path(ledger, row)) == row.sha256 for row in read_ledger(ledger))


def test_a_past_session_date_still_keeps_the_protocol_order(tmp_path):
    """With a session date already past, the facts are dated at generation
    time, so they still follow the worksheet hashes and agreement sees no
    CRITICAL order problem."""
    study = tmp_path / "past"
    code, _, err = _run(main, ["synthetic", "--out", str(study), "--hosts", "2", "--session-date", "2026-01-15"])
    assert code == 0, err
    for host in ("H1", "H2"):
        envelope = _json(study / "outputs" / facts_name(host))
        assert envelope["as_of"] == "2026-01-15"
        assert parse_utc_timestamp(envelope["collected_at_utc"]).date() > dt.date(2026, 1, 15)
    code, out, err = _run(main, ["agreement", "--study-dir", str(study)])
    assert code == 0, out + err
    summary = json.loads(_analysis(study, "summary.json").read_text(encoding="utf-8"))
    assert _critical(summary) == []


def test_a_failed_step_says_the_folder_is_incomplete(tmp_path, monkeypatch):
    def refuse(path, envelope):
        raise facts_file.FactsFileError("simulated: the facts file cannot be written")

    monkeypatch.setattr(facts_file, "save_envelope", refuse)
    code, out, err = _run(main, ["synthetic", "--out", str(tmp_path / "broken"), "--hosts", "1"])
    assert (code, out) == (2, "")
    assert "simulated" in err and "is incomplete; delete it before running again" in err


def test_refuses_a_folder_that_is_not_empty(tmp_path):
    folder = tmp_path / "busy"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep", encoding="utf-8")
    code, out, err = _run(main, ["synthetic", "--out", str(folder)])
    assert (code, out) == (2, "")
    assert "not empty" in err
    assert [p.name for p in folder.iterdir()] == ["keep.txt"]


def test_an_empty_folder_is_accepted(tmp_path):
    folder = tmp_path / "empty"
    folder.mkdir()
    code, out, err = _run(main, ["synthetic", "--out", str(folder), "--hosts", "1"])
    assert code == 0, err
    assert out.splitlines()[0] == str(folder.resolve())
    assert load_study_config(folder / "study.yaml").hosts == ["H1"]


@pytest.mark.parametrize("args, message", [
    (["--hosts", "0"], "--hosts"),
    (["--hosts", "21"], "--hosts"),
    (["--session-date", "2026-13-01"], "--session-date"),
    (["--session-date", "20261123"], "--session-date"),
])
def test_bad_options_are_refused_before_anything_is_written(tmp_path, args, message):
    folder = tmp_path / "never"
    code, out, err = _run(main, ["synthetic", "--out", str(folder), *args])
    assert (code, out) == (2, "")
    assert message in err
    assert not folder.exists()


# ------------------------------------------------------------------ small rules
def test_collection_time_always_follows_the_worksheet_hashes():
    session = dt.date(2026, 11, 23)
    utc = dt.timezone.utc
    before = dt.datetime(2026, 11, 19, 10, 0, tzinfo=utc)
    assert synthetic.collection_time(session, 0, before) == dt.datetime(2026, 11, 23, 12, 0, tzinfo=utc)
    assert synthetic.collection_time(session, 2, before) == dt.datetime(2026, 11, 23, 13, 0, tzinfo=utc)
    same_day = dt.datetime(2026, 11, 23, 12, 45, tzinfo=utc)
    assert synthetic.collection_time(session, 0, same_day) == same_day
    assert synthetic.collection_time(session, 2, same_day) == dt.datetime(2026, 11, 23, 13, 0, tzinfo=utc)
    later = dt.datetime(2027, 1, 5, 8, 0, tzinfo=utc)
    assert synthetic.collection_time(session, 4, later) == later


@pytest.mark.parametrize("verdicts, level", [
    ([], "UNASSESSED"),
    (["NOT_APPLICABLE", "UNASSESSED"], "UNASSESSED"),
    (["FAIL", "FAIL", "NOT_APPLICABLE"], "1"),
    (["PARTIAL", "FAIL", "FAIL"], "2"),
    (["PASS", "FAIL"], "3"),
    (["PASS", "PARTIAL"], "3"),
    (["PASS", "PASS", "NOT_APPLICABLE"], "4"),
])
def test_approved_rule_level_for_dummy_data(verdicts, level):
    assert synthetic.approved_rule_level(verdicts) == level
    assert _approved_level(verdicts) == level


# ------------------------------------------------------------------ a non-synthetic study, run as the guide says
# The study.yaml decisions the guide asks for, as edits of formats.config_template.
DECISION_EDITS = (
    ("secondary_methodologies: []", "secondary_methodologies: [cisa-ztmm]"),
    ("manual_max_level: {cmmi: 5, cisa-ztmm: 4}", "manual_max_level: {cmmi: 4, cisa-ztmm: 4}"),
    ("  manual: null", "  manual: approved"),
    ("  overall: null", "  overall: pooled-checks"),
)
WITHDRAW_REASON = "Windows 11 fallback (decision 9): not assessed in this study"


class GuideStudy:
    """A study folder that is not synthetic, run with the guide's commands
    from inside the folder, with relative paths as they are typed there.
    The kit (a synthetic study) supplies the facts, input files and
    worksheet entries. The live collection of step 5 is the one step
    replaced: the kit's facts are saved as the host's facts file, in the
    format --save-facts writes, naming the connector a live run would use,
    and both reports are scored from it with --facts."""

    def __init__(self, root: Path, kit: Path):
        self.root, self.kit = root, kit

    # -- commands
    def study(self, argv):
        with _cwd(self.root):
            return _run(main, argv)

    def tool(self, argv):
        with _cwd(self.root):
            return _run(miccmac_main, argv)

    @staticmethod
    def ok(result):
        code, out, err = result
        assert code == 0, out + err
        return out

    def record(self, host: str, kind: str, *paths: str):
        return self.ok(self.study(["ledger", "record", "--ledger", "ledger.csv", "--host", host, "--kind", kind,
                                   *paths]))

    def rows(self):
        return read_ledger(self.root / "ledger.csv")

    def snapshot(self):
        """The ledger's bytes and the archive's file names, to show that a
        refused command recorded and archived nothing."""
        return ((self.root / "ledger.csv").read_bytes(),
                sorted(p.name for p in (self.root / study_ledger.ARCHIVE_DIR).iterdir()))

    # -- Setup (once)
    def setup(self, hosts: Sequence[str], inputs_for: Optional[Sequence[str]] = None) -> None:
        """Setup, with the input files of the hosts in `inputs_for` (default:
        every host) written, checked and recorded."""
        for folder in ("inputs", "outputs", "worksheets", "register"):
            (self.root / folder).mkdir(parents=True)
        listed = self.ok(self.tool(["list-checks", "--format", "json"]))
        (self.root / "inputs" / "list-checks.json").write_text(listed, encoding="utf-8")
        text = config_template(list(hosts))
        for old, new in DECISION_EDITS:
            assert old in text, old
            text = text.replace(old, new)
        (self.root / "study.yaml").write_text(text, encoding="utf-8")
        with_inputs = list(hosts if inputs_for is None else inputs_for)
        inputs = [path for host in with_inputs for path in self.write_inputs(host)]
        # The kit's H3 attestation leaves firmware_currency out on purpose (a missing-data entry).
        self.ok(self.study(["health", "--inputs", "--as-of", SESSION, "--allow-missing", "firmware_currency",
                            *inputs]))
        self.record("STUDY", "list-checks", "inputs/list-checks.json")
        self.ok(self.study(["ledger", "record", "--ledger", "ledger.csv", "--host", "STUDY", "--kind", "other",
                            "--note", "study configuration", "study.yaml"]))
        for host in with_inputs:
            self.record(host, "input", f"inputs/{synthetic.attestation_name(host)}",
                        f"inputs/{synthetic.inventory_name(host)}")

    def write_inputs(self, host: str, source: Optional[str] = None) -> List[str]:
        """The host's input files, named by role, with the content of the
        kit's files for host `source` (default: the same host) minus the
        kit's synthetic marker; returns their paths as typed."""
        written = []
        for name, kit_name in ((synthetic.attestation_name(host), synthetic.attestation_name(source or host)),
                               (synthetic.inventory_name(host), synthetic.inventory_name(source or host))):
            data = _json(self.kit / "inputs" / kit_name)
            data.pop("synthetic")
            write_json(self.root / "inputs" / name, data)
            written.append(f"inputs/{name}")
        return written

    # -- per host
    def worksheet(self, host: str, source: Optional[str] = None) -> Path:
        """Step 1, then step 2 with the kit's dummy entries for host `source`
        (default: the same host): verdicts, levels and procedure cells; the
        sheet's own meta rows say synthetic no."""
        self.ok(self.study(["worksheet", "--list-checks", "inputs/list-checks.json", "--hosts", host,
                            "--out", "worksheets", "--session-date", SESSION, "--study-config", "study.yaml"]))
        path = self.root / "worksheets" / worksheet_name(host)
        entries = {(r["row_type"], r["item"], r["property"]): r
                   for r in _worksheet_rows(_sheet(self.kit, source or host))}
        rows = _worksheet_rows(path)
        for row in rows:
            if row["row_type"] == "meta":
                if row["item"] == "assessor":
                    row["value"] = "assessor"
                elif row["item"] == "level_rule":
                    row["value"] = "approved, overall pooled-checks"
                continue
            source = entries[(row["row_type"], row["item"], row["property"])]
            for column in JUDGMENT_COLUMNS:
                row[column] = source[column]
        write_csv(path, WORKSHEET_COLUMNS, rows, overwrite=True)
        return path

    def hash_worksheet(self, host: str) -> None:
        """Step 3 (the lint runs first and must find nothing)."""
        out = self.record(host, "worksheet", f"worksheets/{worksheet_name(host)}")
        assert out.splitlines()[1].startswith("archive copy: ledger-archive/")

    def tool_run(self, host: str, index: int, connector: Optional[str] = None, source: Optional[str] = None,
                 attestation: Optional[str] = None, inventory_record: Optional[str] = None,
                 healthy: bool = True):
        """Steps 5-8 after the revert. The facts file is the kit's facts for
        host `source` (default: the same host) under a live connector's name
        (or `connector`), dated now, after the worksheet hash, as a live
        collection would be. `attestation` and `inventory_record` replace
        the input paths the tool is given. Returns step 8's (exit code,
        output); with `healthy` every line must be ok."""
        synthetic._wait_past(synthetic._latest_ledger_time(self.root / "ledger.csv"))
        facts = _json(self.kit / "outputs" / facts_name(source or host))["facts"]
        live = "ssh-osquery-windows" if facts["os"]["platform"] == "windows" else "ssh-osquery"
        envelope = facts_file.build_envelope(
            facts, tool_version=miccmac.__version__, tool_commit=provenance.tool_commit(),
            connector=connector or live, target=f"192.0.2.{10 + index}",
            collected_at_utc=clock.format_utc(clock.now_utc()), as_of=dt.date.fromisoformat(SESSION))
        facts_file.save_envelope(str(self.root / "outputs" / facts_name(host)), envelope)
        for methodology in METHODOLOGIES:
            self.ok(self.tool(self.replay(host, methodology, attestation, inventory_record)))
        self.record(host, "facts", f"outputs/{facts_name(host)}")
        self.record(host, "tool-output", *(f"outputs/{tool_output_name(host, m)}" for m in METHODOLOGIES))
        code, out, err = self.study(["health", "--expect-as-of", SESSION, "--list-checks", "inputs/list-checks.json",
                                     "--pair", "--ledger", "ledger.csv", "--host", host,
                                     f"outputs/{facts_name(host)}",
                                     *(f"outputs/{tool_output_name(host, m)}" for m in METHODOLOGIES)])
        if healthy:
            assert code == 0 and all(line.startswith("ok ") for line in out.splitlines()), out + err
        return code, out

    @staticmethod
    def replay(host: str, methodology: str, attestation: Optional[str] = None,
               inventory_record: Optional[str] = None) -> List[str]:
        """Step 6's command (step 5's for cmmi), scoring the saved facts."""
        return ["assess", "--facts", f"outputs/{facts_name(host)}",
                "--attestation", attestation or f"inputs/{synthetic.attestation_name(host)}",
                "--inventory-record", inventory_record or f"inputs/{synthetic.inventory_name(host)}",
                "--methodology", methodology, "--risk-register", "--format", "json",
                "-o", f"outputs/{tool_output_name(host, methodology)}", "--as-of", SESSION]

    def host(self, host: str, index: int, connector: Optional[str] = None) -> None:
        self.worksheet(host)
        self.hash_worksheet(host)
        self.tool_run(host, index, connector)

    # -- after the last host
    def judge_register(self, hosts: Sequence[str]) -> None:
        """Every entry judged (UNSURE for some priorities), then each sheet
        recorded once, as final."""
        for host in hosts:
            path = self.root / "register" / f"{host}-register-review.csv"
            rows = read_csv(path, REGISTER_REVIEW_COLUMNS)
            assert rows, host
            for number, row in enumerate(rows):
                row.update(accurate="Y", actionable="N" if number % 4 == 3 else "Y",
                           prioritized="UNSURE" if number % 3 == 2 else "Y", reason="rehearsal judgment")
            write_csv(path, REGISTER_REVIEW_COLUMNS, rows, overwrite=True)
            self.record(host, "register-review", f"register/{host}-register-review.csv")
            self.record(host, "missed-gaps", f"register/{host}-missed-gaps.csv")

    def after_the_last_host(self, hosts: Sequence[str], expect: int = 0) -> dict:
        """register-sheet, every entry judged and recorded, then agreement
        into analysis/ with exit `expect`; returns summary.json."""
        self.ok(self.study(["register-sheet", "--study-dir", "."]))
        self.judge_register(hosts)
        code, out, err = self.study(["agreement", "--study-dir", "."])
        assert code == expect, out + err
        return _json(self.root / "analysis" / "summary.json")

    def agreement(self, out_dir: str, *extra: str, expect: int = 3) -> dict:
        """agreement into `out_dir` with exit `expect`; returns summary.json."""
        code, out, err = self.study(["agreement", "--study-dir", ".", "--out", out_dir, *extra])
        assert code == expect, out + err
        return _json(self.root / out_dir / "summary.json")


def _problems(health_out: str) -> List[str]:
    return [line for line in health_out.splitlines() if not line.startswith("ok ")]


def _critical_details(summary: dict) -> List[tuple]:
    return [(r["check"], r["host"], r["detail"]) for r in summary["integrity"]["checks"] if r["result"] == "CRITICAL"]


@pytest.fixture(scope="module")
def mid_study(pipeline, tmp_path_factory):
    """A study folder that is not synthetic, mid-study: H1-H3 done (worksheet
    hashed, then the tool run and its hashes), H4's worksheet filled but not
    hashed yet, H5 not started."""
    root = tmp_path_factory.mktemp("guide") / "study"
    root.mkdir()
    with pytest.MonkeyPatch.context() as mp:
        _pin_build(mp)
        guide = GuideStudy(root, pipeline.root)
        guide.setup(HOSTS)
        for index, host in enumerate(HOSTS[:3]):
            guide.host(host, index)
        guide.worksheet("H4")
    return root


@pytest.fixture(scope="module")
def complete_study(mid_study, pipeline, tmp_path_factory):
    """mid_study finished in the protocol's order (H4 and H5 done), then
    After the last host: register-sheet, every entry judged and recorded,
    agreement exit 0. The seal has opened: the ledger holds the
    seal-opening rows of register-sheet and agreement."""
    root = tmp_path_factory.mktemp("complete") / "study"
    shutil.copytree(str(mid_study), str(root))
    with pytest.MonkeyPatch.context() as mp:
        _pin_build(mp)
        guide = GuideStudy(root, pipeline.root)
        guide.hash_worksheet("H4")
        guide.tool_run("H4", 3)
        guide.host("H5", 4)
        summary = guide.after_the_last_host(HOSTS)
    assert _critical(summary) == []
    assert [r.note.split(":")[0] for r in read_ledger(root / "ledger.csv") if study_ledger.is_seal_opening(r)] == [
        "seal opened by register-sheet", "seal opened by agreement"]
    return root


def _copy_study(source: Path, tmp_path: Path) -> Path:
    target = tmp_path / "study"
    shutil.copytree(str(source), str(target))
    return target


def test_mid_study_the_seal_stays_closed_also_with_a_configuration_listing_fewer_hosts(mid_study, pipeline,
                                                                                     tmp_path):
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    assert load_study_config(root / "study.yaml").synthetic is False
    text = (root / "study.yaml").read_text(encoding="utf-8")
    assert "hosts: [H1, H2, H3, H4, H5]" in text
    (root / "study-h123.yaml").write_text(text.replace("hosts: [H1, H2, H3, H4, H5]", "hosts: [H1, H2, H3]"),
                                          encoding="utf-8")
    ledger_before = (root / "ledger.csv").read_bytes()
    results = set(_tool_texts(root, HOSTS[:3]))

    for extra in ([], ["--config", "study-h123.yaml"]):
        code, out, err = guide.study(["register-sheet", "--study-dir", "."] + extra)
        assert (code, out) == (2, ""), extra
        assert "register sheets stay sealed until every worksheet is hashed and unchanged" in err
        assert "H4 (worksheet not hashed" in err and "H5 (no worksheet yet" in err
        assert not [s for s in results if s in err], extra
        code, out, err = guide.study(["agreement", "--study-dir", ".", "--out", "analysis-early"] + extra)
        assert (code, out) == (2, ""), extra
        assert "tool outputs stay sealed until every worksheet is hashed and unchanged" in err
        assert "H4 (worksheet not hashed" in err and "H5 (no worksheet yet" in err
        assert "a configuration that lists fewer hosts does not open the seal" in err
        assert not [s for s in results if s in err], extra
    assert list((root / "register").iterdir()) == []
    assert not (root / "analysis-early").exists() and not (root / "analysis").exists()
    assert (root / "ledger.csv").read_bytes() == ledger_before
    code, out, _ = guide.study(["ledger", "status", "--ledger", "ledger.csv", "--hosts", ",".join(HOSTS)])
    assert code == 1
    flagged = [line.split()[0] for line in out.splitlines() if "NO WORKSHEET ROW" in line]
    assert flagged == ["H4", "H5"]


def test_the_lint_refuses_a_level_that_does_not_follow_the_declared_rule(mid_study, pipeline, tmp_path):
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    sheet = root / "worksheets" / "H4-worksheet.csv"
    typed = {r["property"]: r["value"] for r in _worksheet_rows(sheet)
             if r["row_type"] == "level" and r["item"] == "cmmi"}
    wrong = "1" if typed["monitored"] != "1" else "2"
    _set_cell(sheet, "level", "cmmi", "value", wrong, prop="monitored")
    ledger_before = (root / "ledger.csv").read_bytes()
    archive_before = sorted(p.name for p in (root / "ledger-archive").iterdir())

    code, out, err = guide.study(["ledger", "record", "--ledger", "ledger.csv", "--host", "H4", "--kind", "worksheet",
                                  "worksheets/H4-worksheet.csv"])
    assert (code, out) == (2, "")
    shown = Path("worksheets/H4-worksheet.csv")  # printed as the platform spells it
    assert f"lint WARNING {shown}: cmmi monitored: level {wrong} entered" in err
    assert "declared manual rule (approved, overall pooled-checks)" in err
    assert "nothing was recorded" in err
    assert (root / "ledger.csv").read_bytes() == ledger_before
    assert sorted(p.name for p in (root / "ledger-archive").iterdir()) == archive_before

    _set_cell(sheet, "level", "cmmi", "value", typed["monitored"], prop="monitored")
    guide.hash_worksheet("H4")
    assert len(read_ledger(root / "ledger.csv")) == len(read_ledger(mid_study / "ledger.csv")) + 1


def test_withdrawing_a_host_lets_the_rest_proceed_and_is_reported(mid_study, pipeline, tmp_path):
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    guide.hash_worksheet("H4")
    guide.tool_run("H4", 3)
    code, _, err = guide.study(["register-sheet", "--study-dir", "."])
    assert code == 2 and "H5 (no worksheet yet" in err

    code, out, err = guide.study(["ledger", "withdraw", "--ledger", "ledger.csv", "--host", "H5",
                                  "--reason", WITHDRAW_REASON])
    assert code == 0, err
    lines = out.splitlines()
    assert lines[1].startswith("archive copy: ledger-archive/")
    assert lines[2].startswith("H5 withdrawn at ") and lines[2].endswith(f": {WITHDRAW_REASON}")
    when = lines[2][len("H5 withdrawn at "):-len(f": {WITHDRAW_REASON}")]
    parse_utc_timestamp(when)
    rows = len(read_ledger(root / "ledger.csv"))
    code, out, err = guide.study(["ledger", "withdraw", "--ledger", "ledger.csv", "--host", "H5", "--reason", "again"])
    assert (code, out) == (2, "") and "already withdrawn" in err
    assert len(read_ledger(root / "ledger.csv")) == rows

    code, out, _ = guide.study(["ledger", "status", "--ledger", "ledger.csv", "--hosts", ",".join(HOSTS)])
    assert code == 0, out
    assert [line.split(None, 2)[2] for line in out.splitlines() if line.split()[:2] == ["H5", "WITHDRAWN"]] == [
        f"{when}: {WITHDRAW_REASON}"]
    assert guide.study(["ledger", "verify", "--ledger", "ledger.csv"])[0] == 0
    written = guide.ok(guide.study(["register-sheet", "--study-dir", "."])).splitlines()
    assert sorted(Path(p).name for p in written) == sorted(
        f"{h}-{kind}.csv" for h in HOSTS[:4] for kind in ("register-review", "missed-gaps"))
    guide.judge_register(HOSTS[:4])

    code, out, err = guide.study(["agreement", "--study-dir", "."])
    assert code == 0, out + err
    summary = _json(root / "analysis" / "summary.json")
    assert summary["config"]["hosts"] == HOSTS[:4] and summary["config"]["config_hosts"] == HOSTS
    assert summary["config"]["withdrawn"] == {"H5": {"recorded_at_utc": when, "reason": WITHDRAW_REASON}}
    assert _critical(summary) == []
    withdrawn = [r for r in summary["integrity"]["checks"] if r["check"] == "hosts" and r["result"] == "WARNING"]
    assert [r["host"] for r in withdrawn] == ["H5"]
    assert when in withdrawn[0]["detail"] and WITHDRAW_REASON in withdrawn[0]["detail"]
    text = (root / "analysis" / "summary.md").read_text(encoding="utf-8")
    assert [line for line in text.splitlines() if line.startswith("| Withdrawn hosts")
            and "H5" in line and WITHDRAW_REASON in line]
    assert {r["host"] for r in _rows(root / "analysis" / "host_levels.csv")} == set(HOSTS[:4])


def test_a_complete_study_opens_the_seal_and_analyses_without_a_critical_problem(mid_study, pipeline, tmp_path):
    """Every host done in the protocol's order: verify is clean, register
    sheets are issued once every worksheet is hashed, and agreement exits 0
    with no SYNTHETIC label. Repeating a tool run onto a hashed output is
    refused and changes nothing."""
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    guide.hash_worksheet("H4")
    guide.tool_run("H4", 3)
    guide.host("H5", 4)

    output = root / "outputs" / tool_output_name("H1", "cisa-ztmm")
    sealed = output.read_bytes()
    code, out, err = guide.tool(guide.replay("H1", "cisa-ztmm"))
    assert (code, out) == (2, "")
    assert "refusing to replace outputs/H1-cisa-ztmm.json: study runs never overwrite a file" in err
    assert output.read_bytes() == sealed

    code, out, _ = guide.study(["ledger", "verify", "--ledger", "ledger.csv"])
    assert code == 0 and all(line.startswith("OK ") for line in out.splitlines()), out
    assert guide.study(["ledger", "status", "--ledger", "ledger.csv", "--hosts", ",".join(HOSTS)])[0] == 0
    guide.ok(guide.study(["register-sheet", "--study-dir", "."]))
    guide.judge_register(HOSTS)
    code, out, err = guide.study(["agreement", "--study-dir", "."])
    assert code == 0, out + err
    assert out.splitlines()[0].startswith("agreement: wrote 12 files to ")
    assert sorted(p.name for p in (root / "analysis").iterdir()) == sorted(ANALYSIS_FILES)
    assert not (root / "analysis" / "summary.md").read_text(encoding="utf-8").startswith(SYNTHETIC_BANNER)
    summary = _json(root / "analysis" / "summary.json")
    assert summary["config"]["synthetic"] is False and summary["run"]["synthetic"] is False
    assert _critical(summary) == []
    warned = {r["check"] for r in summary["integrity"]["checks"] if r["result"] == "WARNING"}
    assert warned <= {"analysis_code"}, warned
    assert summary["h2"]["available"] is True


def test_facts_still_marked_synthetic_in_a_study_are_critical(mid_study, pipeline, tmp_path):
    """The complete study with one host's facts file still naming the kit's
    connector ("synthetic"), as happens when the kit's facts are copied in:
    the seal opens, but agreement exits 3 with a synthetic CRITICAL for that
    host and labels every output SYNTHETIC (any marker labels the study)."""
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    guide.hash_worksheet("H4")
    guide.tool_run("H4", 3)
    guide.host("H5", 4, connector=synthetic.SYNTHETIC_CONNECTOR)
    guide.ok(guide.study(["register-sheet", "--study-dir", "."]))
    guide.judge_register(HOSTS)
    code, out, err = guide.study(["agreement", "--study-dir", "."])
    assert code == 3, out + err
    assert "agreement: CRITICAL integrity problems; see section 2 of the summary" in out.splitlines()
    summary = _json(root / "analysis" / "SYNTHETIC-summary.json")
    assert _critical(summary) == [("synthetic", "H5")]
    detail = next(r["detail"] for r in summary["integrity"]["checks"] if r["result"] == "CRITICAL")
    assert "names connector 'synthetic'" in detail and "says synthetic: false" in detail
    assert sorted(p.name for p in (root / "analysis").iterdir()) == sorted("SYNTHETIC-" + n for n in ANALYSIS_FILES)


# ------------------------------------------------------------------ round 2: what can no longer pass unnoticed
def test_an_edited_hashed_worksheet_is_never_recorded_again_and_its_archive_copy_restores_it(mid_study, pipeline,
                                                                                              tmp_path):
    """Every host done; then H1's hashed worksheet is edited (one cell, as an
    Excel save would). Step 3 again is refused, also with --force, before
    any lint: nothing is recorded or archived, and the message names the
    archive copy to restore. Copying that copy back (the guide's 'If a
    hashed file changed') gives verify 0; step 3 again then only says
    'already recorded', and the study runs to agreement exit 0."""
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    guide.hash_worksheet("H4")
    guide.tool_run("H4", 3)
    guide.host("H5", 4)
    sheet = root / "worksheets" / worksheet_name("H1")
    original = sheet.read_bytes()
    index, first = next((i, r) for i, r in enumerate(guide.rows()) if r.kind == "worksheet" and r.host_code == "H1")
    copy = f"ledger-archive/{first.sha256}.csv"
    _set_cell(sheet, "check", "MON-01", "evidence_notes", "edited after the hash")
    before = guide.snapshot()

    for extra in ([], ["--force"]):
        code, out, err = guide.study(["ledger", "record", "--ledger", "ledger.csv", "--host", "H1", "--kind",
                                      "worksheet", *extra, "worksheets/H1-worksheet.csv"])
        assert (code, out) == (2, ""), extra
        assert (f"error: worksheets/H1-worksheet.csv was hashed at {first.recorded_at_utc} (ledger line {index + 2}, "
                "kind worksheet)") in err
        assert f"restore the recorded bytes from {copy} (or your commit or e-mailed copy)" in err
        assert "nothing was recorded" in err and "lint " not in err
        assert guide.snapshot() == before
    code, out, _ = guide.study(["ledger", "verify", "--ledger", "ledger.csv"])
    assert code == 1 and "CHANGED worksheets/H1-worksheet.csv  (worksheet)" in out.splitlines()
    code, out, err = guide.study(["register-sheet", "--study-dir", "."])
    assert (code, out) == (2, "") and f"restore the original bytes from {copy}" in err

    shutil.copyfile(str(root / copy), str(sheet))  # Copy-Item ledger-archive\<sha256>.csv worksheets\H1-worksheet.csv
    assert sheet.read_bytes() == original
    code, out, _ = guide.study(["ledger", "verify", "--ledger", "ledger.csv"])
    assert code == 0 and all(line.startswith("OK ") for line in out.splitlines()), out
    out = guide.record("H1", "worksheet", "worksheets/H1-worksheet.csv")
    assert out.splitlines() == [f"already recorded at {first.recorded_at_utc} (ledger line {index + 2}):",
                                f"{first.sha256}  worksheets/H1-worksheet.csv", f"archive copy: {copy}"]
    assert guide.snapshot() == before
    summary = guide.after_the_last_host(HOSTS)
    assert _critical(summary) == []


def test_a_study_yaml_host_edit_never_opens_the_seal(pipeline, tmp_path):
    """Mid-study, with H4 and H5 not started and holding no ledger row yet
    (as under decision 3 'exclude', where no host has input rows), study.yaml
    is edited to list only H1-H3. Not recorded, the edit keeps register-sheet
    and agreement sealed (and withdraw refuses), with nothing written and no
    tool result shown. Recorded again after the first tool run, the edit
    still opens nothing: the hosts of the version in force at the first
    tool run stay in the seal."""
    root = tmp_path / "study"
    root.mkdir()
    guide = GuideStudy(root, pipeline.root)
    guide.setup(HOSTS, inputs_for=HOSTS[:3])
    for index, host in enumerate(HOSTS[:3]):
        guide.host(host, index)
    assert {r.host_code for r in guide.rows()} == {"STUDY", "H1", "H2", "H3"}
    config = root / "study.yaml"
    config.write_bytes(config.read_bytes().replace(b"hosts: [H1, H2, H3, H4, H5]", b"hosts: [H1, H2, H3]"))
    before = guide.snapshot()
    results = _tool_texts(root, HOSTS[:3])
    commands = (["register-sheet", "--study-dir", "."], ["agreement", "--study-dir", ".", "--out", "analysis-early"])

    for argv in commands:
        code, out, err = guide.study(argv)
        assert (code, out) == (2, ""), argv
        assert "STUDY (study.yaml changed since it was last recorded (ledger line 3, " in err
        assert "editing study.yaml never opens the seal" in err
        assert not [s for s in results if s in err], argv
    code, out, err = guide.study(["ledger", "withdraw", "--ledger", "ledger.csv", "--host", "H4",
                                  "--reason", WITHDRAW_REASON])
    assert (code, out) == (2, "") and "record or restore study.yaml first; nothing was recorded" in err
    assert guide.snapshot() == before

    guide.ok(guide.study(["ledger", "record", "--ledger", "ledger.csv", "--host", "STUDY", "--kind", "other",
                          "--note", "hosts H1-H3", "study.yaml"]))
    assert study_ledger.first_tool_row(guide.rows())[0] < len(guide.rows()) - 1
    for argv in commands:
        code, out, err = guide.study(argv)
        assert (code, out) == (2, ""), argv
        assert "H4 (no worksheet yet" in err and "H5 (no worksheet yet" in err and "STUDY (" not in err
        assert not [s for s in results if s in err], argv
    assert list((root / "register").iterdir()) == []
    assert not (root / "analysis-early").exists() and not (root / "analysis").exists()
    assert not [r for r in guide.rows() if study_ledger.is_seal_opening(r)]
    code, out, _ = guide.study(["ledger", "verify", "--ledger", "ledger.csv"])
    assert code == 1 and "CHANGED study.yaml  (other)" in out.splitlines()


def test_a_host_added_and_hashed_after_the_seal_opened_is_critical(complete_study, pipeline, tmp_path):
    """After unsealing, H6 is added to study.yaml (recorded again) and goes
    through every step in order. Its blind pass came after tool results
    were available: agreement reports it as CRITICAL, and the changed host
    list as a CRITICAL sensitivity run."""
    root = _copy_study(complete_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    config = root / "study.yaml"
    config.write_text(config.read_text(encoding="utf-8").replace("hosts: [H1, H2, H3, H4, H5]",
                                                                 "hosts: [H1, H2, H3, H4, H5, H6]"), encoding="utf-8")
    guide.ok(guide.study(["ledger", "record", "--ledger", "ledger.csv", "--host", "STUDY", "--kind", "other",
                          "--note", "H6 added", "study.yaml"]))
    guide.record("H6", "input", *guide.write_inputs("H6", source="H1"))
    guide.worksheet("H6", source="H1")
    guide.hash_worksheet("H6")
    guide.tool_run("H6", 5, source="H1")

    summary = guide.agreement("analysis-h6")
    critical = _critical_details(summary)
    opened = study_ledger.first_seal_opening(guide.rows())
    sheet_row = next(r for r in guide.rows() if r.kind == "worksheet" and r.host_code == "H6")
    assert ("ledger_order", "H6",
            f"H6's worksheet was hashed at {sheet_row.recorded_at_utc}, after the seal was first opened at "
            f"{opened[1].recorded_at_utc} (ledger line {opened[0] + 2}): its blind pass may have seen tool "
            "results") in critical
    config_findings = [detail for check, _, detail in critical if check == "config"]
    assert len(config_findings) == 1 and "hosts: H6 added; this run is a sensitivity run" in config_findings[0]
    assert summary["config"]["sensitivity_run"] is True


def test_a_withdrawal_after_the_seal_opened_needs_after_unseal_and_is_critical(complete_study, pipeline, tmp_path):
    """Once register-sheet or agreement has opened the seal, withdrawing a
    host is a post-hoc exclusion: refused without --after-unseal (nothing
    recorded), recorded with it (the note says so), and CRITICAL in agreement."""
    root = _copy_study(complete_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    before = guide.snapshot()
    opened = study_ledger.first_seal_opening(guide.rows())
    argv = ["ledger", "withdraw", "--ledger", "ledger.csv", "--host", "H3", "--reason", "results looked odd"]
    code, out, err = guide.study(argv)
    assert (code, out) == (2, "")
    assert err == (f"error: the seal was opened at {opened[1].recorded_at_utc} (ledger line {opened[0] + 2}): "
                   "withdrawing H3 now is a post-hoc exclusion, which agreement reports as CRITICAL; add "
                   "--after-unseal to record it anyway\n")
    assert guide.snapshot() == before

    code, out, err = guide.study(argv + ["--after-unseal"])
    assert code == 0, err
    row = guide.rows()[-1]
    assert out.splitlines()[-1] == (f"H3 withdrawn at {row.recorded_at_utc}: (after the seal was opened) results "
                                    "looked odd")
    hashed = study_ledger.first_tool_row(guide.rows(), "H3")[1].recorded_at_utc
    assert err == (f"note: H3's tool outputs were hashed at {hashed}; agreement reports this withdrawal with "
                   "that time\n")

    summary = guide.agreement("analysis-late")
    assert _critical_details(summary) == [
        ("hosts", "H3", f"H3 was withdrawn at {row.recorded_at_utc}, after the seal was first opened at "
                        f"{opened[1].recorded_at_utc} (ledger line {opened[0] + 2}): a post-hoc exclusion; the "
                        "pre-registered analysis includes H3")]
    assert summary["config"]["hosts"] == ["H1", "H2", "H4", "H5"]


def test_another_configuration_after_unsealing_is_a_critical_labelled_sensitivity_run(complete_study, pipeline,
                                                                                      tmp_path):
    """After unsealing, only a command-line override is a sensitivity run
    without a finding. A --config with another threshold, and study.yaml
    changed and recorded again, are each CRITICAL and labelled a
    sensitivity run in summary.md and summary.json."""
    root = _copy_study(complete_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    text = (root / "study.yaml").read_text(encoding="utf-8")
    assert "threshold: 0.80" in text
    line = next(i for i, r in enumerate(guide.rows()) if r.path == "study.yaml" and r.kind == "other") + 2

    summary = guide.agreement("analysis-flag", "--threshold", "0.6", expect=0)
    assert summary["config"]["sensitivity_run"] is True and summary["config"]["config_differences"] == []
    assert _critical(summary) == []

    (root / "study-t060.yaml").write_text(text.replace("threshold: 0.80", "threshold: 0.60"), encoding="utf-8")
    (root / "study.yaml").write_text(text.replace("threshold: 0.80", "threshold: 0.60"), encoding="utf-8")
    guide.ok(guide.study(["ledger", "record", "--ledger", "ledger.csv", "--host", "STUDY", "--kind", "other",
                          "--note", "threshold changed after unsealing", "study.yaml"]))
    for out_dir, extra, name in (("analysis-t060", ["--config", "study-t060.yaml"], "study-t060.yaml"),
                                 ("analysis-yaml", [], "study.yaml")):
        summary = guide.agreement(out_dir, *extra)
        assert _critical_details(summary) == [
            ("config", "", f"the configuration used ({name}) differs from study.yaml as it was when the seal first "
                           f"opened (ledger line {line}): threshold 0.80 -> 0.60; this run is a sensitivity run, not "
                           "the pre-registered analysis")], out_dir
        assert summary["config"]["sensitivity_run"] is True
        assert summary["config"]["config_differences"] == ["threshold 0.80 -> 0.60"]
        text_md = (root / out_dir / "summary.md").read_text(encoding="utf-8")
        assert (f"| Sensitivity run (command-line overrides, configuration differences, post-hoc exclusions) | yes: {name} differs from "
                f"study.yaml as recorded at ledger line {line}, when the seal first opened: threshold 0.80 -> 0.60 |"
                in text_md.splitlines()), out_dir


def test_swapped_or_duplicated_inputs_are_a_health_problem_and_critical(mid_study, pipeline, tmp_path):
    """H4's run gets its two input files swapped, H5's run the attestation
    twice. Step 8 (health --ledger) prints a PROBLEM line naming the
    mix-up, and agreement reports each as CRITICAL (inputs)."""
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    guide.hash_worksheet("H4")
    code, out = guide.tool_run("H4", 3, attestation="inputs/H4-inventory-record.json",
                               inventory_record="inputs/H4-attestation.json", healthy=False)
    assert code == 1 and len(_problems(out)) == len(METHODOLOGIES), out
    for line in _problems(out):
        assert line.startswith("PROBLEM outputs/H4-"), line
        assert ": inputs match the ledger for H4: no (the attestation the tool used (sha256 " in line
        assert "is inputs/H4-inventory-record.json, H4's inventory record as recorded at " in line
        assert "is inputs/H4-attestation.json, H4's attestation as recorded at " in line
        assert line.endswith(": the two input files were swapped or mixed up)")
    guide.worksheet("H5")
    guide.hash_worksheet("H5")
    code, out = guide.tool_run("H5", 4, attestation="inputs/H5-attestation.json",
                               inventory_record="inputs/H5-attestation.json", healthy=False)
    assert code == 1 and len(_problems(out)) == len(METHODOLOGIES), out
    recorded = next(r for r in guide.rows() if r.path == "inputs/H5-attestation.json").recorded_at_utc
    for line in _problems(out):
        assert ": inputs match the ledger for H5: no (the run was given the same file (sha256 " in line
        assert line.endswith(") as --attestation and as --inventory-record: inputs/H5-attestation.json as recorded "
                             f"at {recorded})"), line

    summary = guide.after_the_last_host(HOSTS, expect=3)
    critical = _critical_details(summary)
    assert {(check, host) for check, host, _ in critical} == {("inputs", "H4"), ("inputs", "H5")}
    assert all("swapped or mixed up" in detail for _, host, detail in critical if host == "H4")
    assert all("as --attestation and as --inventory-record" in detail for _, host, detail in critical if host == "H5")


def test_an_input_recorded_again_after_the_worksheet_hash_and_used_by_the_tool_is_critical(mid_study, pipeline,
                                                                                          tmp_path):
    """H4's attestation is changed and recorded again after H4's worksheet
    was hashed, and the tool is given the new version: the assessor and the
    tool used different files. Step 8 prints a PROBLEM line saying so, and
    agreement reports it as CRITICAL."""
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    guide.hash_worksheet("H4")
    path = root / "inputs" / "H4-attestation.json"
    data = _json(path)
    data["identity_aware_access"] = {"enabled": not data["identity_aware_access"]["enabled"]}
    write_json(path, data, overwrite=True)
    guide.record("H4", "input", "inputs/H4-attestation.json")
    rows = guide.rows()
    first = next(r for r in rows if r.path == "inputs/H4-attestation.json")
    sheet = next(r for r in rows if r.kind == "worksheet" and r.host_code == "H4")
    again = rows[-1]
    code, out = guide.tool_run("H4", 3, healthy=False)
    reason = (f"the tool used inputs/H4-attestation.json as recorded at {again.recorded_at_utc}, after H4's worksheet "
              f"was hashed at {sheet.recorded_at_utc}; the assessor had the version recorded at "
              f"{first.recorded_at_utc}")
    assert code == 1
    assert _problems(out) == [f"PROBLEM outputs/{tool_output_name('H4', m)}: inputs match the ledger for H4: no "
                              f"({reason})" for m in METHODOLOGIES]
    guide.host("H5", 4)

    summary = guide.after_the_last_host(HOSTS, expect=3)
    assert _critical_details(summary) == [("inputs", "H4", f"{tool_output_name('H4', m)}: {reason}")
                                          for m in METHODOLOGIES]
    code, out, _ = guide.study(["ledger", "verify", "--ledger", "ledger.csv"])
    assert code == 1 and "CHANGED inputs/H4-attestation.json  (input)" in out.splitlines()


def test_a_study_run_without_o_is_refused_and_prints_nothing(mid_study, pipeline, tmp_path):
    """A study run (here step 6's --facts replay) that lost its -o stops
    before it reads anything: exit 2, nothing on stdout, no file written.
    With --stdout, as in the guide's --as-of demonstration, it prints the
    report, the same as the hashed output apart from run_at_utc."""
    root = _copy_study(mid_study, tmp_path)
    guide = GuideStudy(root, pipeline.root)
    argv = guide.replay("H1", "cmmi")
    argv = argv[:argv.index("-o")] + argv[argv.index("-o") + 2:]
    files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*"))

    code, out, err = guide.tool(argv)
    assert (code, out) == (2, "")
    assert err == ("error: this run's report holds results, so it goes to a file: give -o FILE, or --stdout to "
                   "print it here\n")
    assert sorted(p.relative_to(root).as_posix() for p in root.rglob("*")) == files

    code, out, err = guide.tool(argv + ["--stdout"])
    assert (code, err) == (0, "")
    printed, hashed = json.loads(out), _json(root / "outputs" / tool_output_name("H1", "cmmi"))
    for data in (printed, hashed):
        parse_utc_timestamp(data["assessment"]["provenance"].pop("run_at_utc"))
    assert printed == hashed
    assert sorted(p.relative_to(root).as_posix() for p in root.rglob("*")) == files


# ------------------------------------------------------------------ the guide and the package
ATTRIBUTION = "Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review."
GUIDE = Path(synthetic.__file__).resolve().parent / "README.md"
_TOKEN = re.compile(r'"[^"]*"|\S+')


def _guide_commands() -> List[List[str]]:
    """Every `-m miccmac ...` and `-m miccmac_study ...` command in the
    guide's code lines, as tokens after `-m` (pipes, statement separators,
    foreach braces and a `>` redirect end a command)."""
    commands = []
    for line in GUIDE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("    "):
            continue
        for part in re.split(r"[;{}|]", line.strip()):
            if "-m miccmac" not in part:
                continue
            tokens = _TOKEN.findall(part[part.index("-m miccmac") + 3:])
            if ">" in tokens:
                tokens = tokens[:tokens.index(">")]
            commands.append(tokens)
    return commands


def _subparser(parser: argparse.ArgumentParser, name: str) -> argparse.ArgumentParser:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[name]
    raise AssertionError(f"no sub-command {name}")


def test_every_command_in_the_guide_parses_as_written():
    """Each command the guide prints is accepted by its parser as written
    (options, choices such as --kind and --methodology, required options),
    with the guide's PowerShell variables and placeholders as values."""
    commands = _guide_commands()
    assert len(commands) >= 35
    seen = set()
    for tokens in commands:
        program, rest = tokens[0], tokens[1:]
        if program == "miccmac_study":
            name, args = rest[0], rest[1:]
            parser = argparse.ArgumentParser(prog=name)
            importlib.import_module(COMMANDS[name][0]).configure(parser)
            seen.add(name if name != "ledger" else f"ledger {args[0]}")
        else:
            assert program == "miccmac", tokens
            name, args = rest[0], rest[1:]
            parser = miccmac_parser()
            args = [name] + args
            seen.add(f"miccmac {name}")
        unknown = [t for t in args if t.startswith("-") and t not in (
            _subparser(parser, args[0])._option_string_actions if program == "miccmac" or name == "ledger"
            else parser._option_string_actions)]
        assert not unknown, (tokens, unknown)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                parser.parse_args(args)
            except SystemExit:
                raise AssertionError(f"{' '.join(tokens)}: {err.getvalue()}") from None
    assert seen == {"worksheet", "ledger record", "ledger verify", "ledger status", "ledger withdraw", "health",
                    "register-sheet", "agreement", "synthetic", "miccmac assess", "miccmac list-checks"}


def test_every_guide_line_that_writes_a_tool_output_names_its_methodology():
    """Critique: CMMI is the tool's default lens, so a guide line writing
    <H>-<methodology>.json must name that methodology itself; one that
    relied on the default would put CMMI levels under another name."""
    writers = 0
    for tokens in _guide_commands():
        if tokens[:2] != ["miccmac", "assess"] or "-o" not in tokens:
            continue
        target = tokens[tokens.index("-o") + 1].strip('"').replace("\\", "/")
        match = re.search(r"-(cmmi|cisa-ztmm)\.json$", target)
        if match is None:
            continue
        writers += 1
        assert "--methodology" in tokens, tokens
        assert tokens[tokens.index("--methodology") + 1] == match.group(1), tokens
    assert writers >= 3            # steps 5 and 6, and the rehearsal's step 5


def _guide_tool_line(flag: str) -> List[str]:
    """The guide's one `miccmac assess` command (after -m) that names `flag`
    and writes outputs/: step 5 for --connector, step 6 for --facts."""
    found = [tokens for tokens in _guide_commands() if tokens[:2] == ["miccmac", "assess"] and flag in tokens
             and any(t.startswith('"outputs\\') for t in tokens[tokens.index(flag):])]
    assert found, flag
    assert all(tokens[:6] == found[0][:6] for tokens in found), found
    return found[0][1:]


@pytest.mark.parametrize("flag", ["--connector", "--facts"])
def test_every_cut_of_the_guide_tool_lines_is_refused_before_it_connects_or_writes(pipeline, tmp_path, monkeypatch,
                                                                                  flag):
    """V1, V3 (round 2): a step-5 or step-6 line cut or wrapped when pasted must never collect, print a host's
    results or write a report with another reference date. The guide puts --save-facts / --facts and --as-of first
    and -o last, so every prefix is refused (exit 2) without calling the connector or writing a file; only the
    bare `assess $ip` prints the tool's stub report, which holds no result. The whole line connects at most once
    and prints only where the report went."""
    tokens = _guide_tool_line(flag)
    if flag == "--connector":
        assert tokens[:6] == ["assess", "$ip", "--save-facts", '"outputs\\$h-facts.json"', "--as-of", "$day"]
    else:
        assert tokens[:6] == ["assess", "$ip", "--facts", '"outputs\\$h-facts.json"', "--as-of", "$day"]
    assert tokens[-2] == "-o"
    study = tmp_path / "study"
    (study / "inputs").mkdir(parents=True)
    (study / "outputs").mkdir()
    for name in ("H1-attestation.json", "H1-inventory-record.json"):
        shutil.copyfile(str(pipeline.root / "inputs" / name), str(study / "inputs" / name))
    if flag == "--facts":
        shutil.copyfile(str(pipeline.root / "outputs" / "H1-facts.json"), str(study / "outputs" / "H1-facts.json"))
    key = tmp_path / "id_ed25519"
    key.write_text("synthetic\n", encoding="utf-8")
    facts = facts_file.load_envelope(str(pipeline.root / "outputs" / "H1-facts.json")).facts
    calls = []

    class FakeConnector:
        def __init__(self, ssh_user, ssh_key_path, port=22):
            pass

        def collect_facts(self, target, extended=False):
            calls.append(target)
            return copy.deepcopy(facts)

    monkeypatch.setattr("miccmac.connectors.ssh_osquery.SSHOsqueryConnector", FakeConnector)
    values = {"$ip": "192.0.2.10", "$day": SESSION, "$key": str(key), "$h": "H1"}

    def word(token: str) -> str:
        text = token[1:-1] if len(token) > 1 and token[0] == token[-1] == '"' else token
        for name, value in values.items():
            text = text.replace(name, value)
        return text.replace("\\", "/")

    def run(argv):
        try:
            return _run(miccmac_main, argv)
        except SystemExit as exc:                   # argparse: an option that lost its value
            return exc.code, "", ""

    argv = [word(t) for t in tokens]
    before = sorted(p.name for p in (study / "outputs").iterdir())
    with _cwd(study):
        for cut in range(1, len(argv)):
            code, out, err = run(argv[:cut])
            assert calls == [], argv[:cut]
            assert sorted(p.name for p in (study / "outputs").iterdir()) == before, argv[:cut]
            if cut <= 2:                            # `assess` or `assess $ip`: the stub run, no facts at all
                assert code == 0 and "Overall score   : n/a" in out and "Check not yet implemented." in out, out
                # Every check line is a [TODO] (the legend at the end names the other markers).
                assert re.search(r"\[(?!TODO\])[A-Z/]+\]\s+[A-Z]{3}-\d{2}\b", out) is None, out
            else:
                assert code == 2 and out == "", (argv[:cut], out, err)
        # Round 3 (V1, V3): a paste wrapped inside a quoted file name keeps the line break in the value.
        for position, token in enumerate(tokens):
            if not (len(token) > 1 and token[0] == token[-1] == '"'):
                continue
            value = argv[position]
            for cut in range(1, len(value)):
                for brk in ("\n", "\r\n"):
                    wrapped = argv[:position] + [value[:cut] + brk + value[cut:]] + argv[position + 1:]
                    code, out, err = run(wrapped)
                    assert calls == [], wrapped
                    assert (code, out) == (2, ""), (wrapped, err)
                    assert "holds a line break or another control character" in err, err
                    assert sorted(p.name for p in (study / "outputs").iterdir()) == before, wrapped
        code, out, err = run(argv)
    assert code == 0, err
    assert out == f"Report written to {argv[-1]}\n"
    assert calls == (["192.0.2.10"] if flag == "--connector" else [])


def test_the_guide_keeps_its_ai_attribution():
    text = GUIDE.read_text(encoding="utf-8")
    assert "drafted with AI assistance (Claude Code, Anthropic)" in " ".join(text.split())
    # The package docstring says where the assistance is declared (no vague "AI-use log").
    package = " ".join((miccmac_study.__doc__ or "").split())
    assert "AI-use log" not in package
    assert ("That assistance is declared in miccmac_study/README.md and in the first docstring line of every module "
            "and test file of the instruments.") in package


def test_every_study_module_and_test_file_declares_ai_assistance_first():
    root = GUIDE.parent.parent
    files = sorted((root / "miccmac_study").glob("*.py")) + sorted((root / "tests").glob("test_study_*.py"))
    assert len(files) >= 17
    for path in files:
        doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")))
        assert doc and doc.splitlines()[0] == ATTRIBUTION, path.name


def test_usage_lists_every_command():
    code, out, err = _run(main, ["--help"])
    assert (code, err) == (0, "")
    listed = [line.split()[0] for line in out.splitlines() if line.startswith("  ")]
    assert listed == list(COMMANDS)
    # The ledger's help names its real sub-commands (there is no 'ledger list').
    ledger_help = next(line for line in out.splitlines() if line.split()[:1] == ["ledger"])
    assert "Record (lint, hash and archive), verify, status or withdraw" in ledger_help
    parser = argparse.ArgumentParser()
    study_ledger.configure(parser)
    actions = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert sorted(actions.choices) == ["record", "status", "verify", "withdraw"]
    code, out, err = _run(main, ["no-such-command"])
    assert (code, out) == (2, "") and "unknown command 'no-such-command'" in err
