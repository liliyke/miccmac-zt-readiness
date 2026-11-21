"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for the NIST SP 800-30 Rev. 1 fields of the check metadata: the
`threats:` section of data/control-mappings.yaml and its loader
(miccmac.metadata.load_threat_metadata, load_register_metadata), the
independence of the check manifest from that section, the review table in
docs/sp800-30-review.md, the custom-check fields in RISK_METADATA, and the
docs' statements about what was and was not confirmed. tmp_path files and
the shipped files only; no network."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from miccmac.config import Config, ConfigError
from miccmac.engine import run_assessment
from miccmac.metadata import (
    DEFAULT_MAPPINGS_PATH,
    VALID_REVIEW_STATES,
    VALID_THREAT_SOURCE_TYPES,
    MappingsError,
    all_builtin_check_ids,
    load_check_metadata,
    load_register_metadata,
    load_threat_metadata,
)
from miccmac.risk_register import build_risk_register, render

REPO = Path(__file__).resolve().parent.parent
REVIEW_TABLE = REPO / "docs" / "sp800-30-review.md"
METHODOLOGY_DOC = REPO / "docs" / "methodology.md"

TWO_CHECKS = """
version: "0.3.0"
framework: "test"
properties: []
checks:
  - { check_id: MON-01, property_key: monitored, cis_ig: IG1, fair_frequency: HIGH, fair_magnitude: MEDIUM, remediation: "Enable logging." }
  - { check_id: INV-01, property_key: inventoried, cis_ig: IG2, fair_frequency: LOW, fair_magnitude: LOW, remediation: "Add to inventory." }
"""
THREATS = """threats:
  - { check_id: MON-01, threat_source_type: adversarial, review: drafted, threat_event: "An intruder hides." }
  - { check_id: INV-01, threat_source_type: accidental, review: confirmed, threat_event: "A record goes stale." }
"""


def _mappings(tmp_path, threats=THREATS):
    path = tmp_path / "mappings.yaml"
    path.write_text(TWO_CHECKS + threats, encoding="utf-8")
    return path


_DROPPED = "the threats: section was dropped from data/control-mappings.yaml (docs/sp800-30-review.md)"


# ------------------------------------------------------------------ the shipped section
def test_the_shipped_mappings_cover_every_check_with_valid_drafted_fields():
    """Drafted or confirmed rows alike (the researcher's review sets
    review: confirmed); skipped when the section is dropped."""
    threats = load_threat_metadata()
    if not threats:
        pytest.skip(_DROPPED)
    assert sorted(threats) == all_builtin_check_ids() and len(threats) == 26
    for check_id, fields in threats.items():
        assert fields["threat_source_type"] in VALID_THREAT_SOURCE_TYPES, check_id
        assert fields["threat_event"].strip() and fields["threat_event"].endswith("."), check_id
        assert fields["review"] in VALID_REVIEW_STATES, check_id
    metadata = load_register_metadata()
    assert all(m.threat_source_type == threats[c]["threat_source_type"] for c, m in metadata.items())


def test_the_checks_lines_keep_the_confirmed_ratings():
    """The confirmed cis_ig/fair_* values are unchanged by the new section."""
    plain, full = load_check_metadata(), load_register_metadata()
    for check_id, meta in plain.items():
        assert (meta.cis_ig, meta.fair_frequency, meta.fair_magnitude, meta.remediation) == (
            full[check_id].cis_ig, full[check_id].fair_frequency, full[check_id].fair_magnitude,
            full[check_id].remediation)
        assert meta.threat_source_type is None and meta.sp800_30_review is None


# ------------------------------------------------------------------ the loader
def test_a_file_without_a_threats_section_still_loads(tmp_path):
    path = _mappings(tmp_path, threats="")
    assert load_threat_metadata(path) == {}
    assert {m.threat_source_type for m in load_register_metadata(path).values()} == {None}


def test_the_section_is_read_into_the_register_metadata(tmp_path):
    metadata = load_register_metadata(_mappings(tmp_path))
    assert (metadata["MON-01"].threat_source_type, metadata["MON-01"].sp800_30_review) == ("adversarial", "drafted")
    assert (metadata["INV-01"].threat_event, metadata["INV-01"].sp800_30_review) == (
        "A record goes stale.", "confirmed")


@pytest.mark.parametrize("threats, message", [
    ("threats: {MON-01: adversarial}\n", "must be a list"),
    ("threats:\n  - MON-01\n", "is not a mapping"),
    ("threats:\n  - { threat_source_type: adversarial, review: drafted, threat_event: \"x.\" }\n",
     "missing a valid check_id"),
    (THREATS.replace("INV-01, threat_source_type: accidental", "CUR-09, threat_source_type: accidental"),
     "CUR-09"),
    (THREATS + "  - { check_id: MON-01, threat_source_type: adversarial, review: drafted, threat_event: \"y.\" }\n",
     "duplicate"),
    (THREATS.replace("accidental", "malicious"), "invalid threat_source_type 'malicious'"),
    (THREATS.replace('"A record goes stale."', '" "'), "non-empty threat_event"),
    (THREATS.replace("review: confirmed", "review: confimed"), "invalid review 'confimed'"),
    (THREATS.replace("review: confirmed", "reveiw: confirmed"), "invalid review None"),
    ("threats:\n" + THREATS.splitlines()[1] + "\n", "no entry for INV-01"),
])
def test_a_broken_section_raises_naming_the_file(tmp_path, threats, message):
    path = _mappings(tmp_path, threats=threats)
    with pytest.raises(MappingsError, match=re.escape(message)) as raised:
        load_register_metadata(path)
    assert str(path) in str(raised.value)


def test_the_check_manifest_does_not_read_the_threats_section(tmp_path):
    """Critique: confirming the drafted fields means editing this file, so a
    wrong value there must stop only the register, never list-checks, a run
    without --risk-register or the study's worksheet and input checks (they
    all go through the manifest functions and load_check_metadata). A YAML
    syntax error anywhere in the file stops every command (the next test).
    The CUR-04 row is found whatever its type and review state, and a broken
    section is added when the section was dropped (verifier finding: a
    hard-coded 'structural, review: drafted' failed once the row changed)."""
    broken = tmp_path / "mappings.yaml"
    text = DEFAULT_MAPPINGS_PATH.read_text(encoding="utf-8")
    row = re.search(r"check_id: CUR-04, threat_source_type: [a-z]+, review: ([a-z]+)", text)
    if row is not None:
        text = text[:row.start(1)] + "confimed" + text[row.end(1):]
    else:
        assert "\nthreats:" not in text
        text += ("\nthreats:\n  - { check_id: CUR-04, threat_source_type: structural, review: confimed, "
                 "threat_event: \"x.\" }\n")
    broken.write_text(text, encoding="utf-8")
    with pytest.raises(MappingsError, match="confimed"):
        load_register_metadata(broken)
    with pytest.raises(MappingsError, match="confimed"):
        build_risk_register(run_assessment("x"), metadata_path=broken)
    assert all_builtin_check_ids(broken) == all_builtin_check_ids() and len(all_builtin_check_ids(broken)) == 26
    assert load_check_metadata(broken) == load_check_metadata()


def test_a_yaml_syntax_error_anywhere_stops_every_command(tmp_path):
    """Verifier finding: 'a typo there stops only register runs' holds for a
    wrong value, not for broken YAML, which no command can read."""
    broken = tmp_path / "mappings.yaml"
    broken.write_text(DEFAULT_MAPPINGS_PATH.read_text(encoding="utf-8") + '\nthreats_note: "unbalanced\n',
                      encoding="utf-8")
    with pytest.raises(MappingsError):
        all_builtin_check_ids(broken)
    with pytest.raises(MappingsError):
        load_check_metadata(broken)


# ------------------------------------------------------------------ custom checks
def _plugin(tmp_path, metadata: str) -> Config:
    folder = tmp_path / "plugins"
    folder.mkdir()
    (folder / "acme.py").write_text(
        "from miccmac.model import CheckResult, Status\n"
        "CHECK_IDS = ['ACME-01']\nATTACH_TO = 'controlled'\n"
        f"RISK_METADATA = {{'ACME-01': {metadata}}}\n"
        "def run_checks(target, context):\n"
        "    return [CheckResult('ACME-01', 'Acme', Status.FAIL, 'acme detail.')]\n",
        encoding="utf-8")
    return Config(custom_checks_dir=folder)


def test_a_custom_check_may_declare_the_threat_fields(tmp_path):
    config = _plugin(tmp_path, "{'cis_ig': 'IG1', 'threat_source_type': 'environmental', "
                               "'threat_event': 'A flood   takes the site offline.'}")
    meta = config.load_custom_checks()["controlled"][0].risk_metadata["ACME-01"]
    assert (meta.threat_source_type, meta.threat_event, meta.sp800_30_review) == (
        "environmental", "A flood takes the site offline.", None)
    entry = build_risk_register(run_assessment("x", config=config), extra_metadata={"ACME-01": meta})[0]
    assert entry.sp800_30.threat_source_type == "environmental" and entry.sp800_30.review is None
    assert "threat source type environmental; threat event: A flood takes the site offline." in render([entry])


def test_a_custom_check_without_the_threat_fields_shows_not_declared(tmp_path):
    config = _plugin(tmp_path, "{'cis_ig': 'IG2'}")
    meta = config.load_custom_checks()["controlled"][0].risk_metadata["ACME-01"]
    assert (meta.threat_source_type, meta.threat_event) == (None, None)
    entry = build_risk_register(run_assessment("x", config=config), extra_metadata={"ACME-01": meta})[0]
    assert "threat source type n/a (not declared); threat event: n/a (not declared)" in render([entry])


@pytest.mark.parametrize("metadata, message", [
    ("{'cis_ig': 'IG1', 'threat_source_type': 'insider'}", "threat_source_type"),
    ("{'cis_ig': 'IG1', 'threat_event': ''}", "threat_event"),
    ("{'cis_ig': 'IG1', 'threat_event': 3}", "threat_event"),
])
def test_invalid_custom_threat_fields_are_refused(tmp_path, metadata, message):
    with pytest.raises(ConfigError, match=message):
        _plugin(tmp_path, metadata).load_custom_checks()


# ------------------------------------------------------------------ the review table and the docs
# Verifier findings: following docs/sp800-30-review.md (filling the reviewer's columns, setting review:
# confirmed, copying in a corrected type or event, recording the review in the Provenance paragraph) made
# these tests fail. They now hold in every state of the review: drafted, part-way, confirmed with or without
# corrections, and with the threats: section dropped. The drafted columns stay the record of the AI draft;
# the file must hold the drafted value or the reviewer's correction.
REVIEW_COLUMNS = 14       # Check ... Notes
_YES = ("Y", "YES")


def _review_rows(text: str):
    rows = {}
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) > 5 and re.fullmatch(r"[A-Z]{3}-\d\d", cells[0]):
            rows[cells[0]] = cells
    return rows


def _review_problems(table_text: str, mappings_path=DEFAULT_MAPPINGS_PATH):
    """Every way the review table and the mappings file disagree, as texts
    (an empty list when they agree):

    - one row per check of `checks:`, in its order, with 14 cells;
    - the FAIR bands and the matrix rating equal the file's;
    - the file's remediation is the table's response text, or the corrected
      text in "Response text confirmed";
    - with a `threats:` section: each type and event in the file is the
      drafted column's value when its reviewer cell is blank or Y, else the
      corrected value in that cell (either one while the row is still
      `review: drafted`); a row is `review: confirmed` only when both its
      type and event cells are filled in."""
    from miccmac.risk_register import risk_rating

    rows = _review_rows(table_text)
    metadata = load_register_metadata(mappings_path)
    threats = load_threat_metadata(mappings_path)
    if list(rows) != list(metadata):
        return [f"the table's rows {list(rows)} are not one per check of checks:, in its order"]
    problems = []
    for check_id, cells in rows.items():
        if len(cells) != REVIEW_COLUMNS:
            problems.append(f"{check_id}: {len(cells)} cells, not {REVIEW_COLUMNS}")
            continue
        meta = metadata[check_id]
        if (cells[5], cells[6], cells[7]) != (meta.fair_frequency, meta.fair_magnitude,
                                              risk_rating(meta.fair_frequency, meta.fair_magnitude)):
            problems.append(f"{check_id}: the FAIR bands or the matrix rating differ from the file")
        response_answer = cells[12]
        allowed = {cells[8]} | ({response_answer} if response_answer and response_answer.upper() not in _YES
                                else set())
        if meta.remediation not in allowed:
            problems.append(f"{check_id}: the file's remediation is neither the table's response text nor a "
                            "correction written in 'Response text confirmed'")
        fields = threats.get(check_id)
        if fields is None:          # the threats: section was dropped: only the mapped columns are compared
            continue
        confirmed = fields["review"] == "confirmed"
        for name, drafted, answer in (("threat_source_type", cells[3], cells[9]), ("threat_event", cells[4], cells[10])):
            if not answer or answer.upper() in _YES:
                expected = {drafted}
            else:
                expected = {answer} if confirmed else {drafted, answer}
            if fields[name] not in expected:
                problems.append(f"{check_id}: {name} in the file is {fields[name]!r}, the table gives "
                                f"{sorted(expected)}")
        if confirmed and not (cells[9] and cells[10]):
            problems.append(f"{check_id}: review: confirmed in the file, but the table records no review of its "
                            "type and event")
    return problems


def _remediation_review_recorded(table_text: str) -> bool:
    """Whether the table records a review of every response text, signed
    with the reviewer and date line."""
    rows = _review_rows(table_text)
    signature = next((line for line in table_text.splitlines() if line.startswith("Reviewer:")), "")
    return (bool(rows) and "Date:" in signature and "___" not in signature
            and all(len(cells) == REVIEW_COLUMNS and cells[12] for cells in rows.values()))


def test_the_review_table_lists_every_check_with_the_drafted_fields():
    if not REVIEW_TABLE.exists():
        pytest.skip("docs/sp800-30-review.md is not there")
    text = REVIEW_TABLE.read_text(encoding="utf-8")
    assert text.startswith("Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.")
    assert _review_problems(text) == []
    header = next(line for line in text.splitlines() if line.startswith("| Check |"))
    for column in ("Threat source type (drafted)", "Threat event (drafted)", "Type confirmed", "Event confirmed",
                   "FAIR bands fit this threat source (Y/N)", "Response text confirmed", "Notes"):
        assert column in header


def _confirmed_copies(tmp_path, corrections=True):
    """A copy of the review table with every reviewer cell filled in and
    signed, and a copy of the mappings file with review: confirmed on every
    row, as docs/sp800-30-review.md's steps leave them; with
    ``corrections``, CUR-04's type and event and CLM-01's response text
    are corrected in both."""
    table = REVIEW_TABLE.read_text(encoding="utf-8")
    mappings = DEFAULT_MAPPINGS_PATH.read_text(encoding="utf-8")
    if "\nthreats:" not in mappings:
        pytest.skip(_DROPPED)
    metadata = load_register_metadata()
    lines = []
    for line in table.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) == REVIEW_COLUMNS and re.fullmatch(r"[A-Z]{3}-\d\d", cells[0]):
            answers = ["Y", "Y", "Y", "Y", "reviewed"]
            if corrections and cells[0] == "CUR-04":
                answers[0:2] = ["environmental", "A corrected event."]
            if corrections and cells[0] == "CLM-01":
                answers[3] = "Record the owner in the CMDB."
            line = "| " + " | ".join(cells[:9] + answers) + " |"
        elif line.startswith("Reviewer:"):
            line = "Reviewer: I. Ojeh   Date: 2026-11-21"
        lines.append(line)
    mappings = re.sub(r"(threat_source_type: [a-z]+, review: )drafted", r"\1confirmed", mappings)
    if corrections:
        cur04 = metadata["CUR-04"]
        mappings = mappings.replace(
            f"check_id: CUR-04, threat_source_type: {cur04.threat_source_type}, review: confirmed, "
            f'threat_event: "{cur04.threat_event}"',
            'check_id: CUR-04, threat_source_type: environmental, review: confirmed, threat_event: "A corrected event."')
        mappings = mappings.replace(f'remediation: "{metadata["CLM-01"].remediation}"',
                                    'remediation: "Record the owner in the CMDB."')
    table_path, mappings_path = tmp_path / "review.md", tmp_path / "mappings.yaml"
    table_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    mappings_path.write_text(mappings, encoding="utf-8")
    return table_path, mappings_path


@pytest.mark.parametrize("corrections", [False, True], ids=["as-drafted", "with-corrections"])
def test_a_recorded_confirmation_keeps_the_table_and_the_file_in_step(tmp_path, corrections):
    table_path, mappings_path = _confirmed_copies(tmp_path, corrections)
    threats = load_threat_metadata(mappings_path)
    assert {fields["review"] for fields in threats.values()} == {"confirmed"}
    if corrections:
        assert threats["CUR-04"]["threat_source_type"] == "environmental"
    table = table_path.read_text(encoding="utf-8")
    assert _review_problems(table, mappings_path) == []
    assert _remediation_review_recorded(table)
    entries = build_risk_register(run_assessment("x", context={"facts": {}}), metadata_path=mappings_path)
    assert entries and all(e.sp800_30.review in ("confirmed", None) for e in entries)
    assert "(drafted) marks" not in render(entries)


def test_the_table_and_the_file_must_not_drift_apart(tmp_path):
    """A row marked confirmed in the file but not in the table, or a value
    in the file that is neither the draft nor the reviewer's correction,
    is reported."""
    table_path, mappings_path = _confirmed_copies(tmp_path, corrections=False)
    blank = re.sub(r"\| CTL-01 \|(.*)\| Y \| Y \| Y \| Y \| reviewed \|", r"| CTL-01 |\1|  |  |  |  |  |",
                   table_path.read_text(encoding="utf-8"))
    assert any(p.startswith("CTL-01: review: confirmed in the file") for p in _review_problems(blank, mappings_path))
    text = mappings_path.read_text(encoding="utf-8")
    mappings_path.write_text(re.sub(r"(check_id: MON-01, threat_source_type: )[a-z]+", r"\1structural", text),
                             encoding="utf-8")
    problems = _review_problems(table_path.read_text(encoding="utf-8"), mappings_path)
    assert any(p.startswith("MON-01: threat_source_type in the file is 'structural'") for p in problems)


def test_the_docs_never_claim_the_remediation_text_was_confirmed():
    """Not while the review table records no review of every response text
    (signed); once it does, docs/methodology.md may say so."""
    text = " ".join(METHODOLOGY_DOC.read_text(encoding="utf-8").split())
    section = text[text.index("## 9."):text.index("## 10.")].lower()
    assert "the remediation text was not part of that review" in section     # the 2026-08-29 review
    assert "confirmed CIS IG/FAIR/remediation" not in section
    table = REVIEW_TABLE.read_text(encoding="utf-8") if REVIEW_TABLE.exists() else ""
    if not _remediation_review_recorded(table):
        assert not re.search(r"remediation[^.]{0,40}(were|was) confirmed", section)
