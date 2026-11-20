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


# ------------------------------------------------------------------ the shipped section
def test_the_shipped_mappings_cover_every_check_with_valid_drafted_fields():
    threats = load_threat_metadata()
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
    typo there must stop only the register, never list-checks, a run without
    --risk-register or the study's worksheet and input checks (they all go
    through the manifest functions and load_check_metadata)."""
    broken = tmp_path / "mappings.yaml"
    text = DEFAULT_MAPPINGS_PATH.read_text(encoding="utf-8")
    assert "check_id: CUR-04, threat_source_type: structural, review: drafted" in text
    broken.write_text(text.replace("check_id: CUR-04, threat_source_type: structural, review: drafted",
                                   "check_id: CUR-04, threat_source_type: structural, review: confimed"),
                      encoding="utf-8")
    with pytest.raises(MappingsError, match="confimed"):
        load_register_metadata(broken)
    with pytest.raises(MappingsError, match="confimed"):
        build_risk_register(run_assessment("x"), metadata_path=broken)
    assert all_builtin_check_ids(broken) == all_builtin_check_ids() and len(all_builtin_check_ids(broken)) == 26
    assert load_check_metadata(broken) == load_check_metadata()


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
def _review_rows():
    rows = {}
    for line in REVIEW_TABLE.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) > 5 and re.fullmatch(r"[A-Z]{3}-\d\d", cells[0]):
            rows[cells[0]] = cells
    return rows


def test_the_review_table_lists_every_check_with_the_drafted_fields():
    text = REVIEW_TABLE.read_text(encoding="utf-8")
    assert text.startswith("Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.")
    rows = _review_rows()
    threats = load_threat_metadata()
    metadata = load_register_metadata()
    assert list(rows) == list(load_check_metadata())          # one row per check, in the checks: order
    for check_id, cells in rows.items():
        assert cells[3] == threats[check_id]["threat_source_type"], check_id
        assert cells[4] == threats[check_id]["threat_event"], check_id
        assert cells[5] == metadata[check_id].fair_frequency and cells[6] == metadata[check_id].fair_magnitude
        assert cells[8] == metadata[check_id].remediation, check_id
        assert cells[9:] == ["", "", "", "", ""], check_id     # the reviewer's columns start blank
    header = next(line for line in text.splitlines() if line.startswith("| Check |"))
    for column in ("Type confirmed", "Event confirmed", "FAIR bands fit this threat source (Y/N)",
                   "Response text confirmed", "Notes"):
        assert column in header


def test_the_docs_never_claim_the_remediation_text_was_confirmed():
    text = " ".join(METHODOLOGY_DOC.read_text(encoding="utf-8").split())
    section = text[text.index("## 9."):text.index("## 10.")].lower()
    assert "the remediation text was not part of that review" in section
    assert "confirmed CIS IG/FAIR/remediation" not in section
    assert not re.search(r"remediation[^.]{0,40}(were|was) confirmed", section)
