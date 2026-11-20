"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for miccmac.risk_register: which checks get an entry (findings for
FAIL/PARTIAL, missing-data entries for ERROR and for NOT_APPLICABLE with a
missing-data marker), the CIS IG / FAIR-inspired rating, the order
(findings first, then missing-data entries, each by rating, CIS IG and check
id), the missing-data texts for every source and problem, the SP 800-30
fields, and the text, markdown and JSON renderings. All tests construct
Assessment/PropertyResult/CheckResult objects directly or run the engine on
fake facts -- no target, osquery, or network dependency.

In this file, AI assistance covers every test: the original ones (the
matrix, UNRATED, the sort, custom metadata, the renderers) were kept, with
test_only_fail_and_partial_checks_are_included renamed and extended to the
new entry rule (deliberately changed: an ERROR now gets an entry) and the
empty-register test updated to the new empty text."""
import json

import pytest

from miccmac import clock
from miccmac.config import Config
from miccmac.engine import run_assessment
from miccmac.metadata import CheckMetadata, MappingsError, load_register_metadata
from miccmac.methodology import apply_methodology
from miccmac.model import Assessment, CheckResult, MissingData, PropertyResult, Status
from miccmac.risk_register import (
    FINDING,
    MISSING_DATA,
    build_risk_register,
    not_evaluated_count,
    render,
    risk_rating,
)

ORIGINAL_KEYS = ["check_id", "property_key", "name", "status", "cis_ig", "fair_frequency", "fair_magnitude",
                 "risk_rating", "detail", "remediation"]
NEW_KEYS = ["entry_type", "missing_data", "next_level", "sp800_30"]
LINUX_FACTS = {"os": {"platform": "ubuntu"}, "system_info": {}, "deb_packages": [], "systemd_units": {},
               "apt_sources": [], "expired_certificates": []}


def _assessment(checks, methodology=None, key="monitored", title="Monitored"):
    prop = PropertyResult(key=key, letter=title[0], title=title, checks=checks)
    assessment = Assessment(target="x", properties=[prop])
    if methodology:
        from miccmac.engine import score_property
        prop.score = score_property(prop)
        assessment.overall_score = prop.score
        assessment.methodology = apply_methodology(assessment, methodology)
    return assessment


def _marker(source="attestation", problem="missing-field", field="k", expected="{}"):
    return MissingData(source, problem, field, expected)


# ------------------------------------------------------------------ which checks get an entry
def test_findings_and_missing_data_get_entries_and_nothing_else():
    """Deliberately changed: the register held FAIL and PARTIAL only; an
    ERROR and a NOT_APPLICABLE with a missing-data marker now get
    missing-data entries. PASS, a genuine NOT_APPLICABLE and NOT_IMPLEMENTED
    still get none."""
    checks = [
        CheckResult("MON-01", "a", Status.FAIL),
        CheckResult("MON-02", "b", Status.PARTIAL),
        CheckResult("MON-03", "c", Status.PASS),
        CheckResult("MON-04", "d", Status.NOT_IMPLEMENTED),
        CheckResult("INV-01", "e", Status.ERROR, "Broken."),
        CheckResult("INV-02", "f", Status.NOT_APPLICABLE, "Not given.", missing_data=_marker()),
        CheckResult("INV-03", "g", Status.NOT_APPLICABLE, "Does not apply."),
    ]
    entries = build_risk_register(_assessment(checks))
    kinds = {e.check_id: e.entry_type for e in entries}
    assert kinds == {"MON-01": FINDING, "MON-02": FINDING, "INV-01": MISSING_DATA, "INV-02": MISSING_DATA}


def test_filtering_fail_and_partial_gives_exactly_the_findings():
    checks = [CheckResult("MON-01", "a", Status.FAIL), CheckResult("MON-02", "b", Status.ERROR),
              CheckResult("MON-03", "c", Status.PARTIAL),
              CheckResult("MON-04", "d", Status.NOT_APPLICABLE, missing_data=_marker())]
    entries = [e.to_dict() for e in build_risk_register(_assessment(checks))]
    assert [e["check_id"] for e in entries if e["status"] in ("FAIL", "PARTIAL")] == [
        e["check_id"] for e in entries if e["entry_type"] == "finding"]
    assert {e["status"] for e in entries if e["entry_type"] == "missing-data"} == {"ERROR", "NOT_APPLICABLE"}


def test_an_excluded_check_gets_no_entry_even_without_its_input():
    config = Config(excluded_checks={"CTL-03": "Identity-aware access is out of scope in this lab."})
    assessment = run_assessment("x", context={"facts": LINUX_FACTS}, config=config)
    ids = [e.check_id for e in build_risk_register(assessment)]
    assert "CTL-03" not in ids and "CLM-01" in ids
    controlled = next(p for p in assessment.to_dict()["properties"] if p["key"] == "controlled")
    assert "missing_data" not in next(c for c in controlled["checks"] if c["check_id"] == "CTL-03")


def test_not_implemented_checks_get_no_entry_and_are_counted_in_the_note():
    assessment = run_assessment("test-device")
    assert build_risk_register(assessment) == []
    assert not_evaluated_count(assessment) == 26
    for fmt in ("text", "markdown"):
        out = render([], fmt, not_evaluated=26)
        assert "nothing to remediate" in out.lower()
        assert ("Not evaluated: 26 check(s) are NOT_IMPLEMENTED (no facts or inputs reached them, or a custom "
                "check is a placeholder); they have no register entry.") in " ".join(out.split())
    assert "Not evaluated" not in render([], "text")


# ------------------------------------------------------------------ rating and order
def test_sort_order_highest_risk_lowest_ig_first():
    # MON-03 is IG2/HIGH-HIGH (CRITICAL), MON-01 is IG1/HIGH-MEDIUM (HIGH)
    checks = [
        CheckResult("MON-01", "a", Status.FAIL),
        CheckResult("MON-03", "c", Status.FAIL),
    ]
    entries = build_risk_register(_assessment(checks))
    assert [e.check_id for e in entries] == ["MON-03", "MON-01"]
    assert entries[0].risk_rating == "CRITICAL"
    assert entries[1].risk_rating == "HIGH"


def test_findings_come_first_and_keep_their_old_order():
    """A missing-data entry rated CRITICAL still follows a LOW finding; among
    the findings the old key (-risk, IG, id) is unchanged."""
    checks = [
        CheckResult("CLM-01", "owner", Status.FAIL),                  # LOW IG1 finding
        CheckResult("CTL-01", "mdm", Status.ERROR, "Unreadable."),    # CRITICAL missing data
        CheckResult("MON-03", "edr", Status.PARTIAL),                 # CRITICAL IG2 finding
        CheckResult("MIN-03", "fw", Status.FAIL),                     # CRITICAL IG1 finding
        CheckResult("CUR-03", "fw", Status.NOT_APPLICABLE, missing_data=_marker()),   # LOW IG2 missing data
    ]
    entries = build_risk_register(_assessment(checks))
    assert [(e.check_id, e.entry_type) for e in entries] == [
        ("MIN-03", FINDING), ("MON-03", FINDING), ("CLM-01", FINDING),
        ("CTL-01", MISSING_DATA), ("CUR-03", MISSING_DATA)]
    rank = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "UNRATED": 0}
    findings = [e for e in entries if e.entry_type == FINDING]
    assert findings == sorted(findings, key=lambda e: (-rank[e.risk_rating], {"IG1": 1, "IG2": 2}.get(e.cis_ig, 99),
                                                       e.check_id))


def test_the_order_does_not_depend_on_the_methodology():
    context = {"facts": LINUX_FACTS, "attestation": {"business_owner": {"assigned": False}}}
    orders = [[e.check_id for e in build_risk_register(run_assessment("x", context=context, methodology_name=m))]
              for m in (None, "cmmi", "cisa-ztmm")]
    assert orders[0] == orders[1] == orders[2] and orders[0]


def test_missing_metadata_check_sorts_last_as_unrated():
    checks = [
        CheckResult("MON-01", "a", Status.FAIL),      # rated
        CheckResult("CUSTOM-01", "custom", Status.FAIL),  # no metadata entry
    ]
    entries = build_risk_register(_assessment(checks))
    assert entries[-1].check_id == "CUSTOM-01"
    assert entries[-1].risk_rating == "UNRATED"
    assert entries[-1].cis_ig is None
    assert entries[-1].sp800_30.threat_source_type is None and entries[-1].sp800_30.review is None


def test_build_risk_register_raises_on_bad_metadata_path(tmp_path):
    checks = [CheckResult("MON-01", "a", Status.FAIL)]
    with pytest.raises(MappingsError):
        build_risk_register(_assessment(checks), metadata_path=tmp_path / "nope.yaml")


def test_extra_metadata_rates_a_custom_check_instead_of_unrated():
    """A custom check's declared RISK_METADATA (see miccmac/config.py) plugs
    it into the same prioritization as built-in checks, instead of always
    sorting last as UNRATED."""
    checks = [
        CheckResult("MON-01", "a", Status.FAIL),        # built-in, HIGH
        CheckResult("CUSTOM-01", "custom", Status.FAIL),  # supplied via extra_metadata
    ]
    extra = {
        "CUSTOM-01": CheckMetadata(
            check_id="CUSTOM-01", property_key="monitored",
            cis_ig="IG1", fair_frequency="HIGH", fair_magnitude="HIGH",
        ),
    }
    entries = build_risk_register(_assessment(checks), extra_metadata=extra)
    custom_entry = next(e for e in entries if e.check_id == "CUSTOM-01")
    assert custom_entry.cis_ig == "IG1"
    assert custom_entry.risk_rating == "CRITICAL"
    # CRITICAL outranks MON-01's HIGH, so the custom check sorts first.
    assert entries[0].check_id == "CUSTOM-01"


@pytest.mark.parametrize("frequency,magnitude,expected", [
    ("LOW", "LOW", "LOW"), ("LOW", "MEDIUM", "LOW"), ("LOW", "HIGH", "MODERATE"),
    ("MEDIUM", "LOW", "LOW"), ("MEDIUM", "MEDIUM", "MODERATE"), ("MEDIUM", "HIGH", "HIGH"),
    ("HIGH", "LOW", "MODERATE"), ("HIGH", "MEDIUM", "HIGH"), ("HIGH", "HIGH", "CRITICAL"),
])
def test_risk_rating_matrix_all_nine_combinations(frequency, magnitude, expected):
    assert risk_rating(frequency, magnitude) == expected


def test_risk_rating_none_inputs_are_unrated():
    assert risk_rating(None, "HIGH") == "UNRATED"
    assert risk_rating("HIGH", None) == "UNRATED"
    assert risk_rating(None, None) == "UNRATED"


# ------------------------------------------------------------------ missing-data texts
def test_an_error_with_a_marker_gets_exact_texts():
    """Design example E: an unreadable last_scan."""
    attestation = {"vulnerability_scanning": {"performed": True, "last_scan": "23/11/2026", "interval_days": 30}}
    assessment = run_assessment("x", context={"facts": LINUX_FACTS, "attestation": attestation,
                                              clock.AS_OF_KEY: clock.parse_as_of("2026-11-23")})
    entry = next(e for e in build_risk_register(assessment) if e.check_id == "ASM-01")
    assert (entry.entry_type, entry.status) == (MISSING_DATA, Status.ERROR)
    assert entry.missing_data.to_dict() == {
        "source": "attestation", "problem": "invalid-value", "field": "vulnerability_scanning.last_scan",
        "expected": "a YYYY-MM-DD date",
        "what": "The attestation file's vulnerability_scanning.last_scan value cannot be read (Attestation's "
                "last_scan='23/11/2026' is not a valid ISO date), so ASM-01 could not be evaluated.",
        "how_to_supply": "Correct vulnerability_scanning.last_scan in the --attestation file to a YYYY-MM-DD date, "
                         "and run the assessment again.",
    }
    assert entry.sp800_30.response == (
        "Correct vulnerability_scanning.last_scan in the --attestation file to a YYYY-MM-DD date, and run the "
        "assessment again. If the check then fails: Enroll the device in the organization's authenticated "
        "vulnerability-scanning schedule.")
    assert entry.remediation == ("Enroll the device in the organization's authenticated vulnerability-scanning "
                                 "schedule.")   # the static fix, unchanged


def test_an_error_without_a_marker_gets_the_generic_texts():
    entries = build_risk_register(_assessment([CheckResult("CUSTOM-02", "x", Status.ERROR, "Probe failed."),
                                               CheckResult("CUSTOM-03", "y", Status.ERROR)]))
    by_id = {e.check_id: e.missing_data.to_dict() for e in entries}
    assert by_id["CUSTOM-02"] == {
        "source": None, "problem": None, "field": None, "expected": None,
        "what": "CUSTOM-02 could not be evaluated (Probe failed).",
        "how_to_supply": "Supply or correct the data this check reads (its detail says what failed), and run the "
                         "assessment again."}
    assert by_id["CUSTOM-03"]["what"] == "CUSTOM-03 could not be evaluated (status ERROR)."


def test_a_missing_attestation_entry_in_the_design_example():
    """Design example 2: CTL-03 with no attestation at all."""
    assessment = run_assessment("x", context={"facts": LINUX_FACTS}, methodology_name="cmmi")
    entry = next(e for e in build_risk_register(assessment) if e.check_id == "CTL-03").to_dict()
    assert entry["missing_data"] == {
        "source": "attestation", "problem": "not-supplied", "field": "identity_aware_access",
        "expected": '{"enabled": true or false}',
        "what": "No attestation file was given (--attestation), so CTL-03 could not be evaluated.",
        "how_to_supply": 'Give an --attestation JSON file with the entry "identity_aware_access": {"enabled": true '
                         "or false}, recording this device's facts, and run the assessment again. If this check "
                         "does not apply to this device, exclude it with a reason in the --config file "
                         "(excluded_checks) instead.",
    }
    assert entry["sp800_30"]["vulnerability"] is None and entry["sp800_30"]["risk_basis"] == "if-control-absent"
    assert entry["next_level"]["effect"] == "not-scored"


TEMPLATES = [
    # (source, problem, field, expected) -> (what, how)
    (("attestation", "not-supplied", "k", "{X}"),
     ("No attestation file was given (--attestation), so C-01 could not be evaluated.",
      'Give an --attestation JSON file with the entry "k": {X}, recording this device\'s facts, and run the '
      "assessment again. If this check does not apply")),
    (("attestation", "not-supplied", None, "{X}"),
     ("No attestation file was given (--attestation), so C-01 could not be evaluated.",
      "Give an --attestation JSON file recording this device's facts, for example {X}, and run the assessment "
      "again. If this check")),
    (("attestation", "missing-field", "k", "{X}"),
     ('The attestation file has no "k" entry, so C-01 could not be evaluated.',
      'Add the entry "k": {X} to the --attestation file, recording this device\'s facts, and run the assessment '
      "again. If this check")),
    (("attestation", "missing-field", None, ""),
     ("The attestation file holds no entries for this check, so C-01 could not be evaluated.",
      "Put this device's facts in the --attestation file, and run the assessment again. If this check")),
    (("attestation", "invalid-value", "k.d", "a date"),
     ("The attestation file's k.d value cannot be read (Bad date), so C-01 could not be evaluated.",
      "Correct k.d in the --attestation file to a date, and run the assessment again.")),
    (("attestation", "invalid-value", None, ""),
     ("The attestation file's data for this check cannot be read (Bad date), so C-01 could not be evaluated.",
      "Correct the --attestation file, and run the assessment again.")),
    (("inventory_record", "not-supplied", None, "{R}"),
     ("No inventory-system record was given (--inventory-record), so C-01 could not be evaluated.",
      "Give the device's record from the inventory system as an --inventory-record JSON file, for example {R}, "
      "and run the assessment again. If this check")),
    (("inventory_record", "missing-field", "tracked", "true or false"),
     ('The inventory record has no "tracked" entry, so C-01 could not be evaluated.',
      'Add the entry "tracked": true or false to the --inventory-record file, and run the assessment again. If '
      "this check")),
    (("inventory_record", "missing-field", None, "{R}"),
     ("The --inventory-record file holds no record, so C-01 could not be evaluated.",
      "Put the device's record from the inventory system in the --inventory-record file, for example {R}, and run "
      "the assessment again. If this check")),
    (("inventory_record", "invalid-value", "last_reviewed", "a YYYY-MM-DD date"),
     ("The inventory record's last_reviewed value cannot be read (Bad date), so C-01 could not be evaluated.",
      "Correct last_reviewed in the --inventory-record file to a YYYY-MM-DD date, and run the assessment again.")),
    (("facts", "missing-field", "uptime", "seconds"),
     ("The collected device facts have no uptime value, so C-01 could not be evaluated.",
      "Collect the device facts again with --connector; if uptime is still missing or unreadable (expected: "
      "seconds), check it on the device by hand.")),
    (("facts", "missing-field", None, ""),
     ("The collected device facts lack the data this check reads, so C-01 could not be evaluated.",
      "Collect the device facts again with --connector; if the data is still missing or unreadable, check it on "
      "the device by hand.")),
    (("facts", "invalid-value", "stamp", "an ISO timestamp"),
     ("The collected device facts' stamp value cannot be read (Bad date), so C-01 could not be evaluated.",
      "Collect the device facts again with --connector; if stamp is still missing or unreadable (expected: an ISO "
      "timestamp), check it on the device by hand.")),
]


@pytest.mark.parametrize("marker, texts", TEMPLATES)
def test_every_missing_data_template(marker, texts):
    status = Status.ERROR if marker[1] == "invalid-value" else Status.NOT_APPLICABLE
    check = CheckResult("C-01", "c", status, "Bad date.", missing_data=MissingData(*marker))
    entry = build_risk_register(_assessment([check]))[0]
    what, how = texts
    assert entry.missing_data.what == what
    assert entry.missing_data.how_to_supply.startswith(how)
    assert entry.sp800_30.response == entry.missing_data.how_to_supply   # no fix on file for C-01
    applies = marker[0] != "facts" and marker[1] != "invalid-value"
    assert entry.missing_data.how_to_supply.endswith(
        "exclude it with a reason in the --config file (excluded_checks) instead.") == applies
    for text in (what, entry.missing_data.how_to_supply):
        assert "<" not in text and ">" not in text and "|" not in text


# ------------------------------------------------------------------ SP 800-30 fields and JSON
def test_the_sp800_30_fields_map_the_existing_ones():
    entries = build_risk_register(_assessment([CheckResult("CTL-01", "mdm", Status.FAIL, "No agent."),
                                               CheckResult("CTL-02", "admin", Status.PARTIAL, "")]))
    ctl01, ctl02 = entries
    meta = load_register_metadata()["CTL-01"]
    assert ctl01.sp800_30.to_dict() == {
        "threat_source_type": meta.threat_source_type, "threat_event": meta.threat_event,
        "vulnerability": "No agent.", "likelihood": ctl01.fair_frequency, "impact": ctl01.fair_magnitude,
        "risk": ctl01.risk_rating, "risk_basis": "finding", "response": ctl01.remediation, "review": "drafted"}
    assert ctl02.sp800_30.vulnerability == "admin"     # an empty detail falls back to the check's name


def test_to_dict_keeps_the_original_keys_in_order_and_adds_four():
    checks = [CheckResult("MON-01", "a", Status.FAIL, "Off.")]
    entry = build_risk_register(_assessment(checks, methodology="cmmi"))[0].to_dict()
    assert list(entry) == ORIGINAL_KEYS + NEW_KEYS
    assert entry["entry_type"] == "finding" and entry["missing_data"] is None
    assert entry["next_level"]["methodology"] == "cmmi"
    assert json.loads(json.dumps(entry)) == entry
    without_lens = build_risk_register(_assessment(checks))[0].to_dict()
    assert without_lens["next_level"] is None


# ------------------------------------------------------------------ rendering
def test_render_text_markdown_json_smoke():
    checks = [CheckResult("MON-01", "a", Status.FAIL)]
    entries = build_risk_register(_assessment(checks))
    assert "MON-01" in render(entries, "text")
    assert "MON-01" in render(entries, "markdown")
    assert '"check_id": "MON-01"' in render(entries, "json")


def test_render_empty_register():
    """Deliberately changed: the empty text names missing-data entries too."""
    for fmt in ("text", "markdown"):
        out = render([], fmt)
        assert "No FAIL, PARTIAL or missing-data checks -- nothing to remediate." in out


def _mixed_entries(methodology="cmmi"):
    checks = [CheckResult("CTL-01", "mdm", Status.FAIL, "No agent | at all."),
              CheckResult("CTL-04", "baseline", Status.PARTIAL, "Half."),
              CheckResult("CTL-03", "iaa", Status.NOT_APPLICABLE, "Not given.",
                          missing_data=_marker(field="identity_aware_access", expected='{"enabled": true or false}'))]
    return build_risk_register(_assessment(checks, methodology=methodology, key="controlled", title="Controlled"))


def test_text_rendering_groups_numbers_and_labels_entries():
    text = render(_mixed_entries(), "text", methodology="cmmi")
    assert "MICCMAC RISK REGISTER (structured after NIST SP 800-30 Rev. 1;" in text
    assert text.index("  FINDINGS (FAIL, PARTIAL)") < text.index("  #1 [CRITICAL] CTL-01")
    assert text.index("  #2 [MODERATE] CTL-04") < text.index(
        "  MISSING DATA (ratings apply if the control turns out to be absent)") < text.index("  #3 [HIGH    ] CTL-03")
    assert "Status: NOT_APPLICABLE (missing data)" in text
    assert 'Missing: The attestation file has no "identity_aware_access" entry' in text
    assert "If the check then fails: Place the device behind an identity-aware proxy" in text
    assert "Next level: Fixing this check alone raises Controlled" in text
    assert "SP 800-30: threat source type adversarial (drafted); threat event: " in text
    assert "vulnerability: not determined (missing data)" in text and "risk HIGH if the control is absent" in text
    assert "Next level (CMMI): the property's level now" in " ".join(text.split())


def test_markdown_rendering_has_two_tables_and_escapes_pipes():
    md = render(_mixed_entries(), "markdown", methodology="cmmi")
    assert "## Risk Register (structured after NIST SP 800-30 Rev. 1; CIS IG + FAIR-inspired rating)" in md
    assert "### Findings (FAIL, PARTIAL)" in md and "### Missing data" in md
    assert "| Next level (CMMI) |" in md and "No agent \\| at all." in md
    findings_header = next(line for line in md.splitlines() if line.startswith("| # | Risk | Check"))
    row = next(line for line in md.splitlines() if line.startswith("| 1 | CRITICAL | CTL-01"))
    assert row.count(" | ") == findings_header.count(" | ")    # the escaped pipe adds no cell


def test_without_a_lens_there_is_no_next_level_line_or_column():
    entries = _mixed_entries(methodology=None)
    text, md = render(entries, "text"), render(entries, "markdown")
    assert "Next level: not shown (no maturity lens: --methodology none)." in " ".join(text.split())
    assert "             Next level:" not in text
    assert "Next level (" not in md.split("**Legend**")[1].split("###")[1]


def test_the_legend_states_the_non_claims():
    for fmt in ("text", "markdown"):
        out = " ".join(render(_mixed_entries(), fmt).split())
        assert "not an SP 800-30 risk assessment" in out
        assert "no quantitative (FAIR/Monte Carlo) estimate" in out
        assert "NIST SP 800-39" in out and "stays the organization's decision" in out
        assert "plus a recommended response" in out
        assert "not a CMMI appraisal or a CISA assessment" in out
        assert "reflects one snapshot scoring 90 or more, not sustained improvement" in out


def test_the_drafted_note_appears_only_for_drafted_fields():
    drafted = render(_mixed_entries(), "text")
    assert "(drafted) marks a threat source type and event drafted with AI assistance" in " ".join(drafted.split())
    custom = build_risk_register(_assessment([CheckResult("CUSTOM-01", "x", Status.FAIL)]))
    plain = " ".join(render(custom, "text").split())
    assert "(drafted) marks" not in plain
    assert "threat source type n/a (not declared); threat event: n/a (not declared)" in plain


def test_the_stand_in_sentence_appears_whenever_a_threat_source_is_not_adversarial():
    stand_in = "on an accidental or structural row they stand in for likelihood and impact"
    adversarial = build_risk_register(_assessment([CheckResult("MON-01", "a", Status.FAIL)]))
    assert adversarial[0].sp800_30.threat_source_type == "adversarial"
    accidental = build_risk_register(_assessment([CheckResult("CLM-01", "a", Status.FAIL)], key="claimed",
                                                 title="Claimed"))
    assert accidental[0].sp800_30.threat_source_type == "accidental"
    for fmt in ("text", "markdown"):
        assert stand_in not in " ".join(render(adversarial, fmt).split())
        assert stand_in in " ".join(render(accidental, fmt).split())


def test_a_marker_without_an_expected_value_still_reads_well():
    for problem, start in (("not-supplied", 'Give an --attestation JSON file with a "k" entry, recording'),
                           ("missing-field", 'Add a "k" entry to the --attestation file, recording')):
        check = CheckResult("C-01", "c", Status.NOT_APPLICABLE, missing_data=MissingData("attestation", problem, "k"))
        assert build_risk_register(_assessment([check]))[0].missing_data.how_to_supply.startswith(start)
