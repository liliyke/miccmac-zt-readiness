"""Tests for miccmac.metadata: loads/validates checks: risk metadata from
data/control-mappings.yaml. All fixtures are tmp_path files -- no dependency
on a live target or network."""
import pytest

from miccmac.engine import PROPERTY_MODULES
from miccmac.metadata import (
    MappingsError,
    all_builtin_check_ids,
    builtin_check_ids_by_property,
    load_check_metadata,
)

VALID_YAML = """
version: "0.2.0"
framework: "test"
properties: []
checks:
  - { check_id: MON-01, property_key: monitored, cis_ig: IG1, fair_frequency: HIGH, fair_magnitude: MEDIUM, remediation: "Enable logging." }
  - { check_id: INV-01, property_key: inventoried, cis_ig: IG2, fair_frequency: LOW, fair_magnitude: LOW, remediation: "Add to inventory." }
"""


def test_load_check_metadata_covers_all_26_builtin_ids():
    meta = load_check_metadata()
    assert len(meta) == 26
    assert all(m.check_id == cid for cid, m in meta.items())


def test_builtin_ids_match_actual_check_modules():
    expected = set()
    for module in PROPERTY_MODULES:
        prop = module.evaluate("test-device", {})
        expected.update(c.check_id for c in prop.checks)
    assert set(all_builtin_check_ids()) == expected


def test_builtin_check_ids_by_property_grouping():
    by_property = builtin_check_ids_by_property()
    assert by_property["monitored"] == ["MON-01", "MON-02", "MON-03", "MON-04"]
    assert sum(len(v) for v in by_property.values()) == 26


def test_valid_yaml_parses(tmp_path):
    p = tmp_path / "mappings.yaml"
    p.write_text(VALID_YAML, encoding="utf-8")
    meta = load_check_metadata(p)
    assert set(meta) == {"MON-01", "INV-01"}
    assert meta["MON-01"].cis_ig == "IG1"
    assert meta["MON-01"].remediation == "Enable logging."


def test_rejects_missing_checks_section(tmp_path):
    p = tmp_path / "mappings.yaml"
    p.write_text("version: '0.2.0'\nproperties: []\n", encoding="utf-8")
    with pytest.raises(MappingsError, match="checks"):
        load_check_metadata(p)


def test_rejects_unknown_property_key(tmp_path):
    p = tmp_path / "mappings.yaml"
    p.write_text(VALID_YAML.replace("property_key: monitored", "property_key: bogus"), encoding="utf-8")
    with pytest.raises(MappingsError, match="property_key"):
        load_check_metadata(p)


def test_rejects_invalid_ig_value(tmp_path):
    p = tmp_path / "mappings.yaml"
    p.write_text(VALID_YAML.replace("cis_ig: IG1", "cis_ig: IG9"), encoding="utf-8")
    with pytest.raises(MappingsError, match="cis_ig"):
        load_check_metadata(p)


def test_rejects_invalid_fair_value(tmp_path):
    p = tmp_path / "mappings.yaml"
    p.write_text(VALID_YAML.replace("fair_frequency: HIGH", "fair_frequency: EXTREME"), encoding="utf-8")
    with pytest.raises(MappingsError, match="fair_frequency"):
        load_check_metadata(p)


def test_rejects_missing_remediation(tmp_path):
    p = tmp_path / "mappings.yaml"
    p.write_text(VALID_YAML.replace(', remediation: "Enable logging."', ""), encoding="utf-8")
    with pytest.raises(MappingsError, match="remediation"):
        load_check_metadata(p)


def test_rejects_duplicate_check_id(tmp_path):
    p = tmp_path / "mappings.yaml"
    dup = VALID_YAML + "  - { check_id: MON-01, property_key: monitored, cis_ig: IG2, fair_frequency: LOW, fair_magnitude: LOW }\n"
    p.write_text(dup, encoding="utf-8")
    with pytest.raises(MappingsError, match="duplicate"):
        load_check_metadata(p)


def test_rejects_missing_file(tmp_path):
    with pytest.raises(MappingsError):
        load_check_metadata(tmp_path / "does-not-exist.yaml")


def test_rejects_malformed_yaml(tmp_path):
    p = tmp_path / "mappings.yaml"
    p.write_text("checks: [this is not: valid: yaml: at all", encoding="utf-8")
    with pytest.raises(MappingsError):
        load_check_metadata(p)


# The lowest CIS Controls v8 Implementation Group of every Safeguard a
# built-in check cites, from CIS's Controls v8 Navigator (v8.1 changed no IG).
CIS_V8_SAFEGUARD_IG = {
    "1.1": "IG1", "2.1": "IG1", "2.3": "IG1", "3.2": "IG1", "3.10": "IG2", "4.1": "IG1",
    "4.2": "IG1", "4.5": "IG1", "4.8": "IG2", "5.4": "IG1", "6.7": "IG2", "7.1": "IG1",
    "7.3": "IG1", "7.4": "IG1", "7.5": "IG2", "7.6": "IG2", "8.2": "IG1", "8.5": "IG2",
    "8.9": "IG2", "13.7": "IG3",
}


def test_each_builtin_cis_ig_is_the_ig_of_the_safeguard_it_cites():
    """The cis_ig rule in data/control-mappings.yaml: the lowest IG at which
    the check's CIS v8 Safeguard first appears. Every built-in check cites
    exactly one Safeguard."""
    meta = load_check_metadata()
    seen = set()
    for module in PROPERTY_MODULES:
        for check in module.evaluate("test-device", {}).checks:
            cited = [ref.split()[-1] for ref in check.control_refs if ref.startswith("CIS v8 ")]
            assert len(cited) == 1, (check.check_id, check.control_refs)
            assert meta[check.check_id].cis_ig == CIS_V8_SAFEGUARD_IG[cited[0]], (check.check_id, cited[0])
            seen.add(check.check_id)
    assert len(seen) == 26
    assert [cid for cid, m in meta.items() if m.cis_ig == "IG3"] == ["MON-03"]
