"""Tests for miccmac.config: excluded-checks + custom-check plugin loading.
All fixtures are tmp_path files -- no target/network dependency."""
import pytest

from miccmac.config import Config, ConfigError

VALID_PLUGIN = '''
from miccmac.model import CheckResult, Status

CHECK_IDS = ["ACME-01"]
ATTACH_TO = "controlled"
RISK_METADATA = {"ACME-01": {"cis_ig": "IG2", "fair_frequency": "MEDIUM", "fair_magnitude": "MEDIUM"}}

def run_checks(target, context):
    return [CheckResult(check_id="ACME-01", name="test", status=Status.NOT_IMPLEMENTED)]
'''


def test_config_defaults_are_inert():
    cfg = Config()
    assert cfg.excluded_checks == {}
    assert cfg.custom_checks_dir is None
    assert cfg.load_custom_checks() == {}


def test_from_file_parses_excluded_checks_and_custom_checks_dir(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (tmp_path / "config.yaml").write_text(
        "excluded_checks:\n"
        "  - check_id: MON-02\n"
        "    reason: \"No centralized SIEM in this pilot's environment.\"\n"
        "custom_checks_dir: ./custom_checks\n",
        encoding="utf-8",
    )
    cfg = Config.from_file(tmp_path / "config.yaml")
    assert cfg.excluded_checks == {"MON-02": "No centralized SIEM in this pilot's environment."}
    assert cfg.custom_checks_dir == checks_dir.resolve()


def test_from_file_excluded_check_missing_reason_raises(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("excluded_checks:\n  - check_id: MON-02\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="reason"):
        Config.from_file(p)


def test_from_file_excluded_check_plain_string_raises(tmp_path):
    """A bare check-id string (the old schema) must be rejected -- every
    exclusion now requires a recorded reason."""
    p = tmp_path / "config.yaml"
    p.write_text("excluded_checks:\n  - MON-02\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="reason"):
        Config.from_file(p)


def test_from_file_duplicate_excluded_check_raises(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "excluded_checks:\n"
        "  - check_id: MON-02\n    reason: \"first\"\n"
        "  - check_id: MON-02\n    reason: \"second\"\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate"):
        Config.from_file(p)


def test_from_file_missing_file_raises_configerror(tmp_path):
    with pytest.raises(ConfigError):
        Config.from_file(tmp_path / "nope.yaml")


def test_from_file_malformed_yaml_raises_configerror(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("excluded_checks: [unterminated", encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.from_file(p)


def test_from_file_wrong_type_excluded_checks_raises(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("excluded_checks: not-a-list\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="excluded_checks"):
        Config.from_file(p)


def test_load_custom_checks_discovers_and_validates_plugin(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (checks_dir / "acme.py").write_text(VALID_PLUGIN, encoding="utf-8")

    cfg = Config(custom_checks_dir=checks_dir)
    plugins = cfg.load_custom_checks()
    assert list(plugins) == ["controlled"]
    assert plugins["controlled"][0].check_ids == ["ACME-01"]
    assert plugins["controlled"][0].risk_metadata["ACME-01"].cis_ig == "IG2"
    assert plugins["controlled"][0].risk_metadata["ACME-01"].fair_frequency == "MEDIUM"

    result = plugins["controlled"][0].run_checks("target", {})
    assert result[0].check_id == "ACME-01"


def test_load_custom_checks_is_cached(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (checks_dir / "acme.py").write_text(VALID_PLUGIN, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    first = cfg.load_custom_checks()
    second = cfg.load_custom_checks()
    assert first is second


def test_load_custom_checks_missing_dir_raises(tmp_path):
    cfg = Config(custom_checks_dir=tmp_path / "does-not-exist")
    with pytest.raises(ConfigError):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_unknown_attach_to(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace('ATTACH_TO = "controlled"', 'ATTACH_TO = "bogus"')
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="ATTACH_TO"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_id_collision_with_builtin(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace('CHECK_IDS = ["ACME-01"]', 'CHECK_IDS = ["MON-01"]')
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="collide"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_duplicate_ids_across_plugins(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    (checks_dir / "a_first.py").write_text(VALID_PLUGIN, encoding="utf-8")
    (checks_dir / "b_second.py").write_text(VALID_PLUGIN, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="collide"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_missing_check_ids(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace('CHECK_IDS = ["ACME-01"]', "CHECK_IDS = []")
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="CHECK_IDS"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_missing_run_checks(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace("def run_checks(target, context):", "def not_run_checks(target, context):")
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="run_checks"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_missing_risk_metadata(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace(
        'RISK_METADATA = {"ACME-01": {"cis_ig": "IG2", "fair_frequency": "MEDIUM", "fair_magnitude": "MEDIUM"}}',
        "",
    )
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="RISK_METADATA"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_risk_metadata_missing_a_check_id(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace('CHECK_IDS = ["ACME-01"]', 'CHECK_IDS = ["ACME-01", "ACME-02"]')
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="ACME-02"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_invalid_cis_ig(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace('"cis_ig": "IG2"', '"cis_ig": "IG9"')
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="cis_ig"):
        cfg.load_custom_checks()


def test_load_custom_checks_rejects_invalid_fair_level(tmp_path):
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    bad = VALID_PLUGIN.replace('"fair_frequency": "MEDIUM"', '"fair_frequency": "EXTREME"')
    (checks_dir / "bad.py").write_text(bad, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    with pytest.raises(ConfigError, match="fair_frequency"):
        cfg.load_custom_checks()


def test_load_custom_checks_allows_omitted_fair_fields(tmp_path):
    """cis_ig is required; fair_frequency/fair_magnitude are optional."""
    checks_dir = tmp_path / "custom_checks"
    checks_dir.mkdir()
    minimal = VALID_PLUGIN.replace(
        'RISK_METADATA = {"ACME-01": {"cis_ig": "IG2", "fair_frequency": "MEDIUM", "fair_magnitude": "MEDIUM"}}',
        'RISK_METADATA = {"ACME-01": {"cis_ig": "IG2"}}',
    )
    (checks_dir / "acme.py").write_text(minimal, encoding="utf-8")
    cfg = Config(custom_checks_dir=checks_dir)
    plugins = cfg.load_custom_checks()
    meta = plugins["controlled"][0].risk_metadata["ACME-01"]
    assert meta.cis_ig == "IG2"
    assert meta.fair_frequency is None


def test_example_plugin_and_config_files_are_valid():
    """The shipped examples/ files must themselves load cleanly."""
    from pathlib import Path

    examples_dir = Path(__file__).resolve().parent.parent / "examples"
    cfg = Config.from_file(examples_dir / "miccmac-config.example.yaml")
    plugins = cfg.load_custom_checks()
    assert "controlled" in plugins
    assert plugins["controlled"][0].check_ids == ["ACME-01"]
