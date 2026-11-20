"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for the provenance block (miccmac/provenance.py) and for when the
CLI adds it. git is replaced by a fake wherever a test needs a particular
answer. Synthetic values only; no network."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest

import miccmac
from miccmac import clock, provenance
from miccmac.cli import main
from miccmac.engine import run_assessment
from miccmac.model import Assessment
from miccmac.report import render
from miccmac_study.formats import PROVENANCE_FORMAT, check_ids_fingerprint

UTC = dt.timezone.utc
TARGET = "192.0.2.10"
SSH = ["--ssh-user", "assessor", "--ssh-key", "keys/id_ed25519"]
EXPECTED_KEYS = [
    "provenance_format", "tool_version", "tool_commit", "tool_tree_clean",
    "python_version", "platform", "run_at_utc", "as_of", "as_of_source",
    "methodology", "risk_register", "target", "facts_source", "connector",
    "facts_collected_at_utc", "facts_file", "inputs", "enabled_check_ids",
    "enabled_check_ids_fingerprint", "os", "osquery_version", "extended_facts",
]
LINUX_FACTS = {
    "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "codename": "resolute"},
    "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "", "hardware_serial": ""},
    "deb_packages": [{"name": "bash", "version": "5.2"}],
    "systemd_units": {"apt-daily-upgrade.timer": {"active_state": "active"}},
    "apt_update_stamp_mtime": int(dt.datetime(2026, 11, 20, 6, 0, tzinfo=UTC).timestamp()),
    "apt_sources": [], "expired_certificates": [],
}


@pytest.fixture
def set_clock(monkeypatch):
    def _set(moment: dt.datetime) -> None:
        monkeypatch.setattr(clock, "_now_utc", lambda: moment)
        monkeypatch.setattr(clock, "_today", lambda: moment.date())
    return _set


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """tmp_path as the working directory and a fake Linux connector; returns
    the list of (target, extended) collect_facts calls."""
    monkeypatch.chdir(tmp_path)
    calls = []

    class FakeConnector:
        def __init__(self, ssh_user, ssh_key_path, port=22):
            pass

        def collect_facts(self, target, extended=False):
            calls.append((target, extended))
            return copy.deepcopy(LINUX_FACTS)

    monkeypatch.setattr("miccmac.connectors.ssh_osquery.SSHOsqueryConnector", FakeConnector)
    return calls


@pytest.fixture
def fresh_git_cache():
    """tool_commit()/tool_tree_clean() are cached per process; clear them
    around tests that fake git, so no fake answer leaks into other tests."""
    provenance.tool_commit.cache_clear()
    provenance.tool_tree_clean.cache_clear()
    yield
    provenance.tool_commit.cache_clear()
    provenance.tool_tree_clean.cache_clear()


def _json_run(args, capsys) -> dict:
    assert main(args) == 0
    return json.loads(capsys.readouterr().out)


def _provenance_of(args, capsys) -> dict:
    data = _json_run(args, capsys)
    return (data.get("assessment") or data)["provenance"]


# ---------------------------------------------------------------- shape and content

def test_keys_are_exactly_the_documented_ones_in_order(lab, capsys):
    prov = _provenance_of(["assess", "test-device", "--format", "json", "--as-of", "2026-11-23"], capsys)
    assert list(prov) == EXPECTED_KEYS
    assert prov["provenance_format"] == PROVENANCE_FORMAT == provenance.PROVENANCE_FORMAT
    assert prov["tool_version"] == miccmac.__version__
    assert prov["tool_commit"] is None or re.fullmatch(r"[0-9a-f]{40}", prov["tool_commit"])
    assert prov["tool_tree_clean"] in (True, False, None)
    assert isinstance(prov["python_version"], str) and isinstance(prov["platform"], str)
    assert list(prov["inputs"]) == ["attestation", "inventory_record", "config"]
    assert list(prov["os"]) == ["platform", "name", "version", "build"]


def test_fingerprint_matches_the_study_formula_and_list_checks(lab, capsys, tmp_path):
    Path("config.yaml").write_text(
        'excluded_checks:\n  - check_id: CUR-04\n    reason: "Separate PKI audit."\n', encoding="utf-8")
    prov = _provenance_of(["assess", "test-device", "--format", "json", "--config", "config.yaml",
                           "--as-of", "2026-11-23"], capsys)
    assert prov["enabled_check_ids_fingerprint"] == check_ids_fingerprint(prov["enabled_check_ids"])
    assert prov["enabled_check_ids_fingerprint"] == provenance.check_ids_fingerprint(prov["enabled_check_ids"])
    assert re.fullmatch(r"[0-9a-f]{16}", prov["enabled_check_ids_fingerprint"])
    assert main(["list-checks", "--format", "json", "--config", "config.yaml"]) == 0
    assert prov["enabled_check_ids"] == json.loads(capsys.readouterr().out)
    assert "CUR-04" not in prov["enabled_check_ids"] and len(prov["enabled_check_ids"]) == 25


def test_a_plain_run_has_no_provenance(lab, capsys, tmp_path):
    for args in (["assess", "test-device", "--format", "json"],
                 ["assess", "test-device", "--format", "json", "--methodology", "cmmi"]):
        assert "provenance" not in _json_run(args, capsys)
    Path("attestation.json").write_text("{}", encoding="utf-8")
    data = _json_run(["assess", "test-device", "--format", "json", "--risk-register",
                      "--attestation", "attestation.json"], capsys)
    assert "provenance" not in data["assessment"]
    assert lab == []


def test_an_as_of_only_run_records_that_no_facts_were_used(lab, set_clock, capsys):
    set_clock(dt.datetime(2027, 1, 15, 10, 0, tzinfo=UTC))
    prov = _provenance_of(["assess", "test-device", "--format", "json", "--as-of", "2026-11-23"], capsys)
    assert prov["run_at_utc"] == "2027-01-15T10:00:00Z"  # the real clock, not as_of
    assert (prov["as_of"], prov["as_of_source"]) == ("2026-11-23", "cli")
    # Deliberately changed: CMMI is the default lens, so provenance records it (it was null).
    assert (prov["methodology"], prov["risk_register"], prov["target"]) == ("cmmi", False, "test-device")
    assert (prov["facts_source"], prov["connector"]) == ("none", None)
    assert (prov["facts_collected_at_utc"], prov["facts_file"]) == (None, None)
    assert prov["inputs"] == {"attestation": None, "inventory_record": None, "config": None}
    assert prov["os"] == {"platform": None, "name": None, "version": None, "build": None}
    assert (prov["osquery_version"], prov["extended_facts"]) == (None, False)


def test_methodology_none_records_null_and_the_default_records_cmmi(lab, set_clock, capsys):
    """Drafted with AI assistance (Claude Code, Anthropic): provenance names
    the lens actually applied; --methodology none applies none."""
    set_clock(dt.datetime(2027, 1, 15, 10, 0, tzinfo=UTC))
    none = _provenance_of(["assess", "test-device", "--format", "json", "--as-of", "2026-11-23",
                           "--methodology", "none"], capsys)
    assert none["methodology"] is None
    ztmm = _provenance_of(["assess", "test-device", "--format", "json", "--as-of", "2026-11-23",
                           "-m", "cisa-ztmm"], capsys)
    assert ztmm["methodology"] == "cisa-ztmm"
    assert main(["assess", "test-device", "--format", "json", "--as-of", "2026-11-23", "-m", "none"]) == 0
    assert "methodology" not in json.loads(capsys.readouterr().out)


def test_a_connector_run_without_save_facts(lab, set_clock, capsys):
    set_clock(dt.datetime(2026, 11, 23, 19, 5, tzinfo=UTC))
    prov = _provenance_of(["assess", TARGET, "--connector", "ssh-osquery", *SSH,
                           "--format", "json", "--methodology", "cisa-ztmm", "--risk-register"], capsys)
    assert lab == [(TARGET, False)]  # no extended facts without --save-facts
    assert (prov["facts_source"], prov["connector"], prov["facts_file"]) == ("connector", "ssh-osquery", None)
    assert prov["facts_collected_at_utc"] == prov["run_at_utc"] == "2026-11-23T19:05:00Z"
    assert (prov["as_of"], prov["as_of_source"]) == (None, None)
    assert (prov["methodology"], prov["risk_register"], prov["target"]) == ("cisa-ztmm", True, TARGET)
    assert prov["os"] == {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "build": None}
    assert (prov["osquery_version"], prov["extended_facts"]) == (None, False)


def test_input_paths_are_recorded_exactly_as_given_with_their_sha256(lab, capsys, tmp_path):
    Path("inputs").mkdir()
    files = {
        "attestation": ("inputs/attestation.json", b'{"business_owner": {"assigned": false}}\n'),
        "inventory_record": ("./inputs/../inputs/inventory-record.json", b'{"device_id": "H1"}'),
        "config": ("inputs/config.yaml", b"excluded_checks: []\n"),
    }
    for path, data in files.values():
        Path(path).write_bytes(data)
    prov = _provenance_of(["assess", "test-device", "--format", "json", "--as-of", "2026-11-23",
                           "--attestation", files["attestation"][0],
                           "--inventory-record", files["inventory_record"][0],
                           "--config", files["config"][0]], capsys)
    assert prov["inputs"] == {
        key: {"path": path, "sha256": hashlib.sha256(data).hexdigest()}
        for key, (path, data) in files.items()
    }
    assert str(tmp_path) not in json.dumps(prov)


# ---------------------------------------------------------------- extended facts

def _build(facts):
    return provenance.build_provenance(
        run_at_utc="2026-11-23T19:05:00Z", as_of=dt.date(2026, 11, 23), as_of_source="cli",
        methodology="cmmi", risk_register=True, target=TARGET, facts_source="connector",
        connector="ssh-osquery-windows", facts_collected_at_utc="2026-11-23T19:05:00Z",
        facts_file={"role": "saved", "sha256": "ab" * 32, "path": "outputs/H1-facts.json"},
        inputs={"config": {"sha256": "cd" * 32, "path": "inputs/config.yaml"}},
        enabled_check_ids=["MON-01", "INV-01"], facts=facts,
    )


def test_os_build_and_osquery_version_come_from_the_extended_facts():
    facts = {
        "os": {"platform": "windows", "name": "Microsoft Windows Server 2025 Standard",
               "version": "10.0.26100", "codename": None},
        "extra": {
            "osquery_info": {"ok": True, "data": [{"version": "5.12.1", "build_platform": "windows"}]},
            "os_version_full": {"ok": True, "data": [{"name": "Microsoft Windows Server 2025 Standard",
                                                      "build": "26100", "revision": "2033"}]},
        },
    }
    prov = _build(facts)
    assert list(prov) == EXPECTED_KEYS
    assert prov["os"] == {"platform": "windows", "name": "Microsoft Windows Server 2025 Standard",
                          "version": "10.0.26100", "build": "26100"}
    assert prov["osquery_version"] == "5.12.1"
    assert prov["extended_facts"] is True
    assert prov["facts_file"] == {"path": "outputs/H1-facts.json", "sha256": "ab" * 32, "role": "saved"}
    assert prov["inputs"] == {"attestation": None, "inventory_record": None,
                              "config": {"path": "inputs/config.yaml", "sha256": "cd" * 32}}
    assert prov["enabled_check_ids"] == ["MON-01", "INV-01"]
    assert prov["enabled_check_ids_fingerprint"] == check_ids_fingerprint(["MON-01", "INV-01"])


@pytest.mark.parametrize("extra", [
    {"osquery_info": {"ok": False, "error": "ConnectorError: osqueryi failed (exit 1): boom"},
     "os_version_full": {"ok": False, "error": "timeout: timed out"}},
    {"osquery_info": {"ok": True, "data": []}, "os_version_full": {"ok": True, "data": [{"build": ""}]}},
    {"osquery_info": {"ok": True, "data": "not rows"}, "os_version_full": {"ok": True, "data": [{}]}},
    {},
])
def test_failed_or_empty_extended_items_give_null(extra):
    prov = _build({"os": {"platform": "ubuntu"}, "extra": extra})
    assert prov["os"]["build"] is None
    assert prov["osquery_version"] is None
    assert prov["extended_facts"] is True


def test_no_extended_facts():
    prov = _build({"os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04"}})
    assert (prov["os"]["build"], prov["osquery_version"], prov["extended_facts"]) == (None, None, False)


def test_unknown_sources_are_refused():
    with pytest.raises(ValueError):
        provenance.build_provenance(
            run_at_utc="2026-11-23T19:05:00Z", as_of=None, as_of_source=None, methodology=None,
            risk_register=False, target=TARGET, facts_source="memory", connector=None,
            facts_collected_at_utc=None, facts_file=None, inputs={}, enabled_check_ids=[], facts=None)


# ---------------------------------------------------------------- git

class _FakeGit:
    """Stands in for subprocess.run for the git calls; records each call."""

    def __init__(self, toplevel=None, commit="0123456789abcdef0123456789abcdef01234567",
                 status="", fail=None):
        self.toplevel = str(provenance._REPO_ROOT) if toplevel is None else toplevel
        self.commit, self.status, self.fail = commit, status, fail
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        if self.fail is not None:
            raise self.fail
        if cmd[1] == "rev-parse":
            out = f"{self.toplevel}\n{self.commit}\n"
        else:
            out = self.status
        return subprocess.CompletedProcess(cmd, 0, stdout=out.encode("utf-8"), stderr=b"")


def test_commit_and_clean_tree_from_git(monkeypatch, fresh_git_cache):
    fake = _FakeGit(toplevel=str(provenance._REPO_ROOT).replace("\\", "/"))
    monkeypatch.setattr(provenance.subprocess, "run", fake)
    assert provenance.tool_commit() == "0123456789abcdef0123456789abcdef01234567"
    assert provenance.tool_tree_clean() is True
    (rev_parse, rev_kwargs), (status, status_kwargs) = fake.calls
    assert rev_parse == ["git", "rev-parse", "--show-toplevel", "HEAD"]
    # Untracked files count (CC-01): a module the commit lacks makes the
    # recorded commit unable to reproduce the run. Ignored files stay hidden
    # because "normal" (unlike "all") still honours .gitignore. This pin was
    # changed deliberately from "--untracked-files=no" (the build spec's value).
    assert status == ["git", "status", "--porcelain", "--untracked-files=normal", "--", "miccmac", "data"]
    for kwargs in (rev_kwargs, status_kwargs):
        assert kwargs["cwd"] == str(provenance._REPO_ROOT)
        assert kwargs["timeout"] == 5
        assert kwargs["env"]["GIT_OPTIONAL_LOCKS"] == "0"


def test_a_changed_tool_file_makes_the_tree_unclean(monkeypatch, fresh_git_cache):
    monkeypatch.setattr(provenance.subprocess, "run", _FakeGit(status=" M miccmac/cli.py\n"))
    assert provenance.tool_tree_clean() is False


@pytest.mark.parametrize("status", [
    "?? miccmac/clock.py\n",                      # a new module never added to the commit
    "?? miccmac/checks/helpers.py\n?? data/extra.yaml\n",
    "?? miccmac/checks/\n",                       # a whole untracked folder, as "normal" shows it
])
def test_an_untracked_tool_file_makes_the_tree_unclean(status, monkeypatch, fresh_git_cache):
    monkeypatch.setattr(provenance.subprocess, "run", _FakeGit(status=status))
    assert provenance.tool_tree_clean() is False


def test_git_results_are_cached_per_process(monkeypatch, fresh_git_cache):
    fake = _FakeGit()
    monkeypatch.setattr(provenance.subprocess, "run", fake)
    for _ in range(3):
        provenance.tool_commit()
        provenance.tool_tree_clean()
    assert len(fake.calls) == 2


@pytest.mark.parametrize("fake", [
    _FakeGit(fail=FileNotFoundError("git not installed")),
    _FakeGit(fail=subprocess.TimeoutExpired(cmd="git", timeout=5)),
    _FakeGit(commit="not-a-commit"),
    _FakeGit(toplevel="/somewhere/else/entirely"),
])
def test_git_failures_give_null(fake, monkeypatch, fresh_git_cache):
    monkeypatch.setattr(provenance.subprocess, "run", fake)
    assert provenance.tool_commit() is None
    assert provenance.tool_tree_clean() is None


def test_git_nonzero_exit_gives_null(monkeypatch, fresh_git_cache):
    def failing(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 128, stdout=b"", stderr=b"fatal: not a git repository")

    monkeypatch.setattr(provenance.subprocess, "run", failing)
    assert provenance.tool_commit() is None
    assert provenance.tool_tree_clean() is None


# ---------------------------------------------------------------- model and reports

def test_to_dict_includes_provenance_only_when_set():
    assessment = Assessment(target=TARGET)
    assert "provenance" not in assessment.to_dict()
    assessment.provenance = {"provenance_format": "miccmac-provenance/1"}
    assert assessment.to_dict()["provenance"] == {"provenance_format": "miccmac-provenance/1"}
    assert list(assessment.to_dict())[-1] == "provenance"


@pytest.mark.parametrize("fmt", ["text", "markdown"])
def test_text_and_markdown_reports_do_not_show_provenance(fmt, lab, set_clock, capsys):
    set_clock(dt.datetime(2026, 11, 23, 19, 5, tzinfo=UTC))
    assert main(["assess", TARGET, "--connector", "ssh-osquery", *SSH, "--format", fmt]) == 0
    cli_output = capsys.readouterr().out
    # The CLI's default lens is CMMI (deliberately changed: it was none).
    plain = render(run_assessment(TARGET, context={"facts": copy.deepcopy(LINUX_FACTS)}, methodology_name="cmmi"),
                   fmt)
    assert cli_output == plain + "\n"
    assert "provenance" not in cli_output.lower()
