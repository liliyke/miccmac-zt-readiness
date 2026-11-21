"""Tests for --save-facts and --facts.

The required property: a live run through a fake connector and a replay of
the facts it saved, with the same as_of, inputs, config and methodology,
give identical JSON apart from the provenance fields that describe the run
itself (run_at_utc, facts_source, facts_file.role, connector). Synthetic
values only (IP 192.0.2.10, user "assessor", key "keys/id_ed25519"); the
connector is a fake and nothing connects anywhere."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import pytest

import miccmac
from miccmac import clock
from miccmac.cli import main
from miccmac.facts_file import ENVELOPE_KEYS, FACTS_FORMAT

UTC = dt.timezone.utc
TARGET = "192.0.2.10"
SSH = ["--ssh-user", "assessor", "--ssh-key", "keys/id_ed25519"]
SESSION_DATE = "2026-11-23"
LABEL = " (as of 2026-11-23)"
LIVE_CLOCK = dt.datetime(2026, 11, 23, 19, 5, tzinfo=UTC)
REPLAY_CLOCK = dt.datetime(2027, 1, 15, 10, 0, tzinfo=UTC)  # weeks later
FACTS_PATH = "outputs/H1-facts.json"

LINUX_FACTS = {
    "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "codename": "resolute"},
    "system_info": {"hostname": "lab-h1", "hardware_vendor": "VMware, Inc.",
                    "hardware_model": "VMware Virtual Platform", "hardware_serial": ""},
    "deb_packages": [{"name": "bash", "version": "5.2"}, {"name": "telnet", "version": "0.17"}],
    "systemd_units": {
        "systemd-journald.service": {"id": "systemd-journald.service", "active_state": "active",
                                     "sub_state": "running", "load_state": "loaded"},
        "osqueryd.service": {"id": "osqueryd.service", "active_state": "active",
                             "sub_state": "running", "load_state": "loaded"},
        "apt-daily-upgrade.timer": {"id": "apt-daily-upgrade.timer", "active_state": "active",
                                    "sub_state": "waiting", "load_state": "loaded"},
    },
    "rsyslog_forwarding_configured": False,
    "root_locked": True,
    "sudo_users": ["assessor"],
    "listening_ports": [{"port": "22", "protocol": "6", "address": "0.0.0.0"}],
    "hardening_sysctls": {"kernel.dmesg_restrict": "1", "fs.suid_dumpable": "2"},
    "apt_update_stamp_mtime": int(dt.datetime(2026, 11, 20, 6, 0, tzinfo=UTC).timestamp()),
    "apt_sources": ["http://archive.ubuntu.com/ubuntu", "http://ppa.example.invalid/tools"],
    "platform_info": {},
    "expired_certificates": [{"common_name": "Synthetic Old Root", "not_valid_after": "100"}],
}
EXTRA = {
    "osquery_info": {"ok": True, "data": [{"version": "5.12.1", "build_platform": "ubuntu",
                                           "build_distro": "jammy"}]},
    "os_version_full": {"ok": True, "data": [{"name": "Ubuntu", "version": "26.04", "build": ""}]},
    "audit_rules": {"ok": False, "error": "ConnectorError: command failed (exit 1): Permission denied"},
}
ATTESTATION = {
    "identity_aware_access": {"enabled": True},
    "business_owner": {"assigned": True, "name": "Synthetic Owner"},
    "system_administrator": {"assigned": True, "name": "assessor"},
    "business_purpose": {"documented": True, "data_classification": "internal"},
    "vulnerability_scanning": {"performed": True, "last_scan": "2026-11-03", "interval_days": 30},
    "compliance_assessment": {"performed": True, "last_assessment": "2026-08-01", "interval_days": 90},
    "finding_remediation_sla": {"tracked": False},
    "firmware_currency": {"current": True},
}
INVENTORY_RECORD = {"device_id": "H1", "tracked": True, "last_reviewed": "2026-09-01"}
CONFIG_YAML = 'excluded_checks:\n  - check_id: MON-02\n    reason: "No central log platform in the lab."\n'
INPUTS = [
    "--attestation", "inputs/attestation.json",
    "--inventory-record", "inputs/inventory-record.json",
    "--config", "inputs/config.yaml",
]


@pytest.fixture
def set_clock(monkeypatch):
    """set_clock(moment): make `moment` the real clock that miccmac sees."""
    def _set(moment: dt.datetime) -> None:
        monkeypatch.setattr(clock, "_now_utc", lambda: moment)
        monkeypatch.setattr(clock, "_today", lambda: moment.date())
    return _set


@pytest.fixture
def study(tmp_path, monkeypatch):
    """A study-like folder (inputs/, outputs/) as the working directory and a
    fake Linux connector in place of the class cli.py imports. Returns the
    list of (target, extended) collect_facts calls."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "inputs").mkdir()
    (tmp_path / "outputs").mkdir()
    (tmp_path / "inputs" / "attestation.json").write_text(json.dumps(ATTESTATION), encoding="utf-8")
    (tmp_path / "inputs" / "inventory-record.json").write_text(json.dumps(INVENTORY_RECORD),
                                                               encoding="utf-8")
    (tmp_path / "inputs" / "config.yaml").write_text(CONFIG_YAML, encoding="utf-8")
    calls = []

    class FakeConnector:
        def __init__(self, ssh_user, ssh_key_path, port=22):
            assert (ssh_user, ssh_key_path) == ("assessor", "keys/id_ed25519")

        def collect_facts(self, target, extended=False):
            calls.append((target, extended))
            facts = copy.deepcopy(LINUX_FACTS)
            if extended:
                facts["extra"] = copy.deepcopy(EXTRA)
            return facts

    monkeypatch.setattr("miccmac.connectors.ssh_osquery.SSHOsqueryConnector", FakeConnector)
    return calls


def _live_args(methodology="cmmi", out="outputs/H1-cmmi.json", facts=FACTS_PATH):
    return ["assess", TARGET, "--connector", "ssh-osquery", *SSH, *INPUTS,
            "--methodology", methodology, "--risk-register", "--format", "json", "-o", out,
            "--as-of", SESSION_DATE, "--save-facts", facts]


def _replay_args(methodology="cmmi", out="outputs/H1-cmmi-replay.json", facts=FACTS_PATH):
    return ["assess", "--facts", facts, *INPUTS,
            "--methodology", methodology, "--risk-register", "--format", "json", "-o", out,
            "--as-of", SESSION_DATE]


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _statuses(assessment: dict) -> dict:
    return {c["check_id"]: c["status"] for p in assessment["properties"] for c in p["checks"]}


def _live_run(set_clock) -> dict:
    set_clock(LIVE_CLOCK)
    assert main(_live_args()) == 0
    return _load("outputs/H1-cmmi.json")


# ---------------------------------------------------------------- the required property

def test_replay_of_saved_facts_reproduces_the_live_run(study, set_clock, capsys):
    live = _live_run(set_clock)
    set_clock(REPLAY_CLOCK)
    assert main(_replay_args()) == 0
    assert capsys.readouterr().err == ""  # same as_of and target: no note, no warning
    replay = _load("outputs/H1-cmmi-replay.json")
    assert study == [(TARGET, True)]  # one live collection, with extended facts; no replay connection

    live_prov, replay_prov = live["assessment"]["provenance"], replay["assessment"]["provenance"]
    assert (live_prov["run_at_utc"], replay_prov["run_at_utc"]) == \
        ("2026-11-23T19:05:00Z", "2027-01-15T10:00:00Z")
    assert (live_prov["facts_source"], replay_prov["facts_source"]) == ("connector", "facts-file")
    assert (live_prov["connector"], replay_prov["connector"]) == ("ssh-osquery", None)
    assert (live_prov["facts_file"]["role"], replay_prov["facts_file"]["role"]) == ("saved", "replayed")
    for provenance in (live_prov, replay_prov):
        for key in ("run_at_utc", "facts_source", "connector"):
            del provenance[key]
        del provenance["facts_file"]["role"]
    assert live == replay

    # The comparison covered real results, not an empty shell.
    assert live_prov["facts_collected_at_utc"] == "2026-11-23T19:05:00Z"
    assert live_prov["extended_facts"] is True
    assert live["risk_register"]
    statuses = _statuses(live["assessment"])
    assert "NOT_IMPLEMENTED" not in statuses.values()
    assert statuses["MON-02"] == "NOT_APPLICABLE"  # the config's exclusion applied on both sides
    details = {c["check_id"]: c["detail"] for p in live["assessment"]["properties"] for c in p["checks"]}
    assert details["CUR-01"].endswith(LABEL)


def test_cisa_ztmm_replay_has_the_same_check_statuses_as_the_cmmi_live_run(study, set_clock):
    live = _live_run(set_clock)
    set_clock(REPLAY_CLOCK)
    assert main(_replay_args(methodology="cisa-ztmm", out="outputs/H1-cisa-ztmm.json")) == 0
    cisa = _load("outputs/H1-cisa-ztmm.json")
    assert _statuses(cisa["assessment"]) == _statuses(live["assessment"])
    assert [e["check_id"] for e in cisa["risk_register"]] == [e["check_id"] for e in live["risk_register"]]
    assert live["assessment"]["methodology"]["name"] == "cmmi"
    assert cisa["assessment"]["methodology"]["name"] == "cisa-ztmm"
    assert cisa["assessment"]["provenance"]["methodology"] == "cisa-ztmm"
    assert study == [(TARGET, True)]


# ---------------------------------------------------------------- the saved facts file

def test_saved_facts_envelope_format(study, set_clock):
    live = _live_run(set_clock)
    raw = Path(FACTS_PATH).read_bytes()
    text = raw.decode("utf-8")
    envelope = json.loads(text)
    assert list(envelope) == list(ENVELOPE_KEYS) == [
        "facts_format", "tool_version", "tool_commit", "connector", "target",
        "collected_at_utc", "as_of", "facts",
    ]
    assert text == json.dumps(envelope, indent=2) + "\n"
    assert envelope["facts_format"] == FACTS_FORMAT == "miccmac-facts/1"
    assert envelope["tool_version"] == miccmac.__version__
    assert envelope["tool_commit"] is None or re.fullmatch(r"[0-9a-f]{40}", envelope["tool_commit"])
    assert envelope["connector"] == "ssh-osquery"
    assert envelope["target"] == TARGET
    assert envelope["collected_at_utc"] == "2026-11-23T19:05:00Z"
    assert envelope["as_of"] == SESSION_DATE
    expected_facts = copy.deepcopy(LINUX_FACTS)
    expected_facts["extra"] = EXTRA
    assert envelope["facts"] == expected_facts
    assert live["assessment"]["provenance"]["facts_file"] == {
        "path": FACTS_PATH, "sha256": hashlib.sha256(raw).hexdigest(), "role": "saved",
    }
    # Written in one step: no temporary file is left next to it.
    assert sorted(p.name for p in Path("outputs").iterdir()) == ["H1-cmmi.json", "H1-facts.json"]


def test_facts_are_saved_before_the_checks_run(study, set_clock, monkeypatch, capsys):
    """Deliberately changed: a failure after the facts were saved used to end
    in a traceback; it is now an error (exit 2) that names the saved facts
    and how to build the report from them, and never the exception's text."""
    def crash(*args, **kwargs):
        raise RuntimeError("simulated failure while running the checks")

    monkeypatch.setattr("miccmac.cli.run_assessment", crash)
    set_clock(LIVE_CLOCK)
    assert main(_live_args()) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "error: an internal error (RuntimeError) while scoring the collected facts; no report was written. The "
        f"facts were saved to {FACTS_PATH}, so the report can be built from them with --facts {FACTS_PATH} (no new "
        "collection needed)\n")
    assert "simulated failure" not in captured.err
    envelope = _load(FACTS_PATH)
    assert envelope["facts"]["os"]["platform"] == "ubuntu"
    assert envelope["facts"]["extra"] == EXTRA
    assert sorted(p.name for p in Path("outputs").iterdir()) == ["H1-facts.json"]


def test_a_register_failure_after_the_save_names_the_saved_facts(study, set_clock, monkeypatch, capsys):
    """Critique round of the register change. A failure inside the new register code after
    --save-facts saved the facts says how to rebuild the report; a replay
    with --facts (no save) still raises as before."""
    def crash(*args, **kwargs):
        raise KeyError("FAIL")

    monkeypatch.setattr("miccmac.cli.build_risk_register", crash)
    set_clock(LIVE_CLOCK)
    assert main(_live_args()) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "(KeyError)" in captured.err and f"--facts {FACTS_PATH}" in captured.err
    assert "FAIL" not in captured.err     # the exception's own text is never printed
    assert not Path("outputs/H1-cmmi.json").exists()
    with pytest.raises(KeyError):
        main(_replay_args())


def test_a_register_run_checks_the_mappings_before_it_connects(study, set_clock, monkeypatch, capsys):
    """A broken mappings file stops a --risk-register run before anything is
    collected or saved."""
    from miccmac.metadata import MappingsError

    def broken(*args, **kwargs):
        raise MappingsError("data/control-mappings.yaml: CUR-04 has invalid review 'confimed'")

    monkeypatch.setattr("miccmac.cli.load_register_metadata", broken)
    set_clock(LIVE_CLOCK)
    assert main(_live_args()) == 2
    assert "invalid review 'confimed'" in capsys.readouterr().err
    assert study == [] and not Path(FACTS_PATH).exists()


def test_an_existing_save_facts_file_is_refused_before_connecting(study, set_clock, capsys):
    Path(FACTS_PATH).write_text("earlier raw data\n", encoding="utf-8")
    set_clock(LIVE_CLOCK)
    assert main(_live_args()) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: --save-facts file already exists: outputs/H1-facts.json")
    assert Path(FACTS_PATH).read_text(encoding="utf-8") == "earlier raw data\n"
    assert study == []
    assert not Path("outputs/H1-cmmi.json").exists()


@pytest.mark.parametrize("args, message", [
    (["assess", "--facts", FACTS_PATH, "--connector", "ssh-osquery", *SSH],
     "--facts cannot be combined with --connector"),
    (["assess", TARGET, "--facts", FACTS_PATH, "--connector", "ssh-osquery", *SSH,
      "--save-facts", "outputs/H2-facts.json"],
     "--facts cannot be combined with --connector"),
    (["assess", "--facts", FACTS_PATH, "--save-facts", "outputs/H2-facts.json"],
     "--facts cannot be combined with --save-facts"),
    (["assess", TARGET, "--save-facts", "outputs/H2-facts.json"],
     "--save-facts requires --connector"),
    # -o added deliberately: a live run with --save-facts now needs -o or
    # --stdout (V1-N8), and without either that refusal would come first.
    (["assess", TARGET, "--connector", "ssh-osquery", *SSH, "--save-facts", "missing/H2-facts.json",
      "-o", "outputs/H2-cmmi.json"],
     "--save-facts folder does not exist"),
    (["assess", TARGET, "--connector", "ssh-osquery", *SSH, "--save-facts", "outputs/H2-facts.json",
      "-o", "outputs/../outputs/H2-facts.json"],
     "--output and --save-facts name the same file"),
    (["assess", "--facts", FACTS_PATH, "--format", "json", "-o", FACTS_PATH],
     "--output and --facts name the same file"),
])
def test_conflicting_fact_options_are_rejected(args, message, study, set_clock, capsys):
    _live_run(set_clock)
    capsys.readouterr()
    before = {p.name: p.read_bytes() for p in Path("outputs").iterdir()}
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: " + message)
    assert captured.out == ""
    assert study == [(TARGET, True)]  # only the setup run connected
    assert {p.name: p.read_bytes() for p in Path("outputs").iterdir()} == before  # nothing written
    assert not Path("missing").exists()


VALID_ENVELOPE = {
    "facts_format": "miccmac-facts/1", "tool_version": "0.1.0", "tool_commit": None,
    "connector": "ssh-osquery", "target": TARGET, "collected_at_utc": "2026-11-23T19:05:00Z",
    "as_of": SESSION_DATE, "facts": {"os": {"platform": "ubuntu"}},
}


def _without(key):
    envelope = dict(VALID_ENVELOPE)
    del envelope[key]
    return envelope


# Every --facts run below that reads its report from stdout (or must get past
# the report-destination check to the error it tests) now passes --stdout:
# without -o or --stdout a replay is refused first (V1-N8). Added
# deliberately; tests/test_output_safety.py tests that refusal.

@pytest.mark.parametrize("content, message", [
    (b"{not json", "is not valid UTF-8 JSON"),
    (b"\xff\xfe{\x00}\x00", "is not valid UTF-8 JSON"),
    (b"\xef\xbb\xbf" + json.dumps(VALID_ENVELOPE).encode("utf-8"), "is not valid UTF-8 JSON"),
    ([VALID_ENVELOPE], "is not a miccmac facts file"),
    (dict(VALID_ENVELOPE, facts_format="miccmac-facts/2"), "facts_format is 'miccmac-facts/2'"),
    (_without("facts_format"), "facts_format is None"),
    (dict(VALID_ENVELOPE, facts=[{"os": {}}]), "'facts' must be an object containing 'os'"),
    (dict(VALID_ENVELOPE, facts={"system_info": {}}), "'facts' must be an object containing 'os'"),
    (_without("facts"), "'facts' must be an object containing 'os'"),
    (dict(VALID_ENVELOPE, facts={"os": "ubuntu"}), "facts['os'] must be an object"),
    (_without("target"), "'target' must be a non-empty string"),
    (dict(VALID_ENVELOPE, collected_at_utc="2026-11-23 19:05:00"), "collected_at_utc"),
    (_without("collected_at_utc"), "collected_at_utc"),
    (dict(VALID_ENVELOPE, as_of="23/11/2026"), "as_of"),
])
def test_a_malformed_facts_file_is_rejected(content, message, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    data = content if isinstance(content, bytes) else json.dumps(content).encode("utf-8")
    Path("bad-facts.json").write_bytes(data)
    assert main(["assess", "--facts", "bad-facts.json", "--format", "json", "--stdout"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    assert message in captured.err
    assert captured.out == ""


def test_a_missing_facts_file_is_rejected(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["assess", "--facts", "nope.json", "--stdout"]) == 2
    assert capsys.readouterr().err.startswith("error: cannot read --facts file")


def test_a_valid_hand_written_envelope_replays(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    Path("facts.json").write_text(json.dumps(VALID_ENVELOPE), encoding="utf-8")
    assert main(["assess", "--facts", "facts.json", "--format", "json", "--stdout"]) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["target"] == TARGET
    assert data["provenance"]["extended_facts"] is False


# ---------------------------------------------------------------- reference date and target on replay

def test_replay_without_as_of_uses_the_files_as_of(study, set_clock, capsys):
    _live_run(set_clock)
    set_clock(REPLAY_CLOCK)
    capsys.readouterr()
    assert main(["assess", "--facts", FACTS_PATH, *INPUTS, "--format", "json", "--stdout"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ("note: --as-of not given; using 2026-11-23, the as_of date recorded "
                            "in the facts file\n")
    data = json.loads(captured.out)
    assert (data["provenance"]["as_of"], data["provenance"]["as_of_source"]) == \
        (SESSION_DATE, "facts-file")
    details = {c["check_id"]: c["detail"] for p in data["properties"] for c in p["checks"]}
    assert details["INV-04"] == "Inventory record last reviewed 83 day(s) ago (policy: 90)." + LABEL


def test_replay_of_facts_saved_without_as_of_uses_the_collection_date(study, set_clock, capsys):
    set_clock(LIVE_CLOCK)
    args = [a for a in _live_args() if a != SESSION_DATE and a != "--as-of"]
    assert main(args) == 0
    assert _load(FACTS_PATH)["as_of"] is None
    set_clock(REPLAY_CLOCK)
    capsys.readouterr()
    assert main(["assess", "--facts", FACTS_PATH, *INPUTS, "--format", "json", "--stdout"]) == 0
    captured = capsys.readouterr()
    # CC-07: the note now also says that the live run (no --as-of) read the
    # real clock, so its date-dependent verdicts may differ from the replay's.
    # The expected text was extended deliberately for that change.
    assert captured.err == ("note: --as-of not given; using 2026-11-23, the UTC date the facts "
                            "were collected; they were saved without --as-of, so the live run "
                            "used the real clock and its date-dependent verdicts may differ "
                            "from this replay's\n")
    provenance = json.loads(captured.out)["provenance"]
    assert (provenance["as_of"], provenance["as_of_source"]) == (SESSION_DATE, "facts-collected-date")


def _evening_envelope(as_of):
    """Facts collected at 20:30 EST on 2026-11-23, which is 01:30 UTC on
    2026-11-24 (an evening session: the UTC date has already rolled over)."""
    return dict(VALID_ENVELOPE, collected_at_utc="2026-11-24T01:30:00Z", as_of=as_of)


def test_evening_replay_with_the_live_runs_own_as_of_does_not_warn(tmp_path, monkeypatch, capsys):
    """CC-05: the protocol's step-6 replay after an evening session uses the
    session's local date, which is the as_of the live run recorded and one
    day before the UTC collection date. That is not "earlier than the
    collection", so nothing is printed."""
    monkeypatch.chdir(tmp_path)
    Path("facts.json").write_text(json.dumps(_evening_envelope(SESSION_DATE)), encoding="utf-8")
    assert main(["assess", "--facts", "facts.json", "--format", "json", "--as-of", SESSION_DATE,
                 "-o", "replay.json"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == "Report written to replay.json\n"
    provenance = _load("replay.json")["provenance"]
    assert (provenance["as_of"], provenance["as_of_source"]) == (SESSION_DATE, "cli")


@pytest.mark.parametrize("file_as_of, cli_as_of, expected", [
    # A date earlier than the live run's own as_of still warns, twice.
    (SESSION_DATE, "2026-11-22",
     "warning: --as-of 2026-11-22 differs from the as_of date recorded in the facts file (2026-11-23)\n"
     "warning: --as-of 2026-11-22 is earlier than the date the facts were collected (2026-11-24 UTC)\n"),
    # A file saved without --as-of has no date of its own to match: the warning stays.
    (None, SESSION_DATE,
     "warning: --as-of 2026-11-23 is earlier than the date the facts were collected (2026-11-24 UTC)\n"),
    # The UTC collection date itself differs from the file's as_of, but is not earlier.
    (SESSION_DATE, "2026-11-24",
     "warning: --as-of 2026-11-24 differs from the as_of date recorded in the facts file (2026-11-23)\n"),
])
def test_evening_replay_warnings_otherwise_unchanged(file_as_of, cli_as_of, expected, tmp_path,
                                                      monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    Path("facts.json").write_text(json.dumps(_evening_envelope(file_as_of)), encoding="utf-8")
    assert main(["assess", "--facts", "facts.json", "--format", "json", "--as-of", cli_as_of,
                 "--stdout"]) == 0
    assert capsys.readouterr().err == expected


def test_replay_warns_when_as_of_differs_from_the_file_or_predates_collection(study, set_clock, capsys):
    _live_run(set_clock)
    capsys.readouterr()
    assert main(["assess", "--facts", FACTS_PATH, "--format", "json", "--as-of", "2026-11-20",
                 "--stdout"]) == 0
    assert capsys.readouterr().err == (
        "warning: --as-of 2026-11-20 differs from the as_of date recorded in the facts file "
        "(2026-11-23)\n"
        "warning: --as-of 2026-11-20 is earlier than the date the facts were collected "
        "(2026-11-23 UTC)\n"
    )
    assert main(["assess", "--facts", FACTS_PATH, "--format", "json", "--as-of", "2026-12-01",
                 "--stdout"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ("warning: --as-of 2026-12-01 differs from the as_of date recorded in "
                            "the facts file (2026-11-23)\n")
    provenance = json.loads(captured.out)["provenance"]
    assert (provenance["as_of"], provenance["as_of_source"]) == ("2026-12-01", "cli")


def test_replay_target_defaults_to_the_files_target(study, set_clock, capsys):
    _live_run(set_clock)
    capsys.readouterr()
    assert main(["assess", "--facts", FACTS_PATH, "--format", "json", "--stdout"]) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["target"] == data["provenance"]["target"] == TARGET
    assert "warning" not in captured.err

    assert main(["assess", TARGET, "--facts", FACTS_PATH, "--format", "json", "--stdout"]) == 0
    assert "warning" not in capsys.readouterr().err


def test_replay_with_a_different_target_warns_and_uses_it(study, set_clock, capsys):
    _live_run(set_clock)
    capsys.readouterr()
    assert main(["assess", "H1", "--facts", FACTS_PATH, "--format", "json", "--stdout"]) == 0
    captured = capsys.readouterr()
    assert captured.err.startswith("warning: target 'H1' differs from the target recorded in the "
                                   "facts file ('192.0.2.10')")
    data = json.loads(captured.out)
    assert data["target"] == data["provenance"]["target"] == "H1"


def test_replay_of_windows_facts(tmp_path, monkeypatch, capsys):
    """A replay reads whatever platform the facts were collected from."""
    monkeypatch.chdir(tmp_path)
    envelope = dict(VALID_ENVELOPE, connector="ssh-osquery-windows", facts={
        "os": {"platform": "windows", "name": "Microsoft Windows 11 Enterprise",
               "version": "10.0.26200", "codename": None},
        "system_info": {}, "programs": [{"name": "7-Zip", "version": "23.01", "publisher": "Igor Pavlov"}],
        "services": {"wuauserv": {"status": "RUNNING", "start_type": "DEMAND_START"}},
        "last_update_installed_iso": "2026-11-01T09:00:00", "expired_certificates": [],
        "extra": {"os_version_full": {"ok": True, "data": [{"build": "26200"}]}},
    })
    Path("facts.json").write_text(json.dumps(envelope), encoding="utf-8")
    assert main(["assess", "--facts", "facts.json", "--format", "json", "--stdout"]) == 0
    data = json.loads(capsys.readouterr().out)
    details = {c["check_id"]: c["detail"] for p in data["properties"] for c in p["checks"]}
    assert details["INV-03"] == "1 installed programs enumerated via osquery programs."
    assert details["CUR-01"] == ("Windows Update service active; last successful update installed "
                                 "22 day(s) ago." + LABEL)
    assert data["provenance"]["os"] == {"platform": "windows", "name": "Microsoft Windows 11 Enterprise",
                                        "version": "10.0.26200", "build": "26200"}


# ---------------------------------------------------------------- the risk register in a replay

def test_a_replay_reproduces_a_register_with_missing_data_entries(study, set_clock, capsys):
    """An attestation without business_purpose (CLM-03 not supplied) and with
    an unreadable last_scan (ASM-01 ERROR), plus the config's MON-02
    exclusion: the live and replayed registers are identical, next-level
    hints and SP 800-30 fields included; a CISA ZTMM replay lists the same
    entries in the same order with its own hints."""
    attestation = copy.deepcopy(ATTESTATION)
    del attestation["business_purpose"]
    attestation["vulnerability_scanning"]["last_scan"] = "23/11/2026"
    Path("inputs/attestation.json").write_text(json.dumps(attestation), encoding="utf-8")
    live = _live_run(set_clock)
    set_clock(REPLAY_CLOCK)
    assert main(_replay_args()) == 0
    replay = _load("outputs/H1-cmmi-replay.json")
    assert replay["risk_register"] == live["risk_register"]
    kinds = {e["check_id"]: (e["entry_type"], e["status"]) for e in live["risk_register"]}
    assert kinds["CLM-03"] == ("missing-data", "NOT_APPLICABLE")
    assert kinds["ASM-01"] == ("missing-data", "ERROR")
    assert "MON-02" not in kinds          # excluded by the config: no entry
    entries = live["risk_register"]
    assert [e["entry_type"] for e in entries] == sorted(e["entry_type"] for e in entries)   # findings first
    assert all(e["next_level"]["methodology"] == "cmmi" for e in entries)

    assert main(_replay_args(methodology="cisa-ztmm", out="outputs/H1-cisa-ztmm.json")) == 0
    cisa = _load("outputs/H1-cisa-ztmm.json")["risk_register"]
    assert [e["check_id"] for e in cisa] == [e["check_id"] for e in entries]
    assert all(e["next_level"]["methodology"] == "cisa-ztmm" for e in cisa)
    assert [e["next_level"]["text"] for e in cisa] != [e["next_level"]["text"] for e in entries]
    strip = [{k: v for k, v in e.items() if k != "next_level"} for e in cisa]
    assert strip == [{k: v for k, v in e.items() if k != "next_level"} for e in entries]
