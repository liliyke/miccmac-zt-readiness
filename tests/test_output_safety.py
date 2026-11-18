"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for the assess command's --output safeguards (review findings BI-08,
CC-02, CC-09, RD-02, the two --output items the core-CLI review found
missing, round-1 verifier finding V1-N8 and two round-1 open questions):

- a blank --output, --facts, --save-facts, --attestation, --inventory-record,
  --config or --ssh-key value is an error (list-checks' --config too);
- the --output folder must exist;
- --output is never the same file as an input file, also through a link;
- --output never replaces a saved facts file, in any run, even with
  --overwrite, checked before the run and again just before the write;
- a study run (--connector, --facts, --save-facts or --as-of) never replaces
  an existing file unless --overwrite is given; a plain run still does;
- a run whose report holds study results (--facts, --save-facts, or
  --connector with --as-of) needs -o FILE or --stdout, and --stdout with -o
  is an error; every other run prints as before;
- the report is written whole or not at all, and a failed write is a clean
  error that, after a live run with --save-facts, says how to rebuild it;
- stdout carries only "Report written to <path>", never the report.

Every refusal happens before any connection, before the inputs are read for
scoring and before --save-facts writes anything. The connector is a fake and
nothing connects anywhere. Synthetic values only (IP 192.0.2.10, user
"assessor", key "keys/id_ed25519")."""
from __future__ import annotations

import copy
import datetime as dt
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from miccmac import cli, clock, facts_file
from miccmac.cli import main

TARGET = "192.0.2.10"
SSH = ["--ssh-user", "assessor", "--ssh-key", "keys/id_ed25519"]
SESSION_DATE = "2026-11-23"
FACTS = {
    "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "26.04", "codename": "resolute"},
    "system_info": {"hardware_vendor": "VMware, Inc.", "hardware_model": "", "hardware_serial": ""},
    "deb_packages": [{"name": "bash", "version": "5.2"}],
    "systemd_units": {"apt-daily-upgrade.timer": {"active_state": "active"}},
    "apt_update_stamp_mtime": 1795000000, "apt_sources": [], "expired_certificates": [],
}
ENVELOPE = {
    "facts_format": "miccmac-facts/1", "tool_version": "0.1.0", "tool_commit": None,
    "connector": "ssh-osquery", "target": TARGET, "collected_at_utc": "2026-11-23T19:05:00Z",
    "as_of": SESSION_DATE, "facts": FACTS,
}
ATTESTATION = {"business_owner": {"assigned": True, "name": "Synthetic Owner"}}
INVENTORY_RECORD = {"device_id": "H1", "tracked": True, "last_reviewed": "2026-09-01"}
FACTS_PATH = "outputs/H1-facts.json"
INPUTS = ["--attestation", "inputs/attestation.json", "--inventory-record", "inputs/inventory-record.json",
          "--config", "inputs/config.yaml"]
REFUSAL = ("error: refusing to replace {path}: study runs never overwrite a file; choose a new "
           "file name or pass --overwrite\n")
# Words that would mean a tool result reached the terminal.
RESULT_WORDS = ("PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE", "NOT_IMPLEMENTED", "overall_score",
                "readiness_tier", "level", "risk_register", "Synthetic Owner")
CASE_INSENSITIVE = os.path.normcase("A") == "a"  # Windows


@pytest.fixture
def study(tmp_path, monkeypatch):
    """A study-like folder (inputs/, outputs/ holding a saved facts file) as
    the working directory, and a fake Linux connector in place of the class
    cli.py imports. Returns the list of (target, extended) collect_facts calls."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "inputs").mkdir()
    (tmp_path / "outputs").mkdir()
    (tmp_path / "inputs" / "attestation.json").write_text(json.dumps(ATTESTATION), encoding="utf-8")
    (tmp_path / "inputs" / "inventory-record.json").write_text(json.dumps(INVENTORY_RECORD), encoding="utf-8")
    (tmp_path / "inputs" / "config.yaml").write_text("excluded_checks: []\n", encoding="utf-8")
    (tmp_path / FACTS_PATH).write_text(json.dumps(ENVELOPE, indent=2) + "\n", encoding="utf-8")
    calls = []

    class FakeConnector:
        def __init__(self, ssh_user, ssh_key_path, port=22):
            pass

        def collect_facts(self, target, extended=False):
            calls.append((target, extended))
            return copy.deepcopy(FACTS)

    monkeypatch.setattr("miccmac.connectors.ssh_osquery.SSHOsqueryConnector", FakeConnector)
    return calls


def _snapshot():
    """Every file under the working directory and its bytes."""
    return {str(p): p.read_bytes() for p in Path(".").rglob("*") if p.is_file()}


def _live(out="outputs/H1-cmmi.json", save="outputs/H2-facts.json", *extra):
    return ["assess", TARGET, "--connector", "ssh-osquery", *SSH, *INPUTS, "--methodology", "cmmi",
            "--risk-register", "--format", "json", "-o", out, "--as-of", SESSION_DATE,
            "--save-facts", save, *extra]


def _replay(out, *extra, fmt="json"):
    return ["assess", "--facts", FACTS_PATH, *INPUTS, "--methodology", "cisa-ztmm", "--risk-register",
            "--format", fmt, "-o", out, "--as-of", SESSION_DATE, *extra]


def _assert_refused(captured, message_start):
    assert captured.err.startswith("error: " + message_start), captured.err
    assert captured.out == ""  # nothing at all on stdout, least of all the report
    for word in RESULT_WORDS:
        assert word not in captured.err


class _FailingFile:
    """Stands in for the report's temporary file: writing fails, as on a full disk."""

    def __init__(self, fh):
        self._fh = fh

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._fh.close()
        return False

    def write(self, text):
        raise OSError(28, "No space left on device")

    def flush(self):
        self._fh.flush()

    def fileno(self):
        return self._fh.fileno()


def _failing_report_file(monkeypatch):
    """Make only the report's write fail (the facts file is written by
    facts_file.save_envelope, which this leaves alone)."""
    real = cli._create_temporary_file

    def create(folder, name):
        fh, path = real(folder, name)
        return _FailingFile(fh), path

    monkeypatch.setattr(cli, "_create_temporary_file", create)


# ---------------------------------------------------------------- a. blank file names

@pytest.mark.parametrize("args, flag", [
    (["assess", "test-device", "--format", "json", "-o", ""], "--output"),
    (["assess", "test-device", "--format", "json", "--output", "   "], "--output"),
    (_replay(""), "--output"),
    (_live(out=""), "--output"),
    (["assess", "--facts", "", "--format", "json", "--as-of", SESSION_DATE], "--facts"),
    (["assess", TARGET, "--facts", "", "--connector", "ssh-osquery", *SSH], "--facts"),
    (_live(save=""), "--save-facts"),
    (["assess", TARGET, "--save-facts", " ", "--format", "json", "-o", "outputs/x.json"], "--save-facts"),
    # The input files and the key (a round-1 open question): a blank value
    # was dropped, so the 10 input-driven checks ran without the input.
    (["assess", "test-device", "--format", "json", "--attestation", ""], "--attestation"),
    (["assess", "--facts", FACTS_PATH, "--attestation", "  ", "--format", "json", "-o", "outputs/x.json",
      "--as-of", SESSION_DATE], "--attestation"),
    (["assess", "test-device", "--format", "json", "--inventory-record", ""], "--inventory-record"),
    (["assess", TARGET, "--connector", "ssh-osquery", *SSH, "--inventory-record", "\t", "--format", "json",
      "-o", "outputs/H2-cmmi.json", "--as-of", SESSION_DATE, "--save-facts", "outputs/H2-facts.json"],
     "--inventory-record"),
    (["assess", "test-device", "--format", "json", "--config", ""], "--config"),
    (_replay("outputs/x.json") + ["--config", " "], "--config"),
    (["assess", TARGET, "--connector", "ssh-osquery", "--ssh-user", "assessor", "--ssh-key", "",
      "--format", "json"], "--ssh-key"),
    (["assess", TARGET, "--connector", "ssh-osquery", "--ssh-user", "assessor", "--ssh-key", "  ",
      "--format", "json", "-o", "outputs/H2-cmmi.json", "--as-of", SESSION_DATE], "--ssh-key"),
    (["assess", "test-device", "--format", "json", "--ssh-key", ""], "--ssh-key"),
])
def test_a_blank_file_name_is_an_error(args, flag, study, capsys):
    """An unset shell variable passes "": the report must not go to stdout,
    a replay must not turn into a stub or live run, a save must not vanish,
    and an input file must not silently drop out of the run."""
    before = _snapshot()
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.err == f"error: {flag} needs a file name\n"
    assert captured.out == ""
    assert study == []  # no connection
    assert _snapshot() == before  # nothing written


@pytest.mark.parametrize("value", ["", "   "])
def test_list_checks_refuses_a_blank_config(value, capsys):
    """The enabled-check export (the fairness control) with an unset
    variable for its --config: a clear error, not a puzzling one."""
    assert main(["list-checks", "--config", value, "--format", "json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == "error: --config needs a file name\n"
    assert captured.out == ""


def test_a_blank_attestation_was_dropped_before_and_is_refused_now(study, capsys):
    """The round-1 open question, end to end: the replay with the input files
    as given, and the same replay with --attestation "" (an unset shell
    variable), which used to score the attestation-driven checks without it."""
    assert main(_replay("outputs/with-inputs.json")) == 0
    capsys.readouterr()
    attestation = INPUTS.index("--attestation") + 1
    blank = ["assess", "--facts", FACTS_PATH, *INPUTS[:attestation], "", *INPUTS[attestation + 1:],
             "--methodology", "cisa-ztmm", "--risk-register", "--format", "json", "-o",
             "outputs/without.json", "--as-of", SESSION_DATE]
    assert main(blank) == 2
    captured = capsys.readouterr()
    assert (captured.err, captured.out) == ("error: --attestation needs a file name\n", "")
    assert not Path("outputs/without.json").exists()


# ---------------------------------------------------------------- b. the --output folder

@pytest.mark.parametrize("args", [
    ["assess", "test-device", "--format", "json", "-o", "ouputs/H1-cmmi.json"],
    _replay("ouputs/H1-cisa-ztmm.json"),
    _live(out="ouputs/H1-cmmi.json"),
])
def test_a_missing_output_folder_is_refused_before_anything_happens(args, study, capsys):
    before = _snapshot()
    assert main(args) == 2
    _assert_refused(capsys.readouterr(), "--output folder does not exist: ouputs")
    assert study == []  # the live run never connected ...
    assert _snapshot() == before  # ... and saved no facts
    assert not Path("ouputs").exists()


def test_an_output_naming_a_folder_is_refused(study, capsys):
    assert main(["assess", "test-device", "--format", "json", "-o", "outputs"]) == 2
    _assert_refused(capsys.readouterr(), "--output names a folder, not a file: outputs")


# ---------------------------------------------------------------- c. never an input file

@pytest.mark.parametrize("flag, path", [
    ("--attestation", "inputs/attestation.json"),
    ("--inventory-record", "inputs/inventory-record.json"),
    ("--config", "inputs/config.yaml"),
])
@pytest.mark.parametrize("spelling", ["as given", "with ./ and ..", "in upper case"])
@pytest.mark.parametrize("overwrite", [[], ["--overwrite"]])
def test_output_is_never_an_input_file(flag, path, spelling, overwrite, study, capsys):
    if spelling == "with ./ and ..":
        output = "./inputs/../" + path
    elif spelling == "in upper case" and CASE_INSENSITIVE:
        output = path.upper()
    else:
        output = path
    before = _snapshot()
    # A plain run, which may replace other existing files, still may not replace an input.
    args = ["assess", "test-device", "--format", "json", *INPUTS, "-o", output, *overwrite]
    assert main(args) == 2
    _assert_refused(capsys.readouterr(), f"--output and {flag} name the same file ({output}); "
                                         f"the report would overwrite that input file")
    assert _snapshot() == before


def _hard_link_or_skip(source, link):
    try:
        os.link(source, link)
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"hard links are not available here: {exc}")


@pytest.mark.parametrize("mode", [[], ["--as-of", SESSION_DATE, "--overwrite"]])
def test_output_through_a_hard_link_to_an_input_is_refused(mode, study, capsys):
    _hard_link_or_skip("inputs/attestation.json", "outputs/report.json")
    assert os.path.samefile("inputs/attestation.json", "outputs/report.json")
    before = _snapshot()
    assert main(["assess", "test-device", "--format", "json", "--attestation", "inputs/attestation.json",
                 "-o", "outputs/report.json", *mode]) == 2
    _assert_refused(capsys.readouterr(), "--output and --attestation name the same file "
                                         "(outputs/report.json); the report would overwrite that input file")
    assert _snapshot() == before
    assert json.loads(Path("inputs/attestation.json").read_text(encoding="utf-8")) == ATTESTATION


def test_output_through_a_hard_link_to_the_replayed_facts_is_refused(study, capsys):
    """The review's reproduction: -o on a hard link silently rewrote H1's facts."""
    _hard_link_or_skip(FACTS_PATH, "hl.json")
    before = _snapshot()
    assert main(_replay("hl.json", "--overwrite")) == 2
    _assert_refused(capsys.readouterr(), "--output and --facts name the same file (hl.json); "
                                         "the report would overwrite the saved facts")
    assert _snapshot() == before


def test_output_through_a_symbolic_link_to_an_input_is_refused(study, capsys):
    try:
        os.symlink(os.path.abspath("inputs/inventory-record.json"), "outputs/link.json")
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are not available here: {exc}")
    before = _snapshot()
    assert main(["assess", "test-device", "--format", "json", "--inventory-record",
                 "inputs/inventory-record.json", "-o", "outputs/link.json"]) == 2
    _assert_refused(capsys.readouterr(), "--output and --inventory-record name the same file")
    assert _snapshot() == before


def test_the_spelling_guard_against_save_facts_is_kept(study, capsys):
    """--save-facts names a file that does not exist yet, so only the path
    spelling can be compared."""
    output = "OUTPUTS/../outputs/H2-FACTS.json" if CASE_INSENSITIVE else "outputs/../outputs/H2-facts.json"
    assert main(_live(output)) == 2
    _assert_refused(capsys.readouterr(), "--output and --save-facts name the same file")
    assert study == []


# ---------------------------------------------------------------- d. existing files and --overwrite

@pytest.mark.parametrize("args", [
    _replay("outputs/H1-cmmi.json"),                                                     # --facts
    ["assess", "test-device", "--format", "json", "-o", "outputs/H1-cmmi.json",
     "--as-of", SESSION_DATE],                                                           # --as-of only
    ["assess", TARGET, "--connector", "ssh-osquery", *SSH, "--format", "json",
     "-o", "outputs/H1-cmmi.json"],                                                      # --connector only
    _live("outputs/H1-cmmi.json"),                                                       # --save-facts
])
def test_a_study_run_never_replaces_an_existing_file(args, study, capsys):
    """A repeated step 5 or 6, or a re-test aimed at the baseline file, is
    refused before anything happens: no connection, no facts saved."""
    Path("outputs/H1-cmmi.json").write_text("sealed baseline output\n", encoding="utf-8")
    before = _snapshot()
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.err == REFUSAL.format(path="outputs/H1-cmmi.json")
    assert captured.out == ""
    assert study == []
    assert _snapshot() == before


def test_overwrite_lets_a_study_run_replace_its_output(study, capsys):
    Path("outputs/H1-cisa-ztmm.json").write_text("earlier output\n", encoding="utf-8")
    assert main(_replay("outputs/H1-cisa-ztmm.json", "--overwrite")) == 0
    assert capsys.readouterr().out == "Report written to outputs/H1-cisa-ztmm.json\n"
    data = json.loads(Path("outputs/H1-cisa-ztmm.json").read_text(encoding="utf-8"))
    assert data["assessment"]["methodology"]["name"] == "cisa-ztmm"
    assert sorted(p.name for p in Path("outputs").iterdir()) == ["H1-cisa-ztmm.json", "H1-facts.json"]


def test_overwrite_never_replaces_saved_facts(study, capsys):
    Path("outputs/H2-facts.json").write_text("earlier raw data\n", encoding="utf-8")
    assert main(_live("outputs/H2-cmmi.json", "outputs/H2-facts.json", "--overwrite")) == 2
    assert capsys.readouterr().err.startswith("error: --save-facts file already exists: outputs/H2-facts.json")
    assert study == []
    assert Path("outputs/H2-facts.json").read_text(encoding="utf-8") == "earlier raw data\n"


def test_a_plain_run_still_replaces_an_existing_file(study, capsys):
    """Backward compatible: without any study option, -o replaces a file as before."""
    Path("report.json").write_text("old report\n", encoding="utf-8")
    assert main(["assess", "test-device", "--format", "json", "-o", "report.json"]) == 0
    assert capsys.readouterr().out == "Report written to report.json\n"
    assert json.loads(Path("report.json").read_text(encoding="utf-8"))["target"] == "test-device"


def test_help_documents_overwrite(capsys):
    with pytest.raises(SystemExit):
        main(["assess", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--overwrite" in help_text
    assert "Let a study run replace an existing --output file." in help_text
    assert "refuses an existing file unless --overwrite is given" in help_text


# ---------------------------------------------------------------- e. the write itself

def test_the_report_file_has_the_same_bytes_as_before(study, capsys):
    """Text mode, as the old open(path, "w") wrote it: UTF-8 with the
    platform's newlines (CRLF on Windows), and nothing left behind."""
    assert main(["assess", "test-device", "--format", "json", "--methodology", "cmmi"]) == 0
    printed = capsys.readouterr().out
    assert main(["assess", "test-device", "--format", "json", "--methodology", "cmmi", "-o", "r.json"]) == 0
    assert capsys.readouterr().out == "Report written to r.json\n"
    assert Path("r.json").read_bytes() == printed.replace("\n", os.linesep).encode("utf-8")
    assert sorted(p.name for p in Path(".").iterdir()) == ["inputs", "outputs", "r.json"]


@pytest.mark.parametrize("step, reason", [
    ("write", "No space left on device"),
    ("fsync", "Input/output error"),
    ("replace", "Permission denied"),  # e.g. the file is open in another program
])
def test_a_failed_write_is_a_clean_error_and_leaves_no_trace(step, reason, study, capsys, monkeypatch):
    Path("report.json").write_text("old report\n", encoding="utf-8")
    before = _snapshot()
    with monkeypatch.context() as m:
        if step == "write":
            _failing_report_file(m)
        else:
            errno = 5 if step == "fsync" else 13

            def fail(*args, **kwargs):
                raise OSError(errno, reason)
            m.setattr(cli.os, step, fail)
        assert main(["assess", "test-device", "--format", "json", "-o", "report.json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == f"error: cannot write --output report.json: {reason}\n"
    assert captured.out == ""
    assert _snapshot() == before  # the old file is intact and no temporary file is left


DEVICE = "NUL" if os.name == "nt" else "/dev/null"


@pytest.mark.parametrize("extra", [[], ["--as-of", SESSION_DATE, "--overwrite"]])
def test_a_device_is_written_to_never_replaced(extra, study, capsys):
    """-o /dev/null (or NUL) keeps working as before. A temporary file renamed
    over it would replace the device itself, for example as root."""
    before = _snapshot()
    assert main(["assess", "test-device", "--format", "json", "-o", DEVICE, *extra]) == 0
    assert capsys.readouterr().out == f"Report written to {DEVICE}\n"
    assert _snapshot() == before  # no temporary file next to it, nothing else written
    if os.name != "nt":
        assert stat.S_ISCHR(os.stat(DEVICE).st_mode)


def test_a_study_run_refuses_a_device_without_overwrite(study, capsys):
    assert main(["assess", "test-device", "--format", "json", "-o", DEVICE, "--as-of", SESSION_DATE]) == 2
    assert capsys.readouterr().err == REFUSAL.format(path=DEVICE)


def test_output_through_a_symbolic_link_writes_the_link_target(study, capsys):
    """As the old direct write did: the link stays, its target gets the report."""
    Path("outputs/real.json").write_text("old report\n", encoding="utf-8")
    try:
        os.symlink(os.path.abspath("outputs/real.json"), "outputs/link.json")
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are not available here: {exc}")
    assert main(["assess", "test-device", "--format", "json", "-o", "outputs/link.json"]) == 0
    assert capsys.readouterr().out == "Report written to outputs/link.json\n"
    assert os.path.islink("outputs/link.json")
    assert json.loads(Path("outputs/real.json").read_text(encoding="utf-8"))["target"] == "test-device"
    assert sorted(p.name for p in Path("outputs").iterdir()) == ["H1-facts.json", "link.json", "real.json"]


def test_write_report_writes_a_link_target_on_any_platform(tmp_path, monkeypatch):
    """The same link handling where symbolic links cannot be made (Windows
    without the privilege): the link is simulated."""
    real, link = tmp_path / "real.json", tmp_path / "link.json"
    real.write_text("old report\n", encoding="utf-8")
    link.write_text("stands in for the link itself\n", encoding="utf-8")
    monkeypatch.setattr(cli.os.path, "islink", lambda p: os.fspath(p) == str(link))
    monkeypatch.setattr(cli.os.path, "realpath", lambda p: str(real))
    cli._write_report(str(link), "new report\n", replace=True)
    monkeypatch.undo()
    assert real.read_text(encoding="utf-8") == "new report\n"
    assert link.read_text(encoding="utf-8") == "stands in for the link itself\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["link.json", "real.json"]


def test_an_interrupted_write_removes_its_temporary_file(study, monkeypatch):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    before = _snapshot()
    with monkeypatch.context() as m:
        m.setattr(cli.os, "replace", interrupt)
        with pytest.raises(KeyboardInterrupt):
            main(_replay("outputs/new.json"))
    assert _snapshot() == before


def test_a_failed_write_after_a_live_run_says_how_to_rebuild_the_report(study, capsys, monkeypatch):
    """The facts were saved before the checks ran; the error says so, prints
    no result, and the report can be rebuilt from them with --facts."""
    with monkeypatch.context() as m:
        _failing_report_file(m)
        assert main(_live("outputs/H2-cmmi.json", "outputs/H2-facts.json")) == 2
    captured = capsys.readouterr()
    assert captured.err == ("error: cannot write --output outputs/H2-cmmi.json: No space left on device; "
                            "the facts were saved to outputs/H2-facts.json, so the report can be rebuilt "
                            "from them with --facts outputs/H2-facts.json (no new collection needed)\n")
    assert captured.out == ""
    assert study == [(TARGET, True)]
    assert sorted(p.name for p in Path("outputs").iterdir()) == ["H1-facts.json", "H2-facts.json"]

    rebuild = ["assess", "--facts", "outputs/H2-facts.json", *INPUTS, "--methodology", "cmmi",
               "--risk-register", "--format", "json", "-o", "outputs/H2-cmmi.json", "--as-of", SESSION_DATE]
    assert main(rebuild) == 0
    assert capsys.readouterr().out == "Report written to outputs/H2-cmmi.json\n"
    assert study == [(TARGET, True)]  # rebuilt without a second collection


def test_a_file_that_appears_during_a_study_run_is_not_replaced(study, capsys, monkeypatch):
    real_run = cli.run_assessment

    def run_and_race(*args, **kwargs):
        Path("outputs/raced.json").write_text("written by someone else\n", encoding="utf-8")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(cli, "run_assessment", run_and_race)
    assert main(_replay("outputs/raced.json")) == 2
    captured = capsys.readouterr()
    assert captured.err == REFUSAL.format(path="outputs/raced.json")
    assert captured.out == ""
    assert Path("outputs/raced.json").read_text(encoding="utf-8") == "written by someone else\n"
    assert sorted(p.name for p in Path("outputs").iterdir()) == ["H1-facts.json", "raced.json"]


# ---------------------------------------------------------------- f. stdout

@pytest.mark.parametrize("fmt", ["json", "text", "markdown"])
def test_stdout_is_only_the_report_written_line(fmt, study, capsys):
    out = f"outputs/H1-cisa-ztmm-{fmt}.out"
    assert main(_replay(out, fmt=fmt)) == 0
    captured = capsys.readouterr()
    assert captured.out == f"Report written to {out}\n"
    assert captured.err == ""
    assert Path(out).stat().st_size > 0


# ---------------------------------------------------------------- g. where the report goes (V1-N8)

NO_DESTINATION = ("error: this run's report holds results, so it goes to a file: give -o FILE, "
                  "or --stdout to print it here\n")
STDOUT_AND_OUTPUT = ("error: --stdout cannot be combined with --output: the report goes either to "
                     "a file or to the terminal, not both\n")
FIXED_CLOCK = dt.datetime(2026, 11, 23, 19, 30, tzinfo=dt.timezone.utc)


@pytest.fixture
def fixed_clock(monkeypatch):
    """The real clock miccmac sees, fixed, so two runs give the same bytes."""
    monkeypatch.setattr(clock, "_now_utc", lambda: FIXED_CLOCK)
    monkeypatch.setattr(clock, "_today", lambda: FIXED_CLOCK.date())


def _without_output(args):
    """args with its "-o FILE" taken out: a step-5 or step-6 line cut or
    wrapped when pasted."""
    i = args.index("-o")
    return args[:i] + args[i + 2:]


# The runs whose report holds study results, each without -o.
STUDY_RESULT_RUNS = {
    "replay (step 6)": _without_output(_replay("unused.json")),
    "replay, markdown (Thursday's --as-of demonstration)": [
        "assess", "--facts", FACTS_PATH, *INPUTS, "--as-of", SESSION_DATE, "--format", "markdown"],
    "replay, no other option": ["assess", "--facts", FACTS_PATH],
    "live run with --save-facts (step 5)": _without_output(_live()),
    "live run with --as-of, no --save-facts": [
        "assess", TARGET, "--connector", "ssh-osquery", *SSH, *INPUTS, "--methodology", "cmmi",
        "--risk-register", "--format", "json", "--as-of", SESSION_DATE],
}


def _must_not_run(name):
    def fail(*args, **kwargs):
        raise AssertionError(f"{name} ran although the run is refused")
    return fail


@pytest.mark.parametrize("name", sorted(STUDY_RESULT_RUNS))
def test_a_study_result_run_without_output_is_refused_before_anything_happens(name, study, capsys,
                                                                              monkeypatch):
    """V1-N8: such a run with no -o printed the whole report (statuses and
    register entries) to the terminal, before the later hosts' blind passes.
    Now it stops first: no connection, no input or facts read, no facts
    saved, nothing on stdout."""
    for helper in ("_load_config", "_load_inputs", "_load_replay", "_collect_live"):
        monkeypatch.setattr(cli, helper, _must_not_run(helper))
    before = _snapshot()
    assert main(STUDY_RESULT_RUNS[name]) == 2
    captured = capsys.readouterr()
    assert captured.err == NO_DESTINATION
    assert captured.out == ""
    assert study == []
    assert _snapshot() == before


@pytest.mark.parametrize("name", sorted(STUDY_RESULT_RUNS))
def test_stdout_prints_a_study_result_run_on_request(name, study, capsys):
    """--stdout prints it on purpose, as Thursday's demonstration on
    synthetic data does; stdout is then the report alone."""
    args = STUDY_RESULT_RUNS[name] + ["--stdout"]
    assert main(args) == 0
    out = capsys.readouterr().out
    if "json" in args:
        report = json.loads(out)["assessment"]
        assert report["provenance"]["target"] == TARGET
        assert set(report["provenance"]) >= {"run_at_utc", "facts_source", "inputs"}
    else:  # the text banner, or the markdown title
        assert "MICCMAC ZERO TRUST DEVICE READINESS ASSESSMENT" in out.upper()
    assert "Report written to" not in out
    if "--save-facts" in args:
        assert study == [(TARGET, True)]
        assert json.loads(Path("outputs/H2-facts.json").read_text(encoding="utf-8"))["facts"]["os"]
    elif "--connector" in args:
        assert study == [(TARGET, False)]
    else:
        assert study == []


@pytest.mark.parametrize("fmt", ["json", "markdown"])
def test_stdout_prints_exactly_what_output_would_write(fmt, study, fixed_clock, capsys):
    assert main(_replay("outputs/H1-cisa-ztmm.out", fmt=fmt)) == 0
    capsys.readouterr()
    assert main(_without_output(_replay("unused", fmt=fmt)) + ["--stdout"]) == 0
    captured = capsys.readouterr()
    assert captured.out == Path("outputs/H1-cisa-ztmm.out").read_text(encoding="utf-8")
    assert captured.err == ""


@pytest.mark.parametrize("args", [
    _replay("outputs/H1-cisa-ztmm.json", "--stdout"),
    _live("outputs/H2-cmmi.json", "outputs/H2-facts.json", "--stdout"),
    ["assess", "test-device", "--format", "json", "--stdout", "-o", "outputs/report.json"],
])
def test_stdout_with_output_is_an_error(args, study, capsys):
    before = _snapshot()
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.err == STDOUT_AND_OUTPUT
    assert captured.out == ""
    assert study == []
    assert _snapshot() == before


@pytest.mark.parametrize("args, connects", [
    (["assess", "test-device"], False),                                                  # plain run
    (["assess", "test-device", "--format", "json", "--methodology", "cmmi", "--risk-register",
      *INPUTS], False),                                                                  # plain, with inputs
    (["assess", "test-device", "--format", "markdown", "--as-of", SESSION_DATE], False),  # --as-of alone
    (["assess", "test-device", "--format", "json", *INPUTS, "--as-of", SESSION_DATE], False),
    (["assess", TARGET, "--connector", "ssh-osquery", *SSH, *INPUTS, "--methodology", "cmmi",
      "--risk-register", "--format", "json"], True),                                     # --connector, no --as-of
])
def test_every_other_run_prints_as_before(args, connects, study, fixed_clock, capsys):
    """A plain run, --as-of alone and --connector without --as-of print as
    they always did, and exactly what -o would write; --stdout changes
    nothing for them."""
    assert main(args) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() and "Report written to" not in captured.out
    printed = captured.out
    assert main(args + ["--stdout"]) == 0
    assert capsys.readouterr().out == printed
    assert main(args + ["-o", "outputs/report.out"]) == 0
    assert capsys.readouterr().out == "Report written to outputs/report.out\n"
    assert Path("outputs/report.out").read_text(encoding="utf-8") == printed
    assert study == ([(TARGET, False)] * 3 if connects else [])


def test_help_documents_stdout(capsys):
    with pytest.raises(SystemExit):
        main(["assess", "--help"])
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--stdout" in help_text
    assert "Print the report on stdout." in help_text
    assert ("A run with --facts or --save-facts, or with --connector and --as-of, needs --output or "
            "--stdout.") in help_text
    assert "Not allowed with --output." in help_text


# ---------------------------------------------------------------- h. never over a saved facts file

FACTS_REFUSAL = ("error: refusing to replace {path}: it is a saved facts file (miccmac-facts/1), which "
                 "a report must never replace")


def _save_real_facts(path):
    """A facts file exactly as --save-facts writes it, through
    facts_file.save_envelope; returns its bytes."""
    envelope = facts_file.build_envelope(
        copy.deepcopy(FACTS), tool_version="0.1.0", tool_commit=None, connector="ssh-osquery",
        target=TARGET, collected_at_utc="2026-11-23T19:05:00Z", as_of=dt.date(2026, 11, 23))
    facts_file.save_envelope(path, envelope)
    data = Path(path).read_bytes()
    assert data == facts_file.encode_envelope(envelope)
    return data


@pytest.mark.parametrize("args", [
    ["assess", "test-device", "--format", "json", "-o", "outputs/H2-facts.json"],      # a plain run
    _replay("outputs/H2-facts.json"),                                                 # a study run
    _replay("outputs/H2-facts.json", "--overwrite"),                                  # even with --overwrite
    _live("outputs/H2-facts.json", "outputs/H3-facts.json", "--overwrite"),           # before connecting
    ["assess", TARGET, "--connector", "ssh-osquery", *SSH, "--format", "json",
     "-o", "outputs/H2-facts.json", "--overwrite"],                                   # --connector only
])
def test_output_never_replaces_a_saved_facts_file(args, study, capsys):
    """A round-1 open question: with --overwrite, -o could replace another
    host's saved facts (raw study data). Now no run can, and the refusal
    comes before the run (no connection, no facts saved), ahead of the
    "pass --overwrite" advice."""
    saved = _save_real_facts("outputs/H2-facts.json")
    before = _snapshot()
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.err == FACTS_REFUSAL.format(path="outputs/H2-facts.json") + "\n"
    assert captured.out == ""
    assert study == []
    assert _snapshot() == before
    assert Path("outputs/H2-facts.json").read_bytes() == saved


def test_a_hard_link_to_a_saved_facts_file_is_refused(study, capsys):
    saved = _save_real_facts("outputs/H2-facts.json")
    _hard_link_or_skip("outputs/H2-facts.json", "report.json")
    assert main(["assess", "test-device", "--format", "json", "-o", "report.json"]) == 2
    assert capsys.readouterr().err == FACTS_REFUSAL.format(path="report.json") + "\n"
    assert Path("outputs/H2-facts.json").read_bytes() == saved


def test_a_symbolic_link_to_a_saved_facts_file_is_refused(study, capsys):
    saved = _save_real_facts("outputs/H2-facts.json")
    try:
        os.symlink(os.path.abspath("outputs/H2-facts.json"), "outputs/link.json")
    except (AttributeError, NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links are not available here: {exc}")
    assert main(_replay("outputs/link.json", "--overwrite")) == 2
    assert capsys.readouterr().err == FACTS_REFUSAL.format(path="outputs/link.json") + "\n"
    assert Path("outputs/H2-facts.json").read_bytes() == saved
    assert os.path.islink("outputs/link.json")


@pytest.mark.parametrize("args, hint", [
    (["assess", "test-device", "--format", "json", "-o", "outputs/raced.json"], ""),   # a plain run
    (_replay("outputs/raced.json", "--overwrite"), ""),
    (_live("outputs/raced.json", "outputs/H2-facts.json", "--overwrite"),
     "; the facts were saved to outputs/H2-facts.json, so the report can be rebuilt from them with "
     "--facts outputs/H2-facts.json (no new collection needed)"),
])
def test_a_facts_file_that_appears_during_the_run_is_not_replaced(args, hint, study, capsys, monkeypatch):
    """The check is made again just before the report replaces the file."""
    real_run = cli.run_assessment
    saved = []

    def run_and_race(*run_args, **kwargs):
        saved.append(_save_real_facts("outputs/raced.json"))
        return real_run(*run_args, **kwargs)

    monkeypatch.setattr(cli, "run_assessment", run_and_race)
    assert main(args) == 2
    captured = capsys.readouterr()
    assert captured.err == FACTS_REFUSAL.format(path="outputs/raced.json") + hint + "\n"
    assert captured.out == ""
    assert Path("outputs/raced.json").read_bytes() == saved[0]
    assert not [p for p in Path("outputs").iterdir() if p.name.endswith(".tmp")]


def test_a_report_is_still_replaced_with_overwrite(study, capsys):
    """A real JSON report (with its provenance block) is not a facts file."""
    assert main(_replay("outputs/H1-cisa-ztmm.json")) == 0
    assert main(_replay("outputs/H1-cisa-ztmm.json", "--overwrite")) == 0
    assert capsys.readouterr().out == "Report written to outputs/H1-cisa-ztmm.json\n" * 2
    assert main(["assess", "test-device", "--format", "json", "-o", "outputs/H1-cisa-ztmm.json"]) == 0


SNIFF = 64 * 1024
MARKED = b'{"facts_format": "miccmac-facts/1"}'
MARK_END = MARKED.index(b"miccmac-facts/1") + len(b"miccmac-facts/1")


@pytest.mark.parametrize("content, refused", [
    pytest.param(MARKED, True, id="both marks"),
    pytest.param(b'{\n  "facts_format": "miccmac-facts/1",\n  "tool_version": "0.1.0"', True,
                 id="cut short"),
    pytest.param(b'{"facts_format": "miccmac-facts/2"}', False, id="another format"),
    pytest.param(b'{"note": "miccmac-facts/1"}', False, id="the format string alone"),
    pytest.param(b'{"facts_format": null}', False, id="the key alone"),
    pytest.param(b'{"facts_format_note": "miccmac-facts/1"}', False, id="not the key itself"),
    pytest.param(b" " * (SNIFF - MARK_END) + MARKED, True, id="ends on the last byte read"),
    pytest.param(b" " * (SNIFF - MARK_END + 1) + MARKED, False, id="one byte beyond"),
])
def test_a_facts_file_is_one_whose_first_64_kib_hold_both_marks(content, refused, study, capsys):
    Path("outputs/existing.json").write_bytes(content)
    code = main(["assess", "test-device", "--format", "json", "-o", "outputs/existing.json"])
    captured = capsys.readouterr()
    if refused:
        assert code == 2
        assert captured.err == FACTS_REFUSAL.format(path="outputs/existing.json") + "\n"
        assert Path("outputs/existing.json").read_bytes() == content
    else:
        assert code == 0 and captured.out == "Report written to outputs/existing.json\n"
        assert json.loads(Path("outputs/existing.json").read_text(encoding="utf-8"))["target"] == "test-device"


def test_an_unreadable_existing_file_is_not_replaced(study, capsys, monkeypatch):
    """A file that cannot be read cannot be cleared of being saved facts,
    and an atomic rename could replace it all the same."""
    Path("outputs/unreadable.json").write_text("{}\n", encoding="utf-8")
    real_open = open

    def guarded_open(file, mode="r", *args, **kwargs):
        if mode == "rb" and os.path.basename(os.fspath(file)) == "unreadable.json":
            raise PermissionError(13, "Permission denied")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(cli, "open", guarded_open, raising=False)  # shadows the builtin in cli only
    assert main(["assess", "test-device", "--format", "json", "-o", "outputs/unreadable.json"]) == 2
    captured = capsys.readouterr()
    assert captured.err == ("error: refusing to replace outputs/unreadable.json: it cannot be read to check "
                            "that it is not a saved facts file (Permission denied)\n")
    assert captured.out == ""
    assert Path("outputs/unreadable.json").read_text(encoding="utf-8") == "{}\n"


@pytest.mark.skipif(os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="needs POSIX file modes and a user other than root")
def test_a_file_with_no_read_permission_is_not_replaced(study, capsys):
    saved = _save_real_facts("outputs/H2-facts.json")
    os.chmod("outputs/H2-facts.json", 0)
    try:
        assert main(["assess", "test-device", "--format", "json", "-o", "outputs/H2-facts.json"]) == 2
        assert capsys.readouterr().err.startswith(
            "error: refusing to replace outputs/H2-facts.json: it cannot be read to check")
    finally:
        os.chmod("outputs/H2-facts.json", stat.S_IRUSR | stat.S_IWUSR)
    assert Path("outputs/H2-facts.json").read_bytes() == saved


def test_a_device_is_never_read_as_a_facts_file(study, capsys):
    """-o NUL or /dev/null is written to as before and never opened for
    reading (a pipe opened for reading could block the run)."""
    assert main(["assess", "test-device", "--format", "json", "-o", DEVICE]) == 0
    assert capsys.readouterr().out == f"Report written to {DEVICE}\n"
    assert cli._saved_facts_refusal(DEVICE, DEVICE) is None
    if hasattr(os, "mkfifo") and sys.platform != "win32":
        os.mkfifo("outputs/pipe")
        assert cli._saved_facts_refusal("outputs/pipe", "outputs/pipe") is None  # returns, no block
