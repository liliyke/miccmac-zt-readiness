"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for miccmac_study.ledger: record (with its archive copies and, for
worksheets, the pre-hash lint) / verify (OK, CHANGED, MISSING, SUPERSEDED,
OUT OF ORDER) / status / withdraw through the command dispatcher, the seal
(seal_status) and the library functions other instruments use. All files are
synthetic and live under tmp_path. Most tests use tiny stub worksheets: the
library function record_files never lints, and the command line is given
real generated worksheets (or --force) where it records a worksheet."""
from __future__ import annotations

import codecs
import csv
import json
import shutil
from pathlib import Path

import pytest

from miccmac.engine import enabled_check_ids
from miccmac_study import ledger
from miccmac_study import worksheet as worksheet_module
from miccmac_study.__main__ import main
from miccmac_study.formats import (
    LEDGER_COLUMNS,
    OUTPUTS_DIR,
    WORKSHEET_COLUMNS,
    StudyError,
    config_template,
    ledger_relpath,
    read_csv,
    read_ledger,
    sha256_file,
    write_csv,
)


def _study(tmp_path):
    """A study folder with two worksheets and one tool output."""
    study = tmp_path / "study"
    (study / "worksheets").mkdir(parents=True)
    (study / "outputs").mkdir()
    (study / "worksheets" / "H1-worksheet.csv").write_text("row_type,item\nmeta,host_code\n", encoding="utf-8")
    (study / "worksheets" / "H2-worksheet.csv").write_text("row_type,item\nmeta,host_code\n", encoding="utf-8")
    (study / "outputs" / "H1-cmmi.json").write_text('{"synthetic": true}\n', encoding="utf-8")
    return study


def _lines(capsys):
    return capsys.readouterr().out.splitlines()


def _archive(study, path):
    """Where `record` keeps the copy of `path` as it is now."""
    return study / "ledger-archive" / f"{sha256_file(path)}{path.suffix}"


def _write_ledger(ledger_file, rows):
    """A ledger written by hand: rows of (recorded_at_utc, host, kind, file or path text, note).
    A file gets its current hash and a path relative to the ledger."""
    with open(ledger_file, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(LEDGER_COLUMNS)
        for when, host, kind, target, note in rows:
            if isinstance(target, str):
                writer.writerow([when, host, kind, target, "0" * 64, "1", note])
            else:
                writer.writerow([when, host, kind, ledger_relpath(ledger_file, target), sha256_file(target),
                                 str(target.stat().st_size), note])


def _states(ledger_file):
    return [(item.state, item.out_of_order) for item in ledger.row_states(ledger_file)]


def _with_config(tmp_path, hosts=("H1", "H2", "H3")):
    study = _study(tmp_path)
    (study / "study.yaml").write_text(config_template(list(hosts)), encoding="utf-8")
    return study


def _filled_worksheet(study, host="H1", verdict="PASS", level="4", edits=None):
    """A real worksheet from the worksheet command (CMMI level rows), every
    check and level filled in; `edits` maps a check id or a level scope to
    another value. Replaces the stub worksheet of _study."""
    list_checks = study / "list-checks.json"
    list_checks.write_text(json.dumps(enabled_check_ids()), encoding="utf-8")
    sheet = study / "worksheets" / f"{host}-worksheet.csv"
    if sheet.exists():
        sheet.unlink()
    worksheet_module.generate_worksheets(list_checks, [host], study / "worksheets", session_date="2026-11-23")
    rows = read_csv(sheet, WORKSHEET_COLUMNS)
    for row in rows:
        if row["row_type"] == "check":
            row["value"] = (edits or {}).get(row["item"], verdict)
        elif row["row_type"] == "level":
            row["value"] = (edits or {}).get(row["property"], level)
    write_csv(sheet, WORKSHEET_COLUMNS, rows, overwrite=True)
    return sheet


def _record(ledger_file, host, sheet, *extra):
    return main(["ledger", "record", "--ledger", str(ledger_file), "--host", host, "--kind", "worksheet",
                 *extra, str(sheet)])


# ---------- record ----------

def test_record_creates_ledger_with_relative_paths_and_prints_hashes(tmp_path, capsys):
    # Changed with the worksheet lint: the command line now records a real, complete worksheet (it lints clean).
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    worksheet = _filled_worksheet(study, "H1")

    rc = main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1",
               "--kind", "worksheet", "--note", "manual pass done", str(worksheet)])

    assert rc == 0
    digest = sha256_file(worksheet)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines() == [f"{digest}  worksheets/H1-worksheet.csv",
                                         f"archive copy: ledger-archive/{digest}.csv"]
    rows = read_ledger(ledger_file)
    assert len(rows) == 1
    row = rows[0]
    assert (row.host_code, row.kind, row.path, row.sha256, row.bytes, row.note) == (
        "H1", "worksheet", "worksheets/H1-worksheet.csv", digest, worksheet.stat().st_size, "manual pass done")
    assert row.recorded_at_utc.endswith("Z") and len(row.recorded_at_utc) == 20
    header = ledger_file.read_bytes().decode("utf-8-sig").splitlines()[0]
    assert header == ",".join(LEDGER_COLUMNS)


def test_record_appends_rows_without_a_second_bom(tmp_path, capsys):
    # Changed with the worksheet lint: the stub files are no worksheets, so the command line needs --force.
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "worksheet",
                 "--force", str(study / "worksheets" / "H1-worksheet.csv")]) == 0
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H2", "--kind", "worksheet",
                 "--force", str(study / "worksheets" / "H2-worksheet.csv"), str(study / "outputs" / "H1-cmmi.json")]) == 0
    capsys.readouterr()

    data = ledger_file.read_bytes()
    assert data.startswith(codecs.BOM_UTF8)
    assert data.count(codecs.BOM_UTF8) == 1
    rows = read_ledger(ledger_file)
    assert [(r.host_code, r.path) for r in rows] == [
        ("H1", "worksheets/H1-worksheet.csv"),
        ("H2", "worksheets/H2-worksheet.csv"),
        ("H2", "outputs/H1-cmmi.json"),
    ]


def test_record_file_outside_the_ledger_folder_is_absolute(tmp_path, capsys):
    study = _study(tmp_path)
    outside = tmp_path / "elsewhere.json"
    outside.write_text("{}", encoding="utf-8")
    rows = ledger.record_files(study / "ledger.csv", "STUDY", "protocol", [outside])
    assert rows[0].path == str(outside.resolve())
    assert ledger.verify_rows(study / "ledger.csv")[0][1] == ledger.OK
    assert _archive(study, outside).read_bytes() == b"{}"


def test_record_refuses_missing_files_and_writes_nothing(tmp_path, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    rc = main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "worksheet",
               str(study / "worksheets" / "H1-worksheet.csv"), str(study / "worksheets" / "H9-worksheet.csv")])
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "H9-worksheet.csv" in captured.err
    assert not ledger_file.exists()
    assert not (study / "ledger-archive").exists()


def test_record_refuses_bad_host_and_kind(tmp_path, capsys):
    study = _study(tmp_path)
    worksheet = str(study / "worksheets" / "H1-worksheet.csv")
    assert main(["ledger", "record", "--ledger", str(study / "ledger.csv"), "--host", "H 1",
                 "--kind", "worksheet", worksheet]) == 2
    with pytest.raises(SystemExit):
        main(["ledger", "record", "--ledger", str(study / "ledger.csv"), "--host", "H1",
              "--kind", "notes", worksheet])
    with pytest.raises(StudyError):
        ledger.record_files(study / "ledger.csv", "H1", "notes", [worksheet])


def test_ledger_cannot_record_itself(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])
    with pytest.raises(StudyError, match="cannot record itself"):
        ledger.record_files(ledger_file, "STUDY", "other", [ledger_file])


def test_record_appends_cleanly_to_a_ledger_saved_without_final_newline(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    first = ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])[0]
    ledger_file.write_bytes(ledger_file.read_bytes().rstrip(b"\r\n"))
    ledger.record_files(ledger_file, "H2", "worksheet", [study / "worksheets" / "H2-worksheet.csv"])
    rows = read_ledger(ledger_file)
    assert [r.host_code for r in rows] == ["H1", "H2"]
    assert rows[0].sha256 == first.sha256


def test_record_refuses_a_ledger_that_is_not_utf8_before_copying_anything(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger_file.write_bytes(",".join(LEDGER_COLUMNS).encode("ascii") + b"\r\n2026-11-23T10:00:00Z,H1,other,x,ab,1,caf\xe9\r\n")
    with pytest.raises(StudyError, match="not UTF-8"):
        ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])
    assert not (study / "ledger-archive").exists()


def test_record_follows_existing_header_order(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    reordered = ["note"] + [c for c in LEDGER_COLUMNS if c != "note"]
    ledger_file.write_text(",".join(reordered) + "\r\n", encoding="utf-8")
    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"], note="n1")
    row = read_ledger(ledger_file)[0]
    assert (row.host_code, row.kind, row.note) == ("H1", "worksheet", "n1")


# ---------- record: archive copies ----------

def test_record_keeps_a_byte_identical_copy_named_by_its_hash(tmp_path, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    worksheet = study / "worksheets" / "H1-worksheet.csv"
    output = study / "outputs" / "H1-cmmi.json"
    original = worksheet.read_bytes()
    copy = _archive(study, worksheet)
    ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    ledger.record_files(ledger_file, "H1", "tool-output", [output])
    assert copy.read_bytes() == original
    assert _archive(study, output).read_bytes() == output.read_bytes()
    assert ledger.archive_path(ledger_file, read_ledger(ledger_file)[0]) == copy.resolve()

    # Changed by accident: verify flags it, and the copy restores the hashed bytes.
    worksheet.write_text("edited after hashing\n", encoding="utf-8")
    assert [state for _, state in ledger.verify_rows(ledger_file)] == [ledger.CHANGED, ledger.OK]
    shutil.copyfile(str(copy), str(worksheet))
    assert [state for _, state in ledger.verify_rows(ledger_file)] == [ledger.OK, ledger.OK]


def test_record_never_replaces_an_archive_copy(tmp_path, capsys):
    # Changed with the worksheet lint: the command line records a real, complete worksheet.
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    worksheet = _filled_worksheet(study, "H1")
    ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    copy = _archive(study, worksheet)
    before = copy.stat().st_mtime_ns
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "worksheet",
                 str(worksheet)]) == 0
    assert _lines(capsys)[1] == f"archive copy: ledger-archive/{copy.name}"
    assert copy.stat().st_mtime_ns == before
    assert sorted(p.name for p in (study / "ledger-archive").iterdir()) == [copy.name]

    copy.write_text("tampered\n", encoding="utf-8")
    rows_before = len(read_ledger(ledger_file))
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "worksheet",
                 str(worksheet)]) == 2
    err = capsys.readouterr().err
    assert "does not hold the bytes" in err and "nothing was recorded" in err
    assert copy.read_text(encoding="utf-8") == "tampered\n"
    assert len(read_ledger(ledger_file)) == rows_before


def test_a_copy_that_does_not_match_the_hash_is_removed_and_nothing_recorded(tmp_path, monkeypatch):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    worksheet = study / "worksheets" / "H1-worksheet.csv"

    def changed_while_copying(src, dst, *args):
        dst.write(b"saved again by a spreadsheet\n")

    monkeypatch.setattr(ledger.shutil, "copyfileobj", changed_while_copying)
    with pytest.raises(StudyError, match="changed while it was being recorded"):
        ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    assert not ledger_file.exists()
    assert list((study / "ledger-archive").iterdir()) == []


def test_record_without_archive_makes_no_copy(tmp_path):
    study = _study(tmp_path)
    ledger.record_files(study / "ledger.csv", "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"],
                        archive=False)
    assert not (study / "ledger-archive").exists()


# ---------- record --kind worksheet: the pre-hash lint ----------

def test_record_refuses_a_worksheet_the_lint_finds_problems_in(tmp_path, capsys):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1", edits={"MON-03": "", "current": "9"})
    assert _record(ledger_file, "H1", sheet) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    err = captured.err.splitlines()
    assert f"lint CRITICAL {sheet}: MON-03: missing verdict" in err
    assert f"lint CRITICAL {sheet}: cmmi current: level '9' is outside 1-5" in err
    assert len(err) == 3
    assert "the worksheet lint found 2 problem(s), listed above; nothing was recorded" in err[-1]
    assert "add --force to record it as it is" in err[-1]
    assert not ledger_file.exists() and not (study / "ledger-archive").exists()


def test_record_with_force_keeps_the_lint_findings_in_the_note(tmp_path, capsys):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1", edits={"MON-03": "", "current": "9"})
    assert _record(ledger_file, "H1", sheet, "--force", "--note", "manual pass done") == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines()[0] == f"{sha256_file(sheet)}  worksheets/H1-worksheet.csv"
    assert captured.err.count("lint CRITICAL") == 2
    assert read_ledger(ledger_file)[0].note == (
        "manual pass done; recorded despite lint findings: CRITICAL MON-03: missing verdict; CRITICAL cmmi "
        "current: level '9' is outside 1-5")


def test_record_lint_uses_the_study_configuration_and_needs_one(tmp_path, capsys):
    study = _study(tmp_path)                       # no study.yaml next to the ledger
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1")
    assert _record(ledger_file, "H1", sheet, "--force") == 2
    err = capsys.readouterr().err
    assert "the worksheet lint needs the study configuration" in err and "--config FILE" in err
    assert not ledger_file.exists()
    elsewhere = tmp_path / "settings" / "study.yaml"
    elsewhere.parent.mkdir()
    elsewhere.write_text(config_template(["H1"]), encoding="utf-8")
    assert _record(ledger_file, "H1", sheet, "--config", str(elsewhere)) == 0
    # The configuration decides the allowed range: under the approved rule a 5 is outside it.
    elsewhere.write_text("hosts: [H1]\nmanual_max_level: {cmmi: 4}\n", encoding="utf-8")
    sheet = _filled_worksheet(study, "H1", level="5")
    capsys.readouterr()
    assert _record(ledger_file, "H1", sheet, "--config", str(elsewhere)) == 2
    assert "cmmi monitored: level '5' is outside 1-4" in capsys.readouterr().err


def test_record_lint_follows_the_declared_manual_level_rule(tmp_path, capsys):
    study = _study(tmp_path)
    (study / "study.yaml").write_text(
        "hosts: [H1, H2]\nmanual_max_level: {cmmi: 4}\nlevel_rule: {manual: approved, overall: pooled-checks}\n",
        encoding="utf-8")
    ledger_file = study / "ledger.csv"
    # Every verdict PASS: every pass ratio is 1, so the approved rule gives level 4 everywhere.
    assert _record(ledger_file, "H1", _filled_worksheet(study, "H1", level="4")) == 0
    sheet = _filled_worksheet(study, "H2", level="4", edits={"monitored": "3"})
    capsys.readouterr()
    assert _record(ledger_file, "H2", sheet) == 2
    assert (f"lint WARNING {sheet}: cmmi monitored: level 3 entered, but this worksheet's verdicts give level 4 "
            "under the declared manual rule (approved, overall pooled-checks)") in capsys.readouterr().err.splitlines()
    assert [row.host_code for row in read_ledger(ledger_file)] == ["H1"]


def test_record_lint_checks_the_host_code_and_the_worksheet_path(tmp_path, capsys):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1")
    assert _record(ledger_file, "H2", sheet) == 2           # recorded under the wrong host
    err = capsys.readouterr().err.splitlines()
    assert f"lint CRITICAL {sheet}: host_code is 'H1', expected 'H2'" in err
    assert (f"lint WARNING {sheet}: this is not worksheets/H2-worksheet.csv next to the ledger, so the seal would "
            "not count this row as H2's worksheet") in err
    copy = study / "H1-worksheet (copy).csv"              # the right sheet, but not the file the seal counts
    shutil.copyfile(str(sheet), str(copy))
    assert _record(ledger_file, "H1", copy) == 2
    assert (f"lint WARNING {copy}: this is not worksheets/H1-worksheet.csv next to the ledger, so the seal would "
            "not count this row as H1's worksheet") in capsys.readouterr().err.splitlines()
    attestation = study / "inputs" / "H1-attestation.json"   # step 3 with the wrong path
    attestation.parent.mkdir()
    attestation.write_text("{}", encoding="utf-8")
    assert _record(ledger_file, "H1", attestation) == 2
    assert "not a worksheet this command can read: H1-attestation.json" in capsys.readouterr().err
    assert not ledger_file.exists()


def test_record_lint_reads_no_tool_output(tmp_path, capsys):
    study = _with_config(tmp_path)
    sheet = _filled_worksheet(study, "H1")
    opened = []
    read_bytes, read_text, real_open = Path.read_bytes, Path.read_text, open

    def spy_open(file, *args, **kwargs):
        opened.append(Path(str(file)))
        return real_open(file, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "read_bytes", lambda self: opened.append(self) or read_bytes(self))
        patch.setattr(Path, "read_text", lambda self, *a, **k: opened.append(self) or read_text(self, *a, **k))
        patch.setattr("builtins.open", spy_open)
        assert _record(study / "ledger.csv", "H1", sheet) == 0
    assert sheet in opened and (study / "study.yaml") in opened
    assert [p for p in opened if OUTPUTS_DIR in p.parts] == []
    assert (study / OUTPUTS_DIR / "H1-cmmi.json").is_file()      # there was one to read


def test_force_and_config_belong_to_worksheet_records(tmp_path, capsys):
    study = _with_config(tmp_path)
    output = study / "outputs" / "H1-cmmi.json"
    for extra in (["--force"], ["--config", str(study / "study.yaml")]):
        assert main(["ledger", "record", "--ledger", str(study / "ledger.csv"), "--host", "H1",
                     "--kind", "tool-output", *extra, str(output)]) == 2
        assert "--config and --force belong to the worksheet lint" in capsys.readouterr().err
    assert not (study / "ledger.csv").exists()
    assert main(["ledger", "record", "--ledger", str(study / "ledger.csv"), "--host", "H1",
                 "--kind", "tool-output", str(output)]) == 0       # other kinds are never linted


# ---------- verify ----------

def test_verify_reports_ok_changed_and_missing(tmp_path, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])
    ledger.record_files(ledger_file, "H2", "worksheet", [study / "worksheets" / "H2-worksheet.csv"])
    ledger.record_files(ledger_file, "H1", "tool-output", [study / "outputs" / "H1-cmmi.json"])

    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    assert _lines(capsys) == [
        "OK      worksheets/H1-worksheet.csv  (worksheet)",
        "OK      worksheets/H2-worksheet.csv  (worksheet)",
        "OK      outputs/H1-cmmi.json  (tool-output)",
    ]

    (study / "worksheets" / "H2-worksheet.csv").write_text("edited after hashing\n", encoding="utf-8")
    (study / "outputs" / "H1-cmmi.json").unlink()
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 1
    assert _lines(capsys) == [
        "OK      worksheets/H1-worksheet.csv  (worksheet)",
        "CHANGED worksheets/H2-worksheet.csv  (worksheet)",
        "MISSING outputs/H1-cmmi.json  (tool-output)",
    ]
    states = [state for _, state in ledger.verify_rows(ledger_file)]
    assert states == [ledger.OK, ledger.CHANGED, ledger.MISSING]


def test_verify_resolves_paths_against_the_ledger_folder_not_the_cwd(tmp_path, monkeypatch, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    assert _lines(capsys) == ["OK      worksheets/H1-worksheet.csv  (worksheet)"]


def test_verify_of_a_missing_ledger_is_an_error(tmp_path, capsys):
    assert main(["ledger", "verify", "--ledger", str(tmp_path / "nope.csv")]) == 2
    assert "not found" in capsys.readouterr().err
    with pytest.raises(StudyError, match="not found"):
        ledger.row_states(tmp_path / "nope.csv")


def test_verify_still_flags_an_edit_after_rerecording(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    worksheet = study / "worksheets" / "H1-worksheet.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    worksheet.write_text("edited\n", encoding="utf-8")
    ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    assert [state for _, state in ledger.verify_rows(ledger_file)] == [ledger.CHANGED, ledger.OK]
    assert ledger.worksheets_hashed(ledger_file, ["H1"]) == {"H1": False}
    assert [item.state for item in ledger.row_states(ledger_file)] == [ledger.CHANGED, ledger.OK]


def _corrections(tmp_path):
    """A study whose study.yaml and H1 attestation were hashed at 10:00 and
    corrected since: the two first rows (a hash the files no longer have)
    are CHANGED. Returns the folder, both files and those first rows."""
    study = _study(tmp_path)
    (study / "inputs").mkdir()
    config = study / "study.yaml"
    attestation = study / "inputs" / "H1-attestation.json"
    config.write_text("hosts: [H1, H2]\nthreshold: 0.80\n", encoding="utf-8")
    attestation.write_text('{"version": 2}\n', encoding="utf-8")
    first = [("2026-11-23T10:00:00Z", "STUDY", "other", "study.yaml", "study configuration"),
             ("2026-11-23T10:00:00Z", "H1", "input", "inputs/H1-attestation.json", "")]
    return study, config, attestation, first


def test_a_correction_recorded_before_it_could_matter_is_superseded(tmp_path, capsys):
    study, config, attestation, first = _corrections(tmp_path)
    ledger_file = study / "ledger.csv"
    _write_ledger(ledger_file, first + [
        ("2026-11-23T10:05:00Z", "STUDY", "other", config, "corrected"),
        ("2026-11-23T10:05:00Z", "H1", "input", attestation, "corrected"),
        ("2026-11-23T10:10:00Z", "H1", "worksheet", study / "worksheets" / "H1-worksheet.csv", ""),
        ("2026-11-23T10:20:00Z", "H1", "tool-output", study / "outputs" / "H1-cmmi.json", ""),
    ])
    states = ledger.row_states(ledger_file)
    assert [(s.index, s.state, s.out_of_order) for s in states] == [
        (0, ledger.SUPERSEDED, False), (1, ledger.SUPERSEDED, False), (2, ledger.OK, False),
        (3, ledger.OK, False), (4, ledger.OK, False), (5, ledger.OK, False)]
    assert states[0].row.path == "study.yaml"
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    assert _lines(capsys)[:3] == ["SUPERSEDED study.yaml  (other)",
                                  "SUPERSEDED inputs/H1-attestation.json  (input)",
                                  "OK      study.yaml  (other)"]


@pytest.mark.parametrize("config_time, input_time, expected", [
    # study.yaml corrected after the first tool run of any host: stays CHANGED.
    ("2026-11-23T10:25:00Z", "2026-11-23T10:05:00Z", [ledger.CHANGED, ledger.SUPERSEDED]),
    # The input corrected after its host's worksheet was hashed: stays CHANGED.
    ("2026-11-23T10:05:00Z", "2026-11-23T10:15:00Z", [ledger.SUPERSEDED, ledger.CHANGED]),
    # Recorded in the same second as the deadline is not before it.
    ("2026-11-23T10:20:00Z", "2026-11-23T10:10:00Z", [ledger.CHANGED, ledger.CHANGED]),
])
def test_a_correction_after_the_deadline_stays_changed(tmp_path, capsys, config_time, input_time, expected):
    study, config, attestation, first = _corrections(tmp_path)
    ledger_file = study / "ledger.csv"
    later = [("2026-11-23T10:10:00Z", "H1", "worksheet", study / "worksheets" / "H1-worksheet.csv", ""),
             ("2026-11-23T10:20:00Z", "H2", "facts", study / "outputs" / "H1-cmmi.json", ""),
             (config_time, "STUDY", "other", config, "corrected"),
             (input_time, "H1", "input", attestation, "corrected")]
    _write_ledger(ledger_file, first + sorted(later, key=lambda row: row[0]))  # file order = time order
    states = ledger.row_states(ledger_file)
    assert not any(s.out_of_order for s in states)
    assert [s.state for s in states][:2] == expected
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 1


@pytest.mark.parametrize("kind", ["worksheet", "tool-output", "facts", "register-review", "missed-gaps"])
def test_frozen_kinds_are_never_superseded(tmp_path, kind):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    output = study / "outputs" / "H1-cmmi.json"
    _write_ledger(ledger_file, [("2026-11-23T10:00:00Z", "H1", kind, "outputs/H1-cmmi.json", ""),
                                ("2026-11-23T10:01:00Z", "H1", kind, output, "re-recorded")])
    assert ledger.FROZEN_KINDS == ("worksheet", "tool-output", "facts", "register-review", "missed-gaps")
    assert [s.state for s in ledger.row_states(ledger_file)] == [ledger.CHANGED, ledger.OK]


def test_a_row_dated_before_a_row_above_it_is_out_of_order(tmp_path, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = study / "worksheets" / "H1-worksheet.csv"
    output = study / "outputs" / "H1-cmmi.json"
    _write_ledger(ledger_file, [
        ("2026-11-23T10:00:00Z", "H1", "tool-output", output, ""),
        ("2026-11-23T10:00:00Z", "H2", "worksheet", study / "worksheets" / "H2-worksheet.csv", ""),
        ("2026-11-23T09:59:59Z", "H1", "worksheet", sheet, "moved back by hand"),
        ("2026-11-23T10:00:01Z", "H1", "facts", output, ""),
    ])
    assert _states(ledger_file) == [(ledger.OK, False), (ledger.OK, False), (ledger.OK, True), (ledger.OK, False)]
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 1
    assert _lines(capsys)[2] == ("OK      worksheets/H1-worksheet.csv  (worksheet)  OUT OF ORDER "
                                 "(recorded 2026-11-23T09:59:59Z, earlier than 2026-11-23T10:00:00Z above it)")


def test_rows_in_the_same_second_are_in_order_and_an_unreadable_time_is_not(tmp_path, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = study / "worksheets" / "H1-worksheet.csv"
    _write_ledger(ledger_file, [("2026-11-23T10:00:00Z", "H1", "worksheet", sheet, "")] * 3)
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    capsys.readouterr()
    _write_ledger(ledger_file, [("2026-11-23T10:00:00Z", "H1", "worksheet", sheet, ""),
                                ("11/23/2026 10:01", "H1", "worksheet", sheet, "")])
    assert _states(ledger_file) == [(ledger.OK, False), (ledger.OK, True)]
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 1
    assert "OUT OF ORDER (recorded_at_utc '11/23/2026 10:01' is not a timestamp)" in _lines(capsys)[1]


# ---------- status ----------

def test_status_lists_kinds_and_times_and_flags_hosts_without_worksheet(tmp_path, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    ws_row = ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])[0]
    out_row = ledger.record_files(ledger_file, "H2", "tool-output", [study / "outputs" / "H1-cmmi.json"])[0]

    assert main(["ledger", "status", "--ledger", str(ledger_file), "--hosts", "H1,H2,H3"]) == 1
    lines = _lines(capsys)
    assert lines == [
        f"H1  worksheet        {ws_row.recorded_at_utc}",
        f"H2  tool-output      {out_row.recorded_at_utc}",
        "H2  NO WORKSHEET ROW",
        "H3  NO WORKSHEET ROW (nothing recorded for this host)",
    ]
    text = "\n".join(lines)
    assert ws_row.sha256 not in text and "synthetic" not in text

    assert main(["ledger", "status", "--ledger", str(ledger_file)]) == 0
    assert _lines(capsys) == [
        f"H1  worksheet        {ws_row.recorded_at_utc}",
        f"H2  tool-output      {out_row.recorded_at_utc}",
    ]


def test_status_counts_only_a_worksheet_row_for_the_hosts_own_sheet(tmp_path, capsys):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    (study / "inputs").mkdir()
    attestation = study / "inputs" / "H2-attestation.json"
    attestation.write_text("{}", encoding="utf-8")
    row = ledger.record_files(ledger_file, "H2", "worksheet", [attestation])[0]  # a mistyped path in step 3
    assert main(["ledger", "status", "--ledger", str(ledger_file), "--hosts", "H2"]) == 1
    assert _lines(capsys) == [
        f"H2  worksheet        {row.recorded_at_utc}",
        "H2  NO WORKSHEET ROW for worksheets/H2-worksheet.csv (this host's worksheet rows name another file)",
    ]
    assert not ledger.host_status(ledger_file, ["H2"])[0].has_worksheet
    assert ledger.worksheet_problems(ledger_file, ["H2"]) == {"H2": "no worksheet row in the ledger"}

    # A row recorded under another host code still counts for the sheet it names.
    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H2-worksheet.csv"])
    assert ledger.host_status(ledger_file, ["H2"])[0].has_worksheet
    assert main(["ledger", "status", "--ledger", str(ledger_file), "--hosts", "H2"]) == 0


def test_host_status_orders_hosts_and_kinds(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.record_files(ledger_file, "H2", "tool-output", [study / "outputs" / "H1-cmmi.json"])
    ledger.record_files(ledger_file, "H2", "worksheet", [study / "worksheets" / "H2-worksheet.csv"])
    ledger.record_files(ledger_file, "STUDY", "protocol", [study / "outputs" / "H1-cmmi.json"])
    statuses = ledger.host_status(ledger_file, ["H1", "H2"])
    assert [s.host_code for s in statuses] == ["H1", "H2", "STUDY"]
    assert statuses[0].kinds == {} and not statuses[0].has_worksheet
    assert list(statuses[1].kinds) == ["worksheet", "tool-output"]
    assert statuses[1].has_worksheet
    assert statuses[1].withdrawn is None


# ---------- withdraw ----------

def test_withdraw_appends_a_dated_protocol_row_and_status_shows_it(tmp_path, capsys):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])
    rc = main(["ledger", "withdraw", "--ledger", str(ledger_file), "--host", "H3",
               "--reason", "  Windows 11 VM   could not be rearmed "])
    assert rc == 0
    row = read_ledger(ledger_file)[-1]
    assert (row.host_code, row.kind, row.path, row.note) == (
        "H3", "protocol", "study.yaml", "withdrawn: Windows 11 VM could not be rearmed")
    assert row.sha256 == sha256_file(study / "study.yaml")
    assert _lines(capsys) == [f"{row.sha256}  study.yaml", f"archive copy: ledger-archive/{row.sha256}.yaml",
                              f"H3 withdrawn at {row.recorded_at_utc}: Windows 11 VM could not be rearmed"]
    assert ledger.withdrawn_hosts(read_ledger(ledger_file)) == {
        "H3": (row.recorded_at_utc, "Windows 11 VM could not be rearmed")}

    assert main(["ledger", "status", "--ledger", str(ledger_file), "--hosts", "H1,H3"]) == 0
    assert _lines(capsys)[-1] == f"H3  WITHDRAWN {row.recorded_at_utc}: Windows 11 VM could not be rearmed"
    status = ledger.host_status(ledger_file, ["H3"])[0]
    assert status.withdrawn == (row.recorded_at_utc, "Windows 11 VM could not be rearmed")


def test_withdraw_records_the_config_given(tmp_path, capsys):
    study = _with_config(tmp_path)
    other = tmp_path / "study-v2.yaml"
    other.write_text(config_template(["H1", "H2", "H3"]), encoding="utf-8")
    assert main(["ledger", "withdraw", "--ledger", str(study / "ledger.csv"), "--host", "H2",
                 "--reason", "dropped", "--config", str(other)]) == 0
    assert read_ledger(study / "ledger.csv")[-1].path == str(other.resolve())


@pytest.mark.parametrize("host, reason, message", [
    ("STUDY", "not a host", "not a host"),
    ("study", "not a host", "not a host"),
    ("H2", "   ", "--reason"),
    ("H9", "typo", "H9 is not a host of this study (hosts: H1, H2, H3)"),
    ("H 2", "bad code", "invalid host code"),
])
def test_withdraw_refuses_and_records_nothing(tmp_path, capsys, host, reason, message):
    study = _with_config(tmp_path)
    assert main(["ledger", "withdraw", "--ledger", str(study / "ledger.csv"), "--host", host,
                 "--reason", reason]) == 2
    assert message in capsys.readouterr().err
    assert not (study / "ledger.csv").exists()


def test_withdraw_refuses_a_host_already_withdrawn_and_a_missing_config(tmp_path, capsys):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.withdraw_host(ledger_file, "H2", "first")
    with pytest.raises(StudyError, match="already withdrawn"):
        ledger.withdraw_host(ledger_file, "H2", "second")
    assert len(read_ledger(ledger_file)) == 1
    (study / "study.yaml").unlink()
    assert main(["ledger", "withdraw", "--ledger", str(ledger_file), "--host", "H1", "--reason", "x"]) == 2
    assert "study configuration not found" in capsys.readouterr().err


def test_a_hand_recorded_withdrawal_counts_and_other_protocol_rows_do_not(tmp_path):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.record_files(ledger_file, "H2", "protocol", [study / "study.yaml"], note="withdrawn: VM lost")
    ledger.record_files(ledger_file, "H3", "protocol", [study / "study.yaml"], note="note about withdrawn: hosts")
    ledger.record_files(ledger_file, "STUDY", "protocol", [study / "study.yaml"], note="withdrawn: whole study")
    assert set(ledger.withdrawn_hosts(read_ledger(ledger_file))) == {"H2"}


# ---------- the seal ----------

def _hash_all(study, *hosts):
    for host in hosts:
        ledger.record_files(study / "ledger.csv", host, "worksheet", [study / "worksheets" / f"{host}-worksheet.csv"])


def test_seal_opens_only_when_every_host_is_hashed_and_unchanged(tmp_path):
    study = _with_config(tmp_path, hosts=("H1", "H2"))
    status = ledger.seal_status(study, study / "study.yaml")
    assert not status.ok and status.hosts == ["H1", "H2"] and status.withdrawn == {}
    assert status.problems[0] == ("STUDY", f"no ledger found at {study / 'ledger.csv'}")
    _hash_all(study, "H1", "H2")
    status = ledger.seal_status(study, ledger.load_config(study / "study.yaml"))
    assert status.ok and status.problems == [] and status.hosts == ["H1", "H2"]


def test_seal_problem_texts_give_advice_per_case(tmp_path):
    study = _with_config(tmp_path, hosts=("H1", "H2", "H3", "H4"))
    (study / "worksheets" / "H3-worksheet.csv").write_text("row_type,item\n", encoding="utf-8")
    (study / "worksheets" / "H4-worksheet.csv").write_text("row_type,item\n", encoding="utf-8")
    _hash_all(study, "H1", "H2", "H4")
    h2_copy = _archive(study, study / "worksheets" / "H2-worksheet.csv").name
    (study / "worksheets" / "H2-worksheet.csv").write_text("edited\n", encoding="utf-8")
    (study / "worksheets" / "H4-worksheet.csv").unlink()
    (study / "worksheets" / "H5-worksheet.csv").write_text("row_type,item\n", encoding="utf-8")
    problems = dict(ledger.seal_status(study, study / "study.yaml").problems)
    assert "H1" not in problems
    assert problems["H2"].startswith(ledger.WORKSHEET_CHANGED + ": worksheets/H2-worksheet.csv; ")
    assert ("restore the original bytes from your commit, e-mail or ledger-archive copy; "
            "a changed worksheet cannot be re-hashed") in problems["H2"]
    assert problems["H2"].endswith(f"(archived copy: ledger-archive/{h2_copy})")
    assert "ledger record" not in problems["H2"]
    assert problems["H3"].startswith(ledger.WORKSHEET_NOT_HASHED + ": no ledger row of kind worksheet for "
                                     "worksheets/H3-worksheet.csv")
    assert "'ledger withdraw'" in problems["H3"]
    assert problems["H4"].startswith(ledger.HASHED_WORKSHEET_MISSING + ": worksheets/H4-worksheet.csv; "
                                     + ledger.RESTORE_ADVICE)
    assert problems["H5"].startswith(ledger.WORKSHEET_NOT_HASHED)  # named by its file only
    for text in problems.values():
        assert "study.yaml" not in text


def test_seal_rerecording_an_edited_worksheet_never_opens_it(tmp_path):
    study = _with_config(tmp_path, hosts=("H1",))
    _hash_all(study, "H1")
    (study / "worksheets" / "H1-worksheet.csv").write_text("edited\n", encoding="utf-8")
    _hash_all(study, "H1")
    problems = dict(ledger.seal_status(study, study / "study.yaml").problems)
    assert "the ledger holds 2 different hashes for it" in problems["H1"]


def test_seal_hosts_come_from_every_source(tmp_path):
    study = _with_config(tmp_path, hosts=("H1", "H2"))
    subset = tmp_path / "h1-only.yaml"
    subset.write_text("hosts: [H1]\n", encoding="utf-8")
    (study / "inputs").mkdir()
    (study / "inputs" / "H3-attestation.json").write_text("{}", encoding="utf-8")
    ledger.record_files(study / "ledger.csv", "H3", "input", [study / "inputs" / "H3-attestation.json"])
    ledger.record_files(study / "ledger.csv", "STUDY", "other", [study / "study.yaml"])
    (study / "worksheets" / "H4-worksheet.csv").write_text("x\n", encoding="utf-8")
    (study / "outputs" / "H5-facts.json").write_text("not json: never opened", encoding="utf-8")
    (study / "outputs" / "LAB-1-cisa-ztmm.json").write_text("not json", encoding="utf-8")
    (study / "outputs" / "H6-cmmi.json").write_text("not json", encoding="utf-8")
    (study / "worksheets" / "~$H1-worksheet.csv").write_text("excel lock", encoding="utf-8")
    (study / "outputs" / "replay.json").write_text("{}", encoding="utf-8")
    (study / "worksheets" / "H1-worksheet - Copy.csv").write_text("x", encoding="utf-8")
    status = ledger.seal_status(study, ledger.load_config(subset))
    # H1 from the subset config; H2 from DIR/study.yaml; H3 from a ledger row;
    # H4 from a worksheet file; H5, LAB-1 and H1 (outputs/H1-cmmi.json) from outputs/.
    assert status.hosts == ["H1", "H2", "H3", "H4", "H5", "H6", "LAB-1"]
    assert [host for host, _ in status.problems] == ["H1", "H2", "H3", "H4", "H5", "H6", "LAB-1"]


def test_seal_withdrawn_hosts_leave_it(tmp_path):
    study = _with_config(tmp_path, hosts=("H1", "H2", "H3"))
    _hash_all(study, "H1")
    ledger.withdraw_host(study / "ledger.csv", "H3", "not assessed")
    status = ledger.seal_status(study, study / "study.yaml")
    assert status.hosts == ["H1", "H2"] and set(status.withdrawn) == {"H3"}
    assert [host for host, _ in status.problems] == ["H2"]
    ledger.withdraw_host(study / "ledger.csv", "H2", "VM lost")
    status = ledger.seal_status(study, study / "study.yaml")
    assert status.ok and status.hosts == ["H1"]


def test_seal_counts_only_rows_for_the_hosts_own_worksheet_path(tmp_path):
    study = _with_config(tmp_path, hosts=("H1",))
    (study / "inputs").mkdir()
    (study / "inputs" / "H1-attestation.json").write_text("{}", encoding="utf-8")
    ledger.record_files(study / "ledger.csv", "H1", "worksheet", [study / "inputs" / "H1-attestation.json"])
    problems = dict(ledger.seal_status(study, study / "study.yaml").problems)
    assert problems["H1"].startswith(ledger.WORKSHEET_NOT_HASHED)


def test_seal_reports_study_wide_problems_under_study(tmp_path):
    study = _with_config(tmp_path, hosts=("H1",))
    _hash_all(study, "H1")
    other = tmp_path / "other.yaml"
    other.write_text("hosts: [H1]\n", encoding="utf-8")
    (study / "study.yaml").write_text("hosts: [H1, H2\n", encoding="utf-8")  # broken YAML: hosts unknown
    with open(study / "ledger.csv", "a", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerow(["2026-11-23T10:00:00Z", "H 9", "other", "x", "0" * 64, "1", ""])
    problems = ledger.seal_status(study, other).problems
    assert [host for host, _ in problems] == ["STUDY", "STUDY", "H2"]  # H2: worksheets/H2-worksheet.csv exists
    assert "study.yaml in the study folder cannot be read" in problems[0][1]
    assert "line 3 of the ledger has an invalid host code 'H 9'" == problems[1][1]
    assert problems[2][1].startswith(ledger.WORKSHEET_NOT_HASHED)


def test_load_config_turns_a_decoding_error_into_a_study_error(tmp_path, monkeypatch):
    def not_utf8(path):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr(ledger, "load_study_config", not_utf8)
    with pytest.raises(StudyError, match="save it as UTF-8"):
        ledger.load_config(tmp_path / "study.yaml")


def test_seal_of_an_unreadable_ledger_is_an_error(tmp_path):
    study = _with_config(tmp_path, hosts=("H1",))
    (study / "ledger.csv").write_text("not,a,ledger\n", encoding="utf-8")
    with pytest.raises(StudyError):
        ledger.seal_status(study, study / "study.yaml")


# ---------- library: worksheets_hashed ----------

def test_worksheets_hashed_true_only_for_recorded_unchanged_worksheets(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    assert ledger.worksheets_hashed(ledger_file, ["H1"]) == {"H1": False}  # no ledger yet

    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])
    ledger.record_files(ledger_file, "H2", "worksheet", [study / "worksheets" / "H2-worksheet.csv"])
    ledger.record_files(ledger_file, "H3", "tool-output", [study / "outputs" / "H1-cmmi.json"])
    assert ledger.worksheets_hashed(ledger_file, ["H1", "H2", "H3"]) == {"H1": True, "H2": True, "H3": False}

    (study / "worksheets" / "H2-worksheet.csv").write_text("changed\n", encoding="utf-8")
    (study / "worksheets" / "H1-worksheet.csv").unlink()
    problems = ledger.worksheet_problems(ledger_file, ["H1", "H2", "H3"])
    assert problems == {
        "H1": "hashed worksheet is missing: worksheets/H1-worksheet.csv",
        "H2": "worksheet changed after it was hashed: worksheets/H2-worksheet.csv",
        "H3": "no worksheet row in the ledger",
    }
    assert ledger.worksheets_hashed(ledger_file, ["H1", "H2", "H3"]) == {"H1": False, "H2": False, "H3": False}


def test_parse_host_list():
    assert ledger.parse_host_list(" H1, H2 ,H3,") == ["H1", "H2", "H3"]
    with pytest.raises(StudyError, match="duplicate"):
        ledger.parse_host_list("H1,H1")
    with pytest.raises(StudyError):
        ledger.parse_host_list(" , ")
