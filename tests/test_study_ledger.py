"""Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

Tests for miccmac_study.ledger: record (with its archive copies, the rule
that a sealed file is hashed once, the study.yaml check and, for worksheets,
the pre-hash lint) / verify (OK, CHANGED, MISSING, SUPERSEDED, OUT OF ORDER)
/ status / withdraw (also after a seal opening) through the command
dispatcher, the seal (seal_status: the first worksheet row is binding,
study.yaml and its recorded versions), seal-opening rows, the assessor's
input files (assessor_inputs, check_run_inputs) and the other library
functions instruments use. All files are synthetic and live under tmp_path.
Most tests use tiny stub worksheets: the library function record_files never
lints, and the command line is given real generated worksheets (or --force)
where it records a worksheet."""
from __future__ import annotations

import codecs
import csv
import hashlib
import json
import os
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
    StudyConfig,
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


def _append_row(ledger_file, when, host, kind, rel, sha256, note=""):
    """One row appended by hand (record_files would refuse a second hash for a sealed path; a ledger
    written before that rule, or edited by hand, can still hold one)."""
    with open(ledger_file, "a", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerow([when, host, kind, rel, sha256, "1", note])


def _edit_cell(sheet, item, column, value):
    """Change one cell of every worksheet row whose item is `item`, as an assessor would."""
    rows = read_csv(sheet, WORKSHEET_COLUMNS)
    for row in rows:
        if row["item"] == item:
            row[column] = value
    write_csv(sheet, WORKSHEET_COLUMNS, rows, overwrite=True)


def _archive_names(study):
    folder = study / "ledger-archive"
    return sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []


def _states(ledger_file):
    return [(item.state, item.out_of_order) for item in ledger.row_states(ledger_file)]


def _with_config(tmp_path, hosts=("H1", "H2", "H3")):
    study = _study(tmp_path)
    (study / "study.yaml").write_text(config_template(list(hosts)), encoding="utf-8")
    return study


# The level rule declared in the template as the guide's Setup does once decision 4 is made. Added with the
# worksheet lint's decision-4 finding: a study.yaml with level_rule.manual null makes `record --kind worksheet`
# refuse every sheet (unless --force).
_DECLARED_RULE = (("manual_max_level: {cmmi: 5, cisa-ztmm: 4}", "manual_max_level: {cmmi: 4, cisa-ztmm: 4}"),
                  ("  manual: null", "  manual: approved"), ("  overall: null", "  overall: pooled-checks"))


def _declared(text):
    """config_template text with the level rule declared (approved, overall pooled-checks)."""
    for old, new in _DECLARED_RULE:
        assert old in text, old
        text = text.replace(old, new)
    return text


def _with_lint_config(tmp_path, hosts=("H1", "H2", "H3")):
    """_with_config with the level rule declared, so a complete worksheet lints clean."""
    study = _with_config(tmp_path, hosts)
    config = study / "study.yaml"
    config.write_text(_declared(config.read_text(encoding="utf-8")), encoding="utf-8")
    return study


def _filled_worksheet(study, host="H1", verdict="PASS", level="4", edits=None):
    """A real worksheet from the worksheet command (CMMI level rows), every
    check and level filled in, with each check's pass criterion, evidence
    steps and procedure source, and the assessor and level_rule meta values
    (the lint asks for them); `edits` maps a check id or a level scope to
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
            row.update(pass_criterion="synthetic criterion", evidence_procedure="synthetic step",
                       procedure_source="NONE")
        elif row["row_type"] == "level":
            row["value"] = (edits or {}).get(row["property"], level)
        elif row["row_type"] == "meta" and row["item"] in ("assessor", "level_rule"):
            row["value"] = {"assessor": "assessor", "level_rule": "approved, overall pooled-checks"}[row["item"]]
    write_csv(sheet, WORKSHEET_COLUMNS, rows, overwrite=True)
    return sheet


def _record(ledger_file, host, sheet, *extra):
    return main(["ledger", "record", "--ledger", str(ledger_file), "--host", host, "--kind", "worksheet",
                 *extra, str(sheet)])


# ---------- record ----------

def test_record_creates_ledger_with_relative_paths_and_prints_hashes(tmp_path, capsys):
    # Changed with the worksheet lint: the command line now records a real, complete worksheet (it lints clean),
    # under a study.yaml that declares the level rule (the lint's decision-4 finding).
    study = _with_lint_config(tmp_path)
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
                 "--force", str(study / "worksheets" / "H2-worksheet.csv")]) == 0
    # Changed (round 3): a file in outputs/ is recorded only as a tool output or facts file.
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "tool-output",
                 str(study / "outputs" / "H1-cmmi.json")]) == 0
    capsys.readouterr()

    data = ledger_file.read_bytes()
    assert data.startswith(codecs.BOM_UTF8)
    assert data.count(codecs.BOM_UTF8) == 1
    rows = read_ledger(ledger_file)
    assert [(r.host_code, r.path) for r in rows] == [
        ("H1", "worksheets/H1-worksheet.csv"),
        ("H2", "worksheets/H2-worksheet.csv"),
        ("H1", "outputs/H1-cmmi.json"),
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
    # Changed with the worksheet lint: the command line records a real, complete worksheet. Changed again
    # with the sealed-path rule: the same sheet recorded again adds no row and says "already recorded".
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    worksheet = _filled_worksheet(study, "H1")
    ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    copy = _archive(study, worksheet)
    before = copy.stat().st_mtime_ns
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "worksheet",
                 str(worksheet)]) == 0
    lines = _lines(capsys)
    assert lines[0].startswith("already recorded at ") and lines[0].endswith(" (ledger line 2):")
    assert lines[2] == f"archive copy: ledger-archive/{copy.name}"
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


# ---------- record: a sealed file is hashed once ----------

def test_rerecording_an_edited_worksheet_is_refused_and_restoring_the_copy_opens_the_seal(tmp_path, capsys):
    """V1-N1, V3-N2: step 3 run again on an edited, hashed worksheet used to
    record a second hash, after which no restore could open the seal."""
    study = _with_lint_config(tmp_path, hosts=("H1",))          # the first record lints clean
    (study / "worksheets" / "H2-worksheet.csv").unlink()
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1")
    assert _record(ledger_file, "H1", sheet) == 0
    first = read_ledger(ledger_file)[0]
    copy = f"ledger-archive/{first.sha256}.csv"
    original = sheet.read_bytes()
    ledger_before, archive_before = ledger_file.read_bytes(), _archive_names(study)
    expected = (f"error: worksheets/H1-worksheet.csv was hashed at {first.recorded_at_utc} (ledger line 2, kind "
                "worksheet); a hashed worksheet, tool output, facts file or register sheet never changes, so nothing "
                f"was recorded. To undo an edit, restore the recorded bytes from {copy} (or your commit or e-mailed "
                "copy); a correction goes in the disagreement log or the protocol log.\n")
    capsys.readouterr()
    # An edit the lint does not see, and one it does: both refused, with or without --force, before the lint.
    for item, column, value in (("MON-01", "evidence_notes", "seen again later"), ("MON-03", "value", "")):
        _edit_cell(sheet, item, column, value)
        for extra in ([], ["--force"]):
            assert _record(ledger_file, "H1", sheet, *extra) == 2
            captured = capsys.readouterr()
            assert (captured.out, captured.err) == ("", expected)
    assert ledger_file.read_bytes() == ledger_before and _archive_names(study) == archive_before
    assert ledger.seal_status(study, study / "study.yaml").problems[0][0] == "H1"

    shutil.copyfile(str(study / copy), str(sheet))         # the restore the refusal names
    assert sheet.read_bytes() == original
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    assert ledger.seal_status(study, study / "study.yaml").ok


@pytest.mark.parametrize("rel, first_kind, second_kind", [
    ("worksheets/H1-worksheet.csv", "other", "other"),
    ("outputs/H1-cmmi.json", "tool-output", "tool-output"),
    ("outputs/H1-facts.json", "other", "facts"),
    ("register/H1-register-review.csv", "register-review", "other"),
    ("register/H1-missed-gaps.csv", "missed-gaps", "missed-gaps"),
    ("elsewhere/H1-worksheet (copy).csv", "worksheet", "other"),   # a frozen kind makes any file sealed
])
def test_record_files_refuses_a_sealed_file_whose_bytes_changed(tmp_path, rel, first_kind, second_kind):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    path = study / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("as hashed\n", encoding="utf-8")
    first = ledger.record_files(ledger_file, "H1", first_kind, [path])[0]
    (study / "inputs").mkdir()
    unsealed = study / "inputs" / "H1-attestation.json"
    unsealed.write_text("{}", encoding="utf-8")
    path.write_text("edited later\n", encoding="utf-8")
    ledger_before, archive_before = ledger_file.read_bytes(), _archive_names(study)
    with pytest.raises(StudyError) as raised:
        ledger.record_files(ledger_file, "H1", second_kind, [unsealed, path])  # the whole call is refused
    message = str(raised.value)
    assert message.startswith(f"{first.path} was hashed at {first.recorded_at_utc} (ledger line 2, kind "
                              f"{first_kind}); ")
    assert (f"restore the recorded bytes from ledger-archive/{first.sha256}{path.suffix} (or your commit or "
            "e-mailed copy)") in message
    assert ledger_file.read_bytes() == ledger_before and _archive_names(study) == archive_before


def test_a_sealed_file_is_matched_however_its_path_is_spelled(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = study / "worksheets" / "H1-worksheet.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [sheet])
    sheet.write_text("edited\n", encoding="utf-8")
    for spelled in (study / "worksheets" / ".." / "worksheets" / "H1-worksheet.csv",
                    study / "outputs" / ".." / "worksheets" / "." / "H1-worksheet.csv"):
        with pytest.raises(StudyError, match="never changes"):
            ledger.record_files(ledger_file, "H1", "worksheet", [spelled])
    assert len(read_ledger(ledger_file)) == 1


@pytest.mark.skipif(os.name != "nt", reason="letter case is part of the file name outside Windows")
def test_a_sealed_file_is_matched_in_any_letter_case_on_windows(tmp_path):
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [study / "worksheets" / "H1-worksheet.csv"])
    (study / "worksheets" / "H1-worksheet.csv").write_text("edited\n", encoding="utf-8")
    with pytest.raises(StudyError, match="never changes"):
        ledger.record_files(ledger_file, "H1", "worksheet", [study / "WORKSHEETS" / "h1-WORKSHEET.CSV"])


@pytest.mark.skipif(os.name != "nt", reason="the \\\\?\\ prefix is a Windows path spelling")
def test_the_windows_extended_length_spelling_is_the_same_file(tmp_path):
    """V1 (round 2): \\\\?\\C:\\... got past the hashed-once rule, and its row then failed verify for good."""
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = study / "worksheets" / "H1-worksheet.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [sheet])
    sheet.write_text("edited\n", encoding="utf-8")
    before = ledger_file.read_bytes()
    prefixed = Path("\\\\?\\" + str(sheet.resolve()))
    with pytest.raises(StudyError, match="never changes"):
        ledger.record_files(ledger_file, "H1", "worksheet", [prefixed])
    with pytest.raises(StudyError, match="never changes"):
        ledger.record_files(ledger_file, "H1", "other", [prefixed])
    assert ledger_file.read_bytes() == before
    assert ledger.is_sealed_path(ledger_file, prefixed, read_ledger(ledger_file))
    # A new file recorded through that spelling is still recorded relative to the ledger.
    other = study / "outputs" / "H1-cmmi.json"
    row = ledger.record_files(ledger_file, "H1", "tool-output", [Path("\\\\?\\" + str(other.resolve()))])[0]
    assert row.path == "outputs/H1-cmmi.json"


def test_record_keeps_each_sealed_folder_to_its_own_kinds(tmp_path, capsys):
    """V1 (round 2): a blank sheet recorded once as 'other' could never be hashed as the worksheet (a sealed path is
    hashed once), so `ledger record` refuses the wrong kind up front."""
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    (study / "register").mkdir()
    review = study / "register" / "H1-register-review.csv"
    review.write_text("entry\n", encoding="utf-8")
    for kind, path, allowed in (
            ("other", study / "worksheets" / "H1-worksheet.csv", "--kind worksheet"),
            ("input", study / "outputs" / "H1-cmmi.json", "--kind tool-output or --kind facts"),
            ("worksheet", study / "outputs" / "H1-cmmi.json", "--kind tool-output or --kind facts"),
            ("protocol", review, "--kind register-review or --kind missed-gaps")):
        assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", kind,
                     str(path)]) == 2
        err = capsys.readouterr().err
        assert f"is in {path.parent.name}/, whose files are recorded only with {allowed}" in err, err
        assert f"not --kind {kind}; nothing was recorded" in err
    assert not ledger_file.exists()
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "register-review",
                 str(review)]) == 0
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "tool-output",
                 str(study / "outputs" / "H1-cmmi.json")]) == 0
    assert [row.kind for row in read_ledger(ledger_file)] == ["register-review", "tool-output"]


@pytest.mark.parametrize("note, owner", [
    ("withdrawn: by hand", "ledger withdraw"),
    ("seal opened by hand: hosts H1", "register-sheet and agreement"),
    ("register sheets generated before every worksheet was hashed: by hand", "register-sheet --force-before-unseal"),
])
def test_record_refuses_the_notes_of_withdrawal_and_seal_opening_rows(tmp_path, capsys, note, owner):
    """Round 3: such rows are ARCHIVED when their file changes later, so `ledger record` cannot write one."""
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "STUDY", "--kind", "protocol",
                 "--note", note, str(study / "study.yaml")]) == 2
    assert f"is written only by {owner}; nothing was recorded" in capsys.readouterr().err
    assert not ledger_file.exists()


def test_record_refuses_an_input_file_named_without_its_role(tmp_path, capsys):
    """V1 (round 2): with role-less names a real swap of the two inputs passed with WARNINGs only."""
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    (study / "inputs").mkdir()
    anonymous = study / "inputs" / "H1-a.json"
    named = study / "inputs" / "H1-attestation.json"
    for path in (anonymous, named):
        path.write_text("{}\n", encoding="utf-8")
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "input",
                 str(named), str(anonymous)]) == 2
    assert ("name an input file <H>-attestation.json or <H>-inventory-record.json, so that its role is known and a "
            "swap of the two files can be detected; nothing was recorded") in capsys.readouterr().err
    assert not ledger_file.exists()
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "input", str(named)]) == 0


def test_files_that_are_not_sealed_can_still_be_recorded_with_new_bytes(tmp_path):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    config = study / "study.yaml"
    ledger.record_files(ledger_file, "STUDY", "other", [config])
    config.write_text(config_template(["H1", "H2"]), encoding="utf-8")
    ledger.record_files(ledger_file, "STUDY", "other", [config], note="corrected")
    ledger.record_files(ledger_file, "STUDY", "other", [config], note="recorded again")
    assert [row.note for row in read_ledger(ledger_file)] == ["", "corrected", "recorded again"]


def test_a_sealed_file_recorded_again_unchanged_adds_no_row(tmp_path, capsys):
    study = _with_lint_config(tmp_path)                          # the first record lints clean
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1")
    cmmi = study / "outputs" / "H1-cmmi.json"
    ztmm = study / "outputs" / "H1-cisa-ztmm.json"
    ztmm.write_text('{"synthetic": "cisa"}\n', encoding="utf-8")
    assert _record(ledger_file, "H1", sheet) == 0
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "tool-output",
                 str(cmmi)]) == 0
    sheet_row, cmmi_row = read_ledger(ledger_file)
    capsys.readouterr()

    assert _record(ledger_file, "H1", sheet) == 0
    assert _lines(capsys) == [f"already recorded at {sheet_row.recorded_at_utc} (ledger line 2):",
                              f"{sheet_row.sha256}  worksheets/H1-worksheet.csv",
                              f"archive copy: ledger-archive/{sheet_row.sha256}.csv"]
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "H1", "--kind", "tool-output",
                 str(cmmi), str(ztmm)]) == 0           # step 7 repeated, with one new file
    lines = _lines(capsys)
    rows = read_ledger(ledger_file)
    assert lines == [f"already recorded at {cmmi_row.recorded_at_utc} (ledger line 3):",
                     f"{cmmi_row.sha256}  outputs/H1-cmmi.json",
                     f"archive copy: ledger-archive/{cmmi_row.sha256}.json",
                     f"{rows[2].sha256}  outputs/H1-cisa-ztmm.json",
                     f"archive copy: ledger-archive/{rows[2].sha256}.json"]
    assert [row.path for row in rows] == ["worksheets/H1-worksheet.csv", "outputs/H1-cmmi.json",
                                          "outputs/H1-cisa-ztmm.json"]
    # The same bytes under another kind are a new fact and get a row, as before.
    assert [row.kind for row in ledger.record_files(ledger_file, "STUDY", "protocol", [cmmi])] == ["protocol"]
    assert len(read_ledger(ledger_file)) == 4


def test_a_worksheet_recorded_again_unchanged_needs_no_lint_and_restores_a_missing_copy(tmp_path, capsys):
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1", edits={"MON-03": ""})          # recorded despite a lint finding
    assert _record(ledger_file, "H1", sheet, "--force") == 0
    (study / "study.yaml").unlink()                                       # the lint could not even run now
    copy = _archive(study, sheet)
    copy.unlink()
    capsys.readouterr()
    assert _record(ledger_file, "H1", sheet) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.splitlines()[0].startswith("already recorded at ")
    assert len(read_ledger(ledger_file)) == 1
    assert copy.read_bytes() == sheet.read_bytes()                       # the missing copy was made again


# ---------- record --kind worksheet: the pre-hash lint ----------

def test_record_refuses_a_worksheet_the_lint_finds_problems_in(tmp_path, capsys):
    # Changed with the decision-4 lint finding: the level rule is declared (cmmi levels 1-4 under the approved rule).
    study = _with_lint_config(tmp_path)
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1", edits={"MON-03": "", "current": "9"})
    assert _record(ledger_file, "H1", sheet) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    err = captured.err.splitlines()
    assert f"lint CRITICAL {sheet}: MON-03: missing verdict" in err
    assert f"lint CRITICAL {sheet}: cmmi current: level '9' is outside 1-4" in err
    assert len(err) == 3
    assert "the worksheet lint found 2 problem(s), listed above; nothing was recorded" in err[-1]
    assert "add --force to record it as it is" in err[-1]
    assert not ledger_file.exists() and not (study / "ledger-archive").exists()


def test_record_with_force_keeps_the_lint_findings_in_the_note(tmp_path, capsys):
    study = _with_lint_config(tmp_path)                          # changed with the decision-4 lint finding
    ledger_file = study / "ledger.csv"
    sheet = _filled_worksheet(study, "H1", edits={"MON-03": "", "current": "9"})
    assert _record(ledger_file, "H1", sheet, "--force", "--note", "manual pass done") == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines()[0] == f"{sha256_file(sheet)}  worksheets/H1-worksheet.csv"
    assert captured.err.count("lint CRITICAL") == 2
    assert read_ledger(ledger_file)[0].note == (
        "manual pass done; recorded despite lint findings: CRITICAL MON-03: missing verdict; CRITICAL cmmi "
        "current: level '9' is outside 1-4")


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
    elsewhere.write_text(_declared(config_template(["H1"])), encoding="utf-8")   # the level rule declared
    assert _record(ledger_file, "H1", sheet, "--config", str(elsewhere)) == 0
    # The configuration decides the allowed range: under the approved rule a 5 is outside it. (A second
    # ledger next to the first: the hashed sheet itself can never be recorded with other bytes.)
    elsewhere.write_text("hosts: [H1]\nmanual_max_level: {cmmi: 4}\n", encoding="utf-8")
    sheet = _filled_worksheet(study, "H1", level="5")
    capsys.readouterr()
    assert _record(study / "ledger-b.csv", "H1", sheet, "--config", str(elsewhere)) == 2
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
    study = _with_lint_config(tmp_path)                          # changed with the decision-4 lint finding
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


@pytest.mark.parametrize("name", ["study.yaml", "Study.YAML"])
def test_record_refuses_a_study_yaml_that_is_not_a_valid_configuration(tmp_path, capsys, name):
    """V3-N6: study.yaml is checked when it is recorded at Setup, not first at step 1 of a session."""
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    folder = study / "draft"
    folder.mkdir()
    config = folder / name
    for content, reason in (("hosts: [H1, H1]\n", "duplicate host codes in 'hosts'"),
                            ("hosts: [H1]\nlevel_rule: {manual: approved}\n",
                             "level_rule.manual approved assigns manual cmmi levels 1-4, so manual_max_level must "
                             "set cmmi: 4 (it is 5, the default when it is not set)")):
        config.write_text(content, encoding="utf-8")
        assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "STUDY", "--kind", "other",
                     str(config)]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == f"error: {config} is not a valid study configuration: {reason}; nothing was recorded\n"
    assert not ledger_file.exists() and _archive_names(study) == []
    notes = folder / "notes.yaml"                       # only a file named study.yaml is checked
    notes.write_text("hosts: [H1, H1]\n", encoding="utf-8")
    config.write_text(config_template(["H1"]), encoding="utf-8")
    assert main(["ledger", "record", "--ledger", str(ledger_file), "--host", "STUDY", "--kind", "other",
                 str(config), str(notes)]) == 0
    assert len(read_ledger(ledger_file)) == 2


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
    # Changed with the sealed-path rule: record_files now refuses the second hash itself (V1-N1). A
    # ledger that holds one anyway (written before the rule, or by hand) still flags the edit.
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    worksheet = study / "worksheets" / "H1-worksheet.csv"
    ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    worksheet.write_text("edited\n", encoding="utf-8")
    with pytest.raises(StudyError, match="never changes, so nothing was recorded"):
        ledger.record_files(ledger_file, "H1", "worksheet", [worksheet])
    _append_row(ledger_file, "2099-01-01T00:00:00Z", "H1", "worksheet", "worksheets/H1-worksheet.csv",
                sha256_file(worksheet))
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


@pytest.mark.parametrize("rel, sealed", [
    ("worksheets/H1-worksheet.csv", True),
    ("outputs/H1-cmmi.json", True),
    ("register/H1-register-review.csv", True),
    ("notes/frozen-elsewhere.json", True),       # sealed by a frozen-kind row further down
    ("inputs/H1-attestation.json", False),
])
def test_a_sealed_path_is_never_superseded_whatever_its_kind(tmp_path, rel, sealed):
    """V1-N6: an edit of a sealed file recorded under a kind that is not frozen
    used to be SUPERSEDED, so verify passed."""
    study = _study(tmp_path)
    ledger_file = study / "ledger.csv"
    path = study / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("as it is now\n", encoding="utf-8")
    rows = [("2026-11-23T10:00:00Z", "STUDY", "other", rel, "first hash"),       # 0 * 64: CHANGED now
            ("2026-11-23T10:01:00Z", "STUDY", "other", path, "recorded again")]
    if rel.startswith("notes/"):
        rows.append(("2026-11-23T10:02:00Z", "STUDY", "facts", path, ""))
    _write_ledger(ledger_file, rows)
    assert ledger.row_states(ledger_file)[0].state == (ledger.CHANGED if sealed else ledger.SUPERSEDED)
    assert ledger.is_sealed_path(ledger_file, path, read_ledger(ledger_file)) is sealed


def test_withdrawal_and_seal_opening_rows_are_archived_never_superseded(tmp_path, capsys):
    """Changed (round 3; V3 found withdrawals shown as SUPERSEDED, as if they had been replaced). A withdrawal or
    seal-opening row records study.yaml as it was at that moment: once study.yaml changes, such a row is ARCHIVED
    while its ledger-archive copy still has the recorded hash (verify passes and names the row), else CHANGED, and
    it is never SUPERSEDED. Other rows are superseded as before, also by a protocol row."""
    study, config, attestation, _ = _corrections(tmp_path)
    ledger_file = study / "ledger.csv"
    old = b"hosts: [H1, H2, H3]\nthreshold: 0.80\n"
    old_sha = hashlib.sha256(old).hexdigest()
    events = [
        ("2026-11-23T09:00:00Z", "STUDY", "other", "study.yaml", "study configuration"),
        ("2026-11-23T09:01:00Z", "H3", "protocol", "study.yaml", "withdrawn: VM lost"),
        ("2026-11-23T09:02:00Z", "STUDY", "protocol", "study.yaml",
         "seal opened by register-sheet: hosts H1, H2; withdrawn: H3")]

    def write(rows):
        _write_ledger(ledger_file, rows)
        ledger_file.write_bytes(ledger_file.read_bytes().replace(b"0" * 64, old_sha.encode("ascii")))

    write(events + [
        ("2026-11-23T09:05:00Z", "STUDY", "other", config, "corrected"),
        ("2026-11-23T09:06:00Z", "H1", "input", "inputs/H1-attestation.json", "first draft"),
        ("2026-11-23T09:07:00Z", "H1", "protocol", attestation, "replaced the draft"),
        ("2026-11-23T10:10:00Z", "H1", "worksheet", study / "worksheets" / "H1-worksheet.csv", ""),
        ("2026-11-23T10:20:00Z", "H1", "tool-output", study / "outputs" / "H1-cmmi.json", ""),
    ])
    # Without the archive copy the two event rows stay CHANGED.
    assert [s.state for s in ledger.row_states(ledger_file)] == [
        ledger.SUPERSEDED, ledger.CHANGED, ledger.CHANGED, ledger.OK, ledger.SUPERSEDED, ledger.OK,
        ledger.OK, ledger.OK]
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 1
    capsys.readouterr()
    copy = study / "ledger-archive" / f"{old_sha}.yaml"         # what `ledger record` and `withdraw` keep
    copy.parent.mkdir()
    copy.write_bytes(old)
    assert [s.state for s in ledger.row_states(ledger_file)] == [
        ledger.SUPERSEDED, ledger.ARCHIVED, ledger.ARCHIVED, ledger.OK, ledger.SUPERSEDED, ledger.OK,
        ledger.OK, ledger.OK]
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[1:3] == [
        f"ARCHIVED study.yaml  (protocol)  H3 withdrawn; the file has changed since, and "
        f"ledger-archive/{old_sha}.yaml keeps the recorded copy",
        f"ARCHIVED study.yaml  (protocol)  the configuration when the seal was opened; the file has changed since, "
        f"and ledger-archive/{old_sha}.yaml keeps the recorded copy"]
    # A copy that no longer has the recorded hash does not count.
    copy.write_bytes(old + b"# edited\n")
    assert [s.state for s in ledger.row_states(ledger_file)][1:3] == [ledger.CHANGED, ledger.CHANGED]
    copy.write_bytes(old)
    # Corrected only after the first tool run: the STUDY row of study.yaml stays CHANGED, so verify fails.
    write(events + [
        ("2026-11-23T10:10:00Z", "H1", "worksheet", study / "worksheets" / "H1-worksheet.csv", ""),
        ("2026-11-23T10:20:00Z", "H1", "tool-output", study / "outputs" / "H1-cmmi.json", ""),
        ("2026-11-23T10:30:00Z", "STUDY", "other", config, "corrected too late")])
    assert [s.state for s in ledger.row_states(ledger_file)] == [
        ledger.CHANGED, ledger.ARCHIVED, ledger.ARCHIVED, ledger.OK, ledger.OK, ledger.OK]
    capsys.readouterr()
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 1


def test_a_seal_opening_row_of_a_moved_sensitivity_config_is_archived(tmp_path, capsys):
    """V1 (round 2): agreement --config study-copy.yaml records that file in its seal-opening row; moving the
    file away afterwards no longer makes verify fail, since ledger-archive keeps it."""
    study = _with_config(tmp_path)
    ledger_file = study / "ledger.csv"
    copy = study / "study-copy.yaml"
    copy.write_bytes((study / "study.yaml").read_bytes())
    status = ledger.SealStatus(hosts=["H1", "H2"], withdrawn={}, problems=[])
    ledger.record_seal_opened(ledger_file, "agreement", copy, status)
    copy.unlink()
    assert [s.state for s in ledger.row_states(ledger_file)] == [ledger.ARCHIVED]
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    capsys.readouterr()


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
    # Reworded on purpose (V1-N1): the first row's archive copy is named in the advice itself.
    assert problems["H2"] == (f"{ledger.WORKSHEET_CHANGED}: worksheets/H2-worksheet.csv; restore the original bytes "
                              f"from ledger-archive/{h2_copy} (or your commit or e-mailed copy); {ledger.NO_REHASH}")
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
    # Changed on purpose (V1-N1): the second record is refused, and the first row is binding.
    study = _with_config(tmp_path, hosts=("H1",))
    _hash_all(study, "H1")
    sheet = study / "worksheets" / "H1-worksheet.csv"
    first = read_ledger(study / "ledger.csv")[0]
    sheet.write_text("edited\n", encoding="utf-8")
    with pytest.raises(StudyError, match="nothing was recorded"):
        _hash_all(study, "H1")
    assert len(read_ledger(study / "ledger.csv")) == 1
    problems = dict(ledger.seal_status(study, study / "study.yaml").problems)
    assert problems["H1"].startswith(ledger.WORKSHEET_CHANGED)
    assert f"ledger-archive/{first.sha256}.csv (or your commit or e-mailed copy)" in problems["H1"]
    assert "different hashes" not in problems["H1"]


def test_the_first_worksheet_row_is_binding(tmp_path, capsys):
    """A ledger written before the sealed-path rule (or by hand) can hold two
    hashes for one sheet: the seal follows the first row, and the later row
    stays CHANGED in verify (agreement reports it)."""
    study = _with_config(tmp_path, hosts=("H1",))
    (study / "worksheets" / "H2-worksheet.csv").unlink()
    ledger_file = study / "ledger.csv"
    sheet = study / "worksheets" / "H1-worksheet.csv"
    original = sheet.read_bytes()
    first_sha = sha256_file(sheet)
    _write_ledger(ledger_file, [("2026-11-23T10:00:00Z", "H1", "worksheet", sheet, "")])
    sheet.write_text("edited after hashing\n", encoding="utf-8")
    _append_row(ledger_file, "2026-11-23T10:05:00Z", "H1", "worksheet", "worksheets/H1-worksheet.csv",
                sha256_file(sheet))

    # The file matches the second row only: sealed, with the first row's copy to restore from.
    status = ledger.seal_status(study, study / "study.yaml")
    assert status.problems == [("H1", f"worksheet changed after it was hashed: worksheets/H1-worksheet.csv; "
                                      f"restore the original bytes from your commit or e-mailed copy (its archive "
                                      f"copy ledger-archive/{first_sha}.csv is missing); {ledger.NO_REHASH}")]
    (study / "ledger-archive").mkdir()
    (study / "ledger-archive" / f"{first_sha}.csv").write_bytes(original)
    assert dict(ledger.seal_status(study, study / "study.yaml").problems)["H1"] == (
        f"worksheet changed after it was hashed: worksheets/H1-worksheet.csv; restore the original bytes from "
        f"ledger-archive/{first_sha}.csv (or your commit or e-mailed copy); a changed worksheet cannot be re-hashed")
    assert ledger.worksheet_problems(ledger_file, ["H1"]) == {
        "H1": "worksheet changed after it was hashed: worksheets/H1-worksheet.csv"}

    # Restored to the first row's bytes: the seal opens; verify still shows the second row.
    shutil.copyfile(str(study / "ledger-archive" / f"{first_sha}.csv"), str(sheet))
    status = ledger.seal_status(study, study / "study.yaml")
    assert status.ok and status.hosts == ["H1"]
    assert ledger.worksheets_hashed(ledger_file, ["H1"]) == {"H1": True}
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 1
    assert _lines(capsys) == ["OK      worksheets/H1-worksheet.csv  (worksheet)",
                              "CHANGED worksheets/H1-worksheet.csv  (worksheet)"]
    # Step 3 run again on the restored sheet records nothing.
    assert ledger.record_files(ledger_file, "H1", "worksheet", [sheet]) == []
    assert len(read_ledger(ledger_file)) == 2


def _setup_rows(study, hosts=("H1", "H2", "H3")):
    """study.yaml naming `hosts`, recorded at setup; returns its row."""
    config = study / "study.yaml"
    config.write_text(config_template(list(hosts)), encoding="utf-8")
    return ledger.record_files(study / "ledger.csv", "STUDY", "other", [config], note="study configuration")[0]


def test_an_unrecorded_study_yaml_edit_keeps_the_seal_closed(tmp_path):
    """V1-N2 (a), BI-01: H3 not started and with no ledger rows (decision 3
    'exclude'); dropping it from study.yaml for a moment used to open the
    seal and leave no trace."""
    study = _study(tmp_path)
    config = study / "study.yaml"
    setup = _setup_rows(study)
    _hash_all(study, "H1", "H2")
    original = config.read_bytes()
    config.write_text(config_template(["H1", "H2"]), encoding="utf-8")
    status = ledger.seal_status(study, config)
    assert not status.ok and "H3" in status.hosts
    assert status.problems[0] == (
        "STUDY", f"study.yaml changed since it was last recorded (ledger line 2, {setup.recorded_at_utc}): restore it "
                 f"from ledger-archive/{setup.sha256}.yaml or record it again; editing study.yaml never opens the seal")
    assert [host for host, _ in status.problems] == ["STUDY", "H3"]
    config.unlink()
    status = ledger.seal_status(study, StudyConfig(hosts=["H1"]))
    assert status.problems[0] == ("STUDY", f"study.yaml is missing; restore it from ledger-archive/{setup.sha256}.yaml")
    assert "H3" in status.hosts                       # read from the recorded version's archive copy
    config.write_bytes(original)
    assert [host for host, _ in ledger.seal_status(study, config).problems] == ["H3"]
    ledger.withdraw_host(study / "ledger.csv", "H3", "Windows 11 fallback")
    assert ledger.seal_status(study, config).ok


def test_a_host_list_recorded_again_after_the_first_tool_run_keeps_the_earlier_hosts(tmp_path):
    study = _study(tmp_path)
    config = study / "study.yaml"
    _setup_rows(study)
    _hash_all(study, "H1", "H2")
    ledger.record_files(study / "ledger.csv", "H1", "tool-output", [study / "outputs" / "H1-cmmi.json"])
    config.write_text(config_template(["H1", "H2"]), encoding="utf-8")
    ledger.record_files(study / "ledger.csv", "STUDY", "other", [config], note="H3 dropped")
    status = ledger.seal_status(study, config)
    assert status.hosts == ["H1", "H2", "H3"]
    assert [host for host, _ in status.problems] == ["H3"]
    assert status.problems[0][1].startswith(ledger.NO_WORKSHEET_YET)


def test_a_host_list_corrected_before_the_first_tool_run_leaves_no_trace(tmp_path):
    study = _study(tmp_path)
    config = study / "study.yaml"
    _setup_rows(study)
    config.write_text(config_template(["H1", "H2"]), encoding="utf-8")
    ledger.record_files(study / "ledger.csv", "STUDY", "other", [config], note="H3 is not in the study")
    _hash_all(study, "H1", "H2")
    status = ledger.seal_status(study, config)
    assert status.ok and status.hosts == ["H1", "H2"]
    ledger.record_files(study / "ledger.csv", "H1", "tool-output", [study / "outputs" / "H1-cmmi.json"])
    assert ledger.seal_status(study, config).ok          # the version in force at the first tool run


@pytest.mark.parametrize("damage", ["missing", "other bytes", "not a configuration"])
def test_a_recorded_study_yaml_whose_hosts_cannot_be_read_is_a_study_problem(tmp_path, damage):
    study = _study(tmp_path)
    config = study / "study.yaml"
    if damage == "not a configuration":                # record_files itself never checks a configuration
        config.write_text("hosts: [H1, H1]\n", encoding="utf-8")
        setup = ledger.record_files(study / "ledger.csv", "STUDY", "other", [config])[0]
    else:
        setup = _setup_rows(study)
    _hash_all(study, "H1", "H2")
    ledger.record_files(study / "ledger.csv", "H1", "tool-output", [study / "outputs" / "H1-cmmi.json"])
    config.write_text(config_template(["H1", "H2"]), encoding="utf-8")
    ledger.record_files(study / "ledger.csv", "STUDY", "other", [config], note="H3 dropped")
    copy = study / "ledger-archive" / f"{setup.sha256}.yaml"
    if damage == "missing":
        copy.unlink()
    elif damage == "other bytes":
        copy.write_text(config_template(["H1", "H2"]), encoding="utf-8")
    problems = ledger.seal_status(study, config).problems
    assert problems == [("STUDY", f"the hosts of study.yaml as recorded at ledger line 2 are unknown: its archive "
                                  f"copy ledger-archive/{setup.sha256}.yaml is missing or unreadable; restore "
                                  "ledger-archive from your commit")]


def test_the_seal_opens_only_the_archived_study_yaml_copies(tmp_path):
    """The seal reads the ledger, study.yaml and its recorded versions, and
    hashes the worksheets: never a tool output, and no other archived copy."""
    study = _study(tmp_path)
    config = study / "study.yaml"
    setup = _setup_rows(study)
    _hash_all(study, "H1", "H2")
    ledger.record_files(study / "ledger.csv", "H1", "tool-output", [study / "outputs" / "H1-cmmi.json"])
    config.write_text(config_template(["H1", "H2"]), encoding="utf-8")
    ledger.record_files(study / "ledger.csv", "STUDY", "other", [config], note="H3 dropped")
    opened = []
    read_bytes, read_text, real_open = Path.read_bytes, Path.read_text, open

    def spy_open(file, *args, **kwargs):
        opened.append(Path(str(file)).resolve())
        return real_open(file, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(Path, "read_bytes", lambda self: opened.append(self.resolve()) or read_bytes(self))
        patch.setattr(Path, "read_text", lambda self, *a, **k: opened.append(self.resolve()) or read_text(self, *a, **k))
        patch.setattr("builtins.open", spy_open)
        status = ledger.seal_status(study, config)
    assert "H3" in status.hosts
    allowed = {(study / name).resolve() for name in ("ledger.csv", "study.yaml", "worksheets/H1-worksheet.csv",
                                                     "worksheets/H2-worksheet.csv",
                                                     f"ledger-archive/{setup.sha256}.yaml")}
    assert set(opened) <= allowed and (study / "ledger-archive" / f"{setup.sha256}.yaml").resolve() in opened
    assert [p for p in opened if OUTPUTS_DIR in p.parts] == []


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


# ---------- seal openings and withdrawals after them ----------

def _open_seal(study, command="register-sheet"):
    status = ledger.seal_status(study, study / "study.yaml")
    assert status.ok, status.problems
    return ledger.record_seal_opened(study / "ledger.csv", command, study / "study.yaml", status)


def test_record_seal_opened_appends_one_archived_study_row(tmp_path):
    study = _with_config(tmp_path, hosts=("H1", "H2", "H3"))
    ledger_file = study / "ledger.csv"
    _hash_all(study, "H1", "H2")
    ledger.withdraw_host(ledger_file, "H3", "not assessed")
    row = _open_seal(study)
    assert ledger.SEAL_OPENED_NOTE_PREFIX == "seal opened by "
    assert (row.host_code, row.kind, row.path, row.note) == (
        "STUDY", "protocol", "study.yaml", "seal opened by register-sheet: hosts H1, H2; withdrawn: H3")
    assert row.sha256 == sha256_file(study / "study.yaml") and ledger.archive_path(ledger_file, row).is_file()
    rows = read_ledger(ledger_file)
    assert rows[-1] == row and ledger.first_seal_opening(rows) == (3, row)
    again = _open_seal(study, command="agreement")                 # every opening is a row of its own
    assert again.note == "seal opened by agreement: hosts H1, H2; withdrawn: H3"
    assert len(read_ledger(ledger_file)) == 5 and ledger.first_seal_opening(read_ledger(ledger_file)) == (3, row)
    assert main(["ledger", "verify", "--ledger", str(ledger_file)]) == 0
    closed = ledger.SealStatus(hosts=["H1"], withdrawn={}, problems=[("H1", "worksheet not hashed")])
    with pytest.raises(StudyError, match="the seal is not open"):
        ledger.record_seal_opened(ledger_file, "register-sheet", study / "study.yaml", closed)
    assert len(read_ledger(ledger_file)) == 5


def test_first_seal_opening_counts_study_rows_with_either_prefix(tmp_path):
    def row(host, note):
        return ledger.LedgerRow("2026-11-23T10:00:00Z", host, "other", "study.yaml", "0" * 64, 1, note)

    assert ledger.first_seal_opening([row("STUDY", "study configuration"), row("H1", "seal opened by me")]) is None
    forced = row("study", ledger.FORCE_NOTE_PREFIX + "dry run")
    rows = [row("STUDY", "study configuration"), forced, row("STUDY", "seal opened by register-sheet: hosts H1")]
    assert ledger.first_seal_opening(rows) == (1, forced)
    assert [ledger.is_seal_opening(r) for r in rows] == [False, True, True]


def test_withdrawing_after_the_seal_opened_needs_after_unseal(tmp_path, capsys):
    """V1-N3 (a): a withdrawal once results could be seen is a post-hoc exclusion."""
    study = _with_config(tmp_path, hosts=("H1", "H2"))
    ledger_file = study / "ledger.csv"
    _hash_all(study, "H1", "H2")
    opened = _open_seal(study)
    rows = len(read_ledger(ledger_file))
    withdraw = ["ledger", "withdraw", "--ledger", str(ledger_file), "--host", "H2", "--reason", "results looked odd"]
    assert main(withdraw) == 2
    assert capsys.readouterr().err == (
        f"error: the seal was opened at {opened.recorded_at_utc} (ledger line 4): withdrawing H2 now is a post-hoc "
        "exclusion, which agreement reports as CRITICAL; add --after-unseal to record it anyway\n")
    assert len(read_ledger(ledger_file)) == rows
    assert main(withdraw + ["--after-unseal"]) == 0
    row = read_ledger(ledger_file)[-1]
    assert (row.host_code, row.kind, row.note) == ("H2", "protocol", "withdrawn: (after the seal was opened) results "
                                                                     "looked odd")
    assert capsys.readouterr().out.splitlines()[-1] == (
        f"H2 withdrawn at {row.recorded_at_utc}: (after the seal was opened) results looked odd")
    assert ledger.withdrawn_hosts(read_ledger(ledger_file)) == {
        "H2": (row.recorded_at_utc, "(after the seal was opened) results looked odd")}


def test_after_unseal_is_refused_while_the_seal_was_never_opened(tmp_path, capsys):
    study = _with_config(tmp_path, hosts=("H1", "H2"))
    assert main(["ledger", "withdraw", "--ledger", str(study / "ledger.csv"), "--host", "H2", "--reason", "x",
                 "--after-unseal"]) == 2
    assert "the seal has not been opened" in capsys.readouterr().err
    assert not (study / "ledger.csv").exists()


def test_a_forced_unseal_counts_as_an_opening_for_withdrawals(tmp_path, capsys):
    study = _with_config(tmp_path, hosts=("H1", "H2"))
    ledger_file = study / "ledger.csv"
    forced = ledger.record_forced_unseal(ledger_file, study / "study.yaml", "dry run")
    assert (forced.host_code, forced.kind, forced.note) == (
        "STUDY", "other", "register sheets generated before every worksheet was hashed: dry run")
    with pytest.raises(StudyError, match="post-hoc exclusion"):
        ledger.withdraw_host(ledger_file, "H2", "dropped")
    assert ledger.withdraw_host(ledger_file, "H2", "dropped", after_unseal=True).note.startswith(
        "withdrawn: (after the seal was opened) ")


def test_withdrawing_a_host_whose_outputs_are_hashed_says_when(tmp_path, capsys):
    """V1-N3: the withdrawal is recorded, with a note that agreement reports it with that time."""
    study = _with_config(tmp_path, hosts=("H1", "H2", "H3"))
    ledger_file = study / "ledger.csv"
    _hash_all(study, "H1")
    output = ledger.record_files(ledger_file, "H1", "tool-output", [study / "outputs" / "H1-cmmi.json"])[0]
    assert main(["ledger", "withdraw", "--ledger", str(ledger_file), "--host", "H1", "--reason", "VM broke"]) == 0
    captured = capsys.readouterr()
    assert captured.err == (f"note: H1's tool outputs were hashed at {output.recorded_at_utc}; agreement reports this "
                            "withdrawal with that time\n")
    assert captured.out.splitlines()[-1].startswith("H1 withdrawn at ")
    assert main(["ledger", "withdraw", "--ledger", str(ledger_file), "--host", "H3", "--reason", "not assessed"]) == 0
    assert capsys.readouterr().err == ""


def test_withdraw_refuses_while_study_yaml_differs_from_its_latest_row(tmp_path, capsys):
    study = _with_config(tmp_path, hosts=("H1", "H2", "H3"))
    ledger_file = study / "ledger.csv"
    config = study / "study.yaml"
    setup = ledger.record_files(ledger_file, "STUDY", "other", [config])[0]
    config.write_text(config_template(["H1", "H2", "H3", "H4"]), encoding="utf-8")
    withdraw = ["ledger", "withdraw", "--ledger", str(ledger_file), "--host", "H3", "--reason", "dropped"]
    assert main(withdraw) == 2
    assert capsys.readouterr().err == (
        f"error: study.yaml changed since it was last recorded (ledger line 2, {setup.recorded_at_utc}): restore it "
        f"from ledger-archive/{setup.sha256}.yaml or record it again; editing study.yaml never opens the seal; "
        "record or restore study.yaml first; nothing was recorded\n")
    assert len(read_ledger(ledger_file)) == 1
    ledger.record_files(ledger_file, "STUDY", "other", [config], note="H4 added before the first session")
    assert main(withdraw) == 0


# ---------- the assessor's input files ----------

A1, A2, A3, I1, N1, X1 = ("a1" * 32, "a2" * 32, "a3" * 32, "c1" * 32, "e1" * 32, "f1" * 32)


def _inputs_ledger(study, worksheet=True):
    """H1's inputs as a ledger records them: setup, a correction before the worksheet hash, a version
    after it, and a file first recorded after it. Only the ledger is read, so no file needs to exist."""
    rows = [("2026-11-23T09:00:00Z", "STUDY", "other", "study.yaml", "0" * 64),
            ("2026-11-23T09:00:00Z", "H1", "input", "inputs/H1-attestation.json", A1),
            ("2026-11-23T09:00:00Z", "H1", "input", "inputs/H1-Inventory-Record.JSON", I1),
            ("2026-11-23T09:00:00Z", "H2", "input", "inputs/H2-attestation.json", X1),
            ("2026-11-23T09:30:00Z", "H1", "input", "inputs/H1-attestation.json", A2),
            ("2026-11-23T18:00:00Z", "H1", "worksheet", "worksheets/H1-worksheet.csv", "b" * 64),
            ("2026-11-23T18:30:00Z", "H1", "input", "inputs/H1-attestation.json", A3),
            ("2026-11-23T18:31:00Z", "H1", "input", "inputs/H1-notes.json", N1),
            ("2026-11-23T19:10:00Z", "H1", "facts", "outputs/H1-facts.json", "d" * 64)]
    if not worksheet:
        rows = [row for row in rows if row[2] != "worksheet"]
    ledger_file = study / "ledger.csv"
    with open(ledger_file, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(LEDGER_COLUMNS)
        writer.writerows([when, host, kind, rel, sha, "1", ""] for when, host, kind, rel, sha in rows)
    return ledger_file


def test_assessor_inputs_are_the_versions_recorded_before_the_first_worksheet_row(tmp_path):
    study = _study(tmp_path)
    hashed_at, inputs = ledger.assessor_inputs(_inputs_ledger(study), "H1")
    assert hashed_at == "2026-11-23T18:00:00Z"
    assert inputs == [
        ledger.AssessorInput("attestation", "inputs/H1-attestation.json", A2, 4, "2026-11-23T09:30:00Z",
                             [(6, "2026-11-23T18:30:00Z", A3)]),
        ledger.AssessorInput("inventory_record", "inputs/H1-Inventory-Record.JSON", I1, 2, "2026-11-23T09:00:00Z", []),
        ledger.AssessorInput(None, "inputs/H1-notes.json", "", -1, "", [(7, "2026-11-23T18:31:00Z", N1)]),
    ]
    hashed_at, inputs = ledger.assessor_inputs(_inputs_ledger(study, worksheet=False), "H1")
    assert hashed_at is None
    assert [(item.sha256, item.row_index, item.later) for item in inputs] == [(A3, 5, []), (I1, 2, []), (N1, 6, [])]
    assert ledger.assessor_inputs(study / "ledger.csv", "H3") == (None, [])


def _inputs(*items):
    return [ledger.AssessorInput(role, rel, sha, index, "2026-11-23T09:00:00Z", later)
            for role, rel, sha, index, later in items]


ROLE_INPUTS = _inputs(("attestation", "inputs/H1-attestation.json", A2, 4, [(6, "2026-11-23T18:30:00Z", A3)]),
                      ("inventory_record", "inputs/H1-inventory-record.json", I1, 2, []))


@pytest.mark.parametrize("given, expected", [
    ({"attestation": A2, "inventory_record": I1, "config": X1}, []),
    ({"attestation": I1, "inventory_record": A2}, [
        ("swapped", f"the attestation the tool used (sha256 {I1[:12]}...) is inputs/H1-inventory-record.json, H1's "
                    "inventory record as recorded at 2026-11-23T09:00:00Z: the two input files were swapped or mixed up"),
        ("swapped", f"the inventory record the tool used (sha256 {A2[:12]}...) is inputs/H1-attestation.json, H1's "
                    "attestation as recorded at 2026-11-23T09:00:00Z: the two input files were swapped or mixed up")]),
    ({"attestation": A2, "inventory_record": A2}, [
        ("duplicate", f"the run was given the same file (sha256 {A2[:12]}...) as --attestation and as "
                      "--inventory-record: inputs/H1-attestation.json as recorded at 2026-11-23T09:00:00Z")]),
    ({"attestation": A3, "inventory_record": I1}, [
        ("later-version", "the tool used inputs/H1-attestation.json as recorded at 2026-11-23T18:30:00Z, after H1's "
                          "worksheet was hashed at 2026-11-23T18:00:00Z; the assessor had the version recorded at "
                          "2026-11-23T09:00:00Z")]),
    ({"attestation": X1, "inventory_record": I1}, [
        ("not-recorded", f"the attestation the tool used (sha256 {X1[:12]}...) is not one of the input files recorded "
                         "for H1 in the ledger")]),
    ({"attestation": "not a hash", "inventory_record": I1}, [
        ("not-recorded", "the attestation the tool used (no valid sha256) is not one of the input files recorded for "
                         "H1 in the ledger")]),
    ({"inventory_record": I1}, [
        ("missing", "the run had no --attestation, although the ledger holds H1's attestation "
                    "inputs/H1-attestation.json")]),
    ({"attestation": "", "inventory_record": None}, [
        ("missing", "the run had no --attestation, although the ledger holds H1's attestation "
                    "inputs/H1-attestation.json"),
        ("missing", "the run had no --inventory-record, although the ledger holds H1's inventory record "
                    "inputs/H1-inventory-record.json")]),
])
def test_check_run_inputs(given, expected):
    assert ledger.check_run_inputs(given, ROLE_INPUTS, True, "H1", worksheet_at_utc="2026-11-23T18:00:00Z") == expected
    assert set(ledger.INPUT_CODES) == {"duplicate", "swapped", "later-version", "not-recorded", "role-unknown",
                                       "missing"}


def test_check_run_inputs_without_input_driven_checks_needs_no_input(tmp_path):
    assert ledger.check_run_inputs({}, ROLE_INPUTS, False, "H1") == []
    assert ledger.check_run_inputs({"attestation": A3}, ROLE_INPUTS, False, "H1") == [
        ("later-version", "the tool used inputs/H1-attestation.json as recorded at 2026-11-23T18:30:00Z, after H1's "
                          "worksheet was hashed; the assessor had the version recorded at 2026-11-23T09:00:00Z")]


def test_check_run_inputs_files_named_otherwise_keep_the_count_rule():
    inputs = _inputs(("attestation", "inputs/H1-attestation.json", A2, 1, []),
                     (None, "inputs/H1-inventory.json", I1, 2, []))
    assert ledger.input_role("inputs/H1-inventory.json") is None
    assert ledger.input_role("C:\\study\\inputs\\H1-INVENTORY-RECORD.json") == "inventory_record"
    unknown = ("role-unknown", "cannot tell whether inputs/H1-inventory.json is an attestation or an inventory record: "
                               "name it H1-attestation.json or H1-inventory-record.json")
    assert ledger.check_run_inputs({"attestation": A2, "inventory_record": I1}, inputs, True, "H1") == [unknown]
    assert ledger.check_run_inputs({"attestation": A2}, inputs, True, "H1") == [
        ("missing", "the ledger holds 2 input file(s) for H1, but the run had 1 of --attestation and "
                    "--inventory-record")]
    assert ledger.check_run_inputs({"inventory_record": I1}, inputs, True, "H1") == [
        unknown, ("missing", "the run had no --attestation, although the ledger holds H1's attestation "
                             "inputs/H1-attestation.json")]
    assert ledger.check_run_inputs({}, inputs, True, "H1") == [
        ("missing", "the run had no --attestation, although the ledger holds H1's attestation "
                    "inputs/H1-attestation.json"),
        ("missing", "the ledger holds 2 input file(s) for H1, but the run had 0 of --attestation and "
                    "--inventory-record")]


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
