# Study instruments (`miccmac_study`)

These commands support the validation study that compares a blind manual
assessment with miccmac's results on five lab hosts. They are separate from
the tool under test (`miccmac/`): they never change how a check decides its
verdict, and only `miccmac assess --connector` ever connects to a host.

They were drafted with AI assistance (Claude Code, Anthropic) for the
researcher to review and test. Every judgment in the study is the
researcher's: manual verdicts and levels, register ratings, root causes and
interpretation. No command fills those fields.

| Command | What it does |
|---|---|
| `worksheet` | Blank manual worksheet per host: check id, property, intent, control references, and the levels you may enter. No results. |
| `ledger` | `record` hashes files and keeps a copy of each in `ledger-archive\` (a worksheet is linted first; a file in `worksheets\`, `outputs\` or `register\` is hashed once, never again); `verify` re-hashes them; `status` lists what each host has; `withdraw` takes a host out of the study. |
| `health` | Checks facts files and tool outputs after a run (with `--ledger` and `--host`, against the ledger too), or input files before the study (`--inputs`: their dates, and whether they give every entry the checks read). Prints ok/PROBLEM lines only, never a result. |
| `register-sheet` | Register review sheets. Refuses until every host of the study has its worksheet hashed and unchanged, or is withdrawn. |
| `agreement` | The analysis plan's counts, rates and intervals, behind the same seal. |
| `synthetic` | A made-up study folder for testing all of the above. Never study data. |

register-sheet and agreement record each opening of the seal in the ledger
(a `seal opened by ...` row). A command that refuses prints `error: ...`
and exits 2. Where a message suggests `python -m miccmac_study ...`, type
it as `& $py -m miccmac_study ...`.

## Keep the study folder private

Keep the study folder outside this public repository, in a private,
versioned folder (for example a git repository with a private remote).
`.gitignore` ignores `study-data/` and `synthetic-study/` only as a safety
net. Keep the SSH private key outside the study folder too, for example
`$HOME\.ssh\miccmac_study_ed25519`. The layout:

    <study>/.gitattributes                "* -text": git keeps every file byte for byte
    <study>/study.yaml                    analysis settings and the decisions
    <study>/ledger.csv                    SHA-256 ledger; never edit or delete a row
    <study>/ledger-archive/               a copy of every hashed file, named by its SHA-256
    <study>/inputs/                       list-checks.json, <H>-attestation.json, <H>-inventory-record.json
    <study>/worksheets/<H>-worksheet.csv  filled worksheet, hashed before the tool run
    <study>/outputs/<H>-cmmi.json, <H>-cisa-ztmm.json, <H>-facts.json   sealed until the last worksheet is hashed
    <study>/register/<H>-register-review.csv, <H>-missed-gaps.csv
    <study>/analysis/                     agreement outputs

`ledger-archive\` also holds copies of the sealed outputs and facts. Never
open or preview a `.json` file there before unsealing, and never change
anything in it.

## Setup (once)

In a new PowerShell window. The study folder must exist and hold no study
files yet (for example a new clone of your private study repository).
Replace the parts in angle brackets.

    $repo = "<path to miccmac-zt-readiness>"; $py = "$repo\.venv\Scripts\python.exe"; $env:PYTHONPATH = $repo
    Set-Location "<study folder>"
    Set-Content -Encoding ASCII .gitattributes "* -text"
    git add .gitattributes; git commit -q -m "Keep study files byte for byte"
    New-Item -ItemType Directory -Force inputs, outputs, worksheets, register | Out-Null
    Add-Content -Encoding ASCII .gitignore "keys/", "id_*", "*_ed25519*", "*_rsa*", "*.pem", "*.ppk"
    & $py -m miccmac list-checks --format json > inputs\list-checks.json
    & $py -c "from miccmac_study.formats import config_template; open('study.yaml', 'x', encoding='utf-8').write(config_template(['H1','H2','H3','H4','H5']))"

- `.gitattributes` goes in first, committed before any study file: Git for
  Windows rewrites line endings by default, so a file restored from a commit
  or a clone would no longer match its hash.
- If a commit stops with `Author identity unknown`, set your name and
  e-mail for this repository once (`git config user.name "<your name>";
  git config user.email "<your e-mail>"`) and run the line again.
- Before unsealing, never look at the study repository with a git GUI,
  `git diff`, `git show` or `git log -p`: they display sealed outputs. Keep
  `-q` on every commit (git's summary counts their lines).
- The `.gitignore` is a safety net: no key belongs in the study folder. Push
  the repository once to its private remote (`git push -u origin <branch>`),
  so that the plain `git push` of steps 3b and 9 works.
- The last line refuses to replace an existing `study.yaml` (Python then
  ends with `FileExistsError`).
- Edit `study.yaml` for the decisions: `hosts` (decision 1),
  `secondary_methodologies` (decision 2), `level_rule` and
  `manual_max_level` (decision 4; see "Analysis defaults" below) and
  `weighted_kappa`. Leave `synthetic: false`. `ledger record` refuses a
  study.yaml that does not load, and step 3 refuses every worksheet until
  `level_rule.manual` (with `approved`, also `level_rule.overall`) is
  declared.
- Write `inputs\<H>-attestation.json` and `inputs\<H>-inventory-record.json`
  for each host (decision 3, input files for every host), with exactly these
  names: the identical-inputs check tells the two files apart by name, and
  `ledger record --kind input --host <H>` refuses any other name, another
  host's file included. The assessor gets the same files and the same check
  list.
- Save JSON and YAML as UTF-8 (in Notepad: Save as, Encoding UTF-8). The
  tools also read what PowerShell writes (`>` saves UTF-16), but the ledger
  hashes the bytes, so settle the encoding before you record a file.
  (`list-checks.json` above is UTF-16 and is fine as it is.)

Check every date and entry in the input files before the first session.
This runs the checks on the input files alone and prints only whether each
date they read is readable, and whether each file gives every entry the
checks read from it:

    & $py -m miccmac_study health --inputs --as-of 2026-11-23 (Get-ChildItem inputs\*-attestation.json, inputs\*-inventory-record.json).FullName

Use the first session's date for `--as-of`. Every line must start with
`ok`. A PROBLEM names the field and your value: fix the file and run it
again. `every entry the checks read from an attestation is given: no,
absent: <names>` names entries the file leaves out: each would leave its
check unevaluated, as a missing-data entry of the register that the H2
reviewers then judge. Add them. Only an entry left out on purpose (a
decision you record in the protocol log) is named with `--allow-missing
<name>` (repeat it for each), which turns the PROBLEM into an ok line. For
an inventory record the line names an absent `device_id`, `tracked` or
`last_reviewed`, which INV-01 or INV-04 would count against the device.
Then hash the fixed inputs:

    & $py -m miccmac_study ledger record --ledger ledger.csv --host STUDY --kind list-checks inputs\list-checks.json
    & $py -m miccmac_study ledger record --ledger ledger.csv --host STUDY --kind other --note "study configuration" study.yaml
    foreach ($h in "H1","H2","H3","H4","H5") { & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind input "inputs\$h-attestation.json" "inputs\$h-inventory-record.json" }

Each record prints `<sha256>  <path>` and the `archive copy:` it made. To
correct study.yaml before the first tool run, or an input file before step 1
of its host, edit it and record it again with the same `--kind`: `ledger
verify` then shows the earlier row as SUPERSEDED. Anything later is in "If a
hashed file changed".

If decision 3 is "exclude the 10 input-driven checks" instead:

- Write `miccmac-config.yaml` with an `excluded_checks` entry and a reason
  for each of INV-01, INV-04, CTL-03, CLM-01, CLM-02, CLM-03, ASM-01,
  ASM-02, ASM-03 and CUR-03 (the shape is in
  `examples\miccmac-config.example.yaml`). It must not set
  `custom_checks_dir`: provenance hashes the config file, not plug-in code.
- Make the check list with it and hash it; write no input files and skip
  `health --inputs`:

      & $py -m miccmac list-checks --config miccmac-config.yaml --format json > inputs\list-checks.json
      & $py -m miccmac_study ledger record --ledger ledger.csv --host STUDY --kind other --note "miccmac config (decision 3)" miccmac-config.yaml

- Per host: add `--miccmac-config miccmac-config.yaml` to step 1, add
  `--config miccmac-config.yaml` to steps 5 and 6, and leave out
  `--attestation` and `--inventory-record` there. Claimed and Assessed then
  have no enabled check: enter UNASSESSED for their levels.

Freeze the tool and these instruments before the first session (protocol
section 2). New files count, so add them before you commit:

    git -C $repo add miccmac miccmac_study data tests docs README.md pyproject.toml .gitignore
    git -C $repo commit -m "Freeze miccmac and miccmac_study for the baseline"
    git -C $repo tag "<tag name>"
    git -C $repo status --porcelain -- miccmac data miccmac_study
    git -C $repo rev-parse HEAD

The status line must print nothing. The last line prints the commit that
step 8 checks (`$commit`). The study venv uses Python 3.12; any supported
Python (3.9 or later) gives the same verdicts, including Windows CUR-01.

The tool changed on 20 November 2026: CMMI became its default maturity
lens, and the risk register gained missing-data entries, next-level hints
and fields arranged after NIST SP 800-30 Rev. 1, whose drafted threat-source
types and events await your review in `docs\sp800-30-review.md`. Confirm or
correct them before this freeze, then run the test suite and the synthetic
kit again (test checklist steps 1, 2 and 6); if the review cannot finish in
time, that file says how to keep `data\` unchanged during the study. Never
edit `miccmac\` or `data\` between this freeze and the last host's tool run.

## Per host

One session per host, in the order below. Each session is a new PowerShell
window, so start with the same line as Setup. Windows hosts use
`--connector ssh-osquery-windows` in step 5. Since 20 November CMMI is the
tool's default maturity lens; steps 5 and 6 still name `--methodology cmmi`
and `--methodology cisa-ztmm`, and must: step 6 without it would write CMMI
levels under the CISA ZTMM name (step 7 then refuses the file, and step 8
reports it).

    $repo = "<path to miccmac-zt-readiness>"; $py = "$repo\.venv\Scripts\python.exe"; $env:PYTHONPATH = $repo
    Set-Location "<study folder>"
    $h = "H1"; $ip = "192.0.2.10"; $day = "2026-11-23"   # host code, its address, the session date
    $key = "$HOME\.ssh\miccmac_study_ed25519"; $commit = "<frozen tool commit>"
    # 1. Blank worksheet
    & $py -m miccmac_study worksheet --list-checks inputs\list-checks.json --hosts $h --out worksheets --session-date $day --study-config study.yaml
    # 2. Manual pass, blind: fill the worksheet in Excel, save it as CSV UTF-8, close Excel
    # 3. Lint and hash the worksheet; from now on it never changes
    & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind worksheet "worksheets\$h-worksheet.csv"
    # 3b. Anchor the hash outside this folder (or e-mail the sheet); note the commit id or the e-mail's send time in the session log
    git add ledger.csv "worksheets\$h-worksheet.csv"; git commit -q -m "$h worksheet hashed"; git push -q; git rev-parse HEAD
    # 4. Revert the VM to its clean snapshot
    # 5. Tool run, to files only, saving the facts: one live collection per revert
    & $py -m miccmac assess $ip --save-facts "outputs\$h-facts.json" --as-of $day --connector ssh-osquery --ssh-user assessor --ssh-key $key --attestation "inputs\$h-attestation.json" --inventory-record "inputs\$h-inventory-record.json" --methodology cmmi --risk-register --format json -o "outputs\$h-cmmi.json"
    # 6. CISA ZTMM from the saved facts, with no second connection
    & $py -m miccmac assess $ip --facts "outputs\$h-facts.json" --as-of $day --attestation "inputs\$h-attestation.json" --inventory-record "inputs\$h-inventory-record.json" --methodology cisa-ztmm --risk-register --format json -o "outputs\$h-cisa-ztmm.json"
    # 7. Hash the outputs
    & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind facts "outputs\$h-facts.json"
    & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind tool-output "outputs\$h-cmmi.json" "outputs\$h-cisa-ztmm.json"
    # 8. Health: shows no results
    & $py -m miccmac_study health --expect-as-of $day --expect-commit $commit --list-checks inputs\list-checks.json --pair --ledger ledger.csv --host $h "outputs\$h-facts.json" "outputs\$h-cmmi.json" "outputs\$h-cisa-ztmm.json"
    # 9. Anchor the output hashes too (quietly: git's own summary would count lines of the sealed outputs)
    git add -A; git commit -q -m "$h outputs hashed"; git push -q

- Step 1: `--study-config` makes each level row state the levels study.yaml
  allows. A `note:` on stderr says when study.yaml declares no level rule
  yet; step 3 would then refuse the sheet.
- Step 2: a verdict per check (PASS, PARTIAL, FAIL, N/A, or UNASSESSED with
  a reason), your pass criterion, evidence steps and their source (NONE when
  no external procedure exists), the levels, `assessor` and `level_rule`.
  Later corrections go in the disagreement log, never in the sheet.
- Step 3: `ledger record` lints the sheet first: blank or unreadable
  verdicts and levels, levels outside the allowed range or not following
  the declared `level_rule` (or no rule declared), a blank pass criterion,
  evidence steps or procedure source on a check that is not UNASSESSED, a
  blank `assessor` or `level_rule`, the host code and the synthetic flag.
  On any `lint` line it records nothing: fix the sheet and run step 3
  again. Use `--force` only with a reason you can defend, and give it with
  `--note "<reason>"`: the ledger keeps it with the findings, and agreement
  reports them. Write it in the session log too. Once recorded, the sheet
  never changes: step 3 on the same bytes prints `already recorded at ...`,
  and on changed bytes it refuses, even with `--force` (see "If a hashed
  file changed"). From now on never open the hashed sheet in Excel: open a
  copy.
- Step 3b: commit the worksheet and the ledger and push them to the study
  folder's private remote, or e-mail yourself the worksheet file itself as
  an attachment, with the `<sha256>  worksheets/<H>-worksheet.csv` line
  step 3 printed in the body. A local commit alone is dated by your own
  clock; a push or an e-mail gives an outside timestamp. Do it before
  step 4.
- Step 5: one live collection per revert. If step 5 stops with an error
  after it connected (`could not SSH ...`, `cannot write --save-facts file
  ...; the facts were collected ... but not saved`, or any other error once
  the collection ran) and the message does not say the facts were saved,
  revert again (step 4) before you repeat it. An error that says `no report
  was written. The facts were saved to outputs\<H>-facts.json, so the report
  can be built from them with --facts ...` came after the facts were saved:
  do not collect again, but build the CMMI report from them with step 6's
  command, with `cmmi` in place of `cisa-ztmm` (twice). If that stops with
  the same error, write both lines in the session log and stop this host's
  session: the tool needs a fix, a protocol deviation. Keep the
  options in the guide's order: `--save-facts` and `--as-of` come first and
  `-o` last, so a line cut or wrapped anywhere when pasted is refused before
  it connects. For example: `--save-facts requires --connector`,
  `--connector ssh-osquery requires --ssh-user and --ssh-key`, `... holds a
  line break or another control character` (wrapped inside a file name),
  or, for a line that lost its `-o`, `error: this run's report holds
  results, so it goes to a file ...`. A cut right after `assess`, inside or
  right after `$ip`, or just after the first two dashes of `--save-facts`
  runs, but only prints the tool's stub report (every check `[TODO]`, every
  CMMI level `Unassessed`, the CMMI legend's score bands, no result) and
  connects nowhere. A
  `--connector` line without `--save-facts` and `--as-of` is not a study run
  and would print the host's report. An empty `$key` stops with `error:
  argument --ssh-key: expected one argument`, and an empty `$ip` with `a
  live run with --save-facts or --as-of needs the target's address`. A
  refused line needs no revert: fix it and run it. Never add `--stdout`
  here. If step 5 ends with `error: cannot write --output ...`, the message
  names the saved facts: do not collect again, but build the CMMI report
  from them with step 6's command, with `cmmi` in place of `cisa-ztmm`
  (twice).
- Step 7: `ledger record --kind tool-output` refuses an output whose
  methodology is not the one its name says (for example CMMI levels in
  `<H>-cisa-ztmm.json`, from a step-6 line that lost `--methodology
  cisa-ztmm`) and records nothing. Do not open the file: move it, unopened,
  out of `outputs\` (it was never hashed), write the refusal in the session
  log, and score the saved facts again with step 6's command and the
  methodology the file name says (`cmmi` for `<H>-cmmi.json`).
- Steps 5 and 6: study runs never overwrite a file, and `-o` never replaces
  a facts file. A repeated command is refused before anything runs
  (`error: refusing to replace ...`): choose a new file name. `--overwrite`
  is for scratch files only, never `outputs\`. A later re-test goes to a
  new folder, for example `retest-v0.2\`.
- Step 8: every line should start with `ok`. These are expected:
  - `ok ... extended facts: N of M items collected (not collected: ...)`:
    some extended items need elevation; no check reads them.
  - `ok ... methodology matches the file name (cmmi)` (and `(cisa-ztmm)`) and
    `ok      pair: methodologies differ: yes`: each output holds the
    methodology its name says.
  - With decision 3 "exclude": `PROBLEM ... inputs match the ledger for H1:
    no input rows for H1 in the ledger` on each output.
  - Only in rehearsals, before the freeze: `PROBLEM ... tool_tree_clean is true`.
  For any other PROBLEM, write the line in the session log. Do not open
  anything in `outputs\`, and do not collect again; it is examined after
  unsealing. `inputs match the ledger ...: no (...)` says what went wrong:
  the two input files swapped, the same file given twice, or a version
  recorded after the worksheet was hashed. agreement reports each as
  CRITICAL.
- Do not open anything in `outputs\` until the last worksheet is hashed.

## Evening sessions

- `$day` (`--as-of`) is the session's local date, whatever the hour.
- The tool counts ages (INV-04, ASM-01, ASM-02, CUR-01) in whole UTC
  calendar days up to the end of the session date. After 19:00 EST (00:00
  UTC) the facts record a collection time on the next UTC date, and an
  update made that evening counts on its UTC date. Step 6 with the same
  `$day` then prints no warning; only a different date does.
- In the disagreement log, a mismatch on one of these checks where the date
  is within a day of your own limit is a "missing or ambiguous fact".

## If a hashed file changed

`ledger verify` shows CHANGED, and register-sheet and agreement refuse
("stay sealed") while any worksheet differs from its first hash. Only a
byte-exact copy restores it: the `ledger-archive\` copy the message names,
a commit made with the Setup `.gitattributes`, or the attachment of step 3b
(saved over the file).

    Copy-Item ledger-archive\<sha256>.csv worksheets\H1-worksheet.csv
    & $py -m miccmac_study ledger verify --ledger ledger.csv

- `ledger verify` must show OK again.
- A file in `worksheets\`, `outputs\` or `register\` is hashed once, and
  only under its folder's own kind (worksheet; tool-output or facts;
  register-review or missed-gaps). The first kind recorded is final and
  must fit the file: a saved facts file is `facts`, a tool output
  `tool-output`, and a register sheet's kind follows its name. `ledger
  record` refuses it with changed bytes, even with `--force`, and names the
  copy to restore. A correction goes in the disagreement log or the
  protocol log, never in the file.
- Never edit or delete a ledger row. Never open a hashed CSV in Excel, which
  may save it again: open a copy.
- An input file is corrected before step 1 of its host and recorded again
  (`--kind input`). Never during its blind pass (agreement: WARNING) or
  after its worksheet is hashed: the tool must get the version recorded
  before the worksheet hash (otherwise CRITICAL).
- study.yaml:
  - Before the first tool run, a correction is in time: record it again
    with `--kind other` (SUPERSEDED).
  - Edited and not recorded again, it keeps the seal closed: restore the
    archive copy the message names, or record it.
  - After the first tool run and before the seal opens, recorded again: a
    deviation. The settings were fixed at the first tool run, so agreement
    gives a WARNING and labels a run with the changed settings a
    sensitivity run; the pre-registered analysis is the run with the
    earlier version, which the WARNING names (`--config
    ledger-archive\<sha256>.yaml`). If the hosts changed too, the WARNING
    says so: copy that file, set its `hosts` to those of the line it names,
    record the copy with `--kind other`, and pass the copy with `--config`.
    `ledger verify` shows the earlier row as CHANGED, and the hosts of the
    earlier version stay in the seal. Record the deviation in the protocol
    log.
  - A run whose configuration differs from study.yaml as it was when the
    seal first opened (study.yaml recorded again after that, or a
    `--config` with other settings or fewer hosts) is CRITICAL and labelled
    a sensitivity run. A setting put back to its value at the first tool
    run is no change. Planned sensitivity runs use the options in "After
    the last host".
  - If study.yaml was never recorded, the configuration recorded when the
    seal first opened is the reference instead (agreement still warns that
    study.yaml was never recorded).
  - Withdrawal and `seal opened by` rows record study.yaml (or the
    `--config` file) as it was then. Once that file changes or is moved,
    `ledger verify` shows them as ARCHIVED, which passes: their
    `ledger-archive\` copy keeps the recorded bytes, and the withdrawals
    still count (`ledger status`).
- Register sheets forced early (`register-sheet --force-before-unseal
  --reason TEXT`) are recorded in the ledger, and agreement reports them as
  CRITICAL.

## Withdrawing a host

A host that will not be assessed (for example under the Windows 11
fallback, decision 9) leaves the study only through a dated ledger row:

    & $py -m miccmac_study ledger withdraw --ledger ledger.csv --host H3 --reason "Windows 11 fallback: <what was decided>"

- It cannot be undone. register-sheet and agreement then leave the host
  out; agreement reports the withdrawal (time and reason) as a WARNING, with
  the time of the host's tool outputs if they were already hashed, and
  `ledger status` shows the host as WITHDRAWN.
- Do not remove the host from study.yaml, and never pass a `--config` that
  lists fewer hosts: neither opens the seal.
- Withdraw before the seal opens. Once register-sheet or agreement has
  opened it, `ledger withdraw` refuses without `--after-unseal`, and
  agreement reports a withdrawal made with it as CRITICAL (a post-hoc
  exclusion) and labels every later run a sensitivity run.
- The row records study.yaml as it is, and withdraw refuses while
  study.yaml differs from its latest ledger row. If study.yaml must still
  change before the first tool run, record it again as in Setup.

## After the last host

    & $py -m miccmac_study ledger verify --ledger ledger.csv
    & $py -m miccmac_study ledger status --ledger ledger.csv --hosts H1,H2,H3,H4,H5
    git -C $repo status --porcelain -- miccmac_study
    & $py -m miccmac_study register-sheet --study-dir .
    # fill register\<H>-register-review.csv and register\<H>-missed-gaps.csv; when a host's sheets are final:
    & $py -m miccmac_study ledger record --ledger ledger.csv --host H1 --kind register-review register\H1-register-review.csv
    & $py -m miccmac_study ledger record --ledger ledger.csv --host H1 --kind missed-gaps register\H1-missed-gaps.csv
    & $py -m miccmac_study agreement --study-dir .

- `ledger verify` must show OK, SUPERSEDED or ARCHIVED on every row, and
  no OUT OF ORDER, before you unseal (a study.yaml recorded again after the
  first tool run stays CHANGED: see "If a hashed file changed").
- The analysis code is frozen before unsealing: the `git status` line must
  print nothing (commit and tag any change first). agreement records
  `analysis_tree_clean`.
- register-sheet and agreement each append a `seal opened by ...` row
  (`ledger status` lists it as `STUDY  protocol`) on every run that opens
  the seal. A worksheet hashed after the first such row is CRITICAL, so
  every blind pass ends before the first register-sheet or agreement run.
- Review sheet: one row per register entry of the primary methodology's
  output, in the tool's order: findings (`entry_type` finding: FAIL,
  PARTIAL) first, then missing-data entries (`entry_type` missing-data: an
  ERROR, or an organizational input not supplied). A check whose control is
  missing is a finding; a missing-data entry is a check the tool could not
  evaluate. The tool's columns:
  `recommended_fix` (the action to take: the fix for a finding; for a
  missing-data entry how to supply the data, then the fix), `rating_basis`
  (`finding`, or `if the control is absent`: a missing-data entry's
  `risk_rating` is the rating the finding would get), `missing_data` and
  `how_to_supply` (missing-data entries only), `next_level` (the primary
  methodology's hint; the CISA ZTMM hints are not reviewed), and
  `threat_source_type`, `threat_event` and `sp800_30_review` (the SP 800-30
  fields, `drafted` until confirmed).
- Judge every entry, missing-data entries too, against the criteria of
  protocol section 7. Proposed criteria, to confirm there before the freeze:
  `accurate` Y/N = the row's claim is true (for a finding, its detail; for a
  missing-data entry, that the data named was missing or unreadable);
  `actionable` Y/N = `recommended_fix` can be followed as written;
  `prioritized` Y/N/UNSURE = the row's place within its group is right. The
  optional `next_level_accurate` (is the hint right?) and `threat_plausible`
  (do the drafted threat source type and event fit?) are descriptive: blank
  answers are fine, and neither ever enters H2's k. Then a one-line reason.
- Missed gaps: checks you found FAIL or PARTIAL that have no finding in the
  register (no entry at all, or only a missing-data entry, which reports no
  gap), and gaps outside the checks.
- Record each register sheet once, when it is final: like worksheets, they
  are frozen once hashed.
- `agreement` exit 0: outputs written; 3: written, with CRITICAL integrity
  problems (summary section 2); 2: nothing written. For a sensitivity run
  add `--threshold 0.75 --out analysis-t075`, or `--tool-side-rule approved
  --overall-rule pooled-checks --out analysis-rule`; the outputs record it,
  with no CRITICAL. Any other change of the configuration is CRITICAL (see
  "If a hashed file changed").
- Hand-check two or three numbers (summary section 7). Then fill in
  root_cause, action and assessor_error_note in `analysis\disagreements.csv`.
  agreement never replaces a disagreements.csv with entries, even with
  `--overwrite`: a later run goes to a new folder with `--out`.

## Analysis defaults to confirm before the freeze

Confirm each in the protocol before Sunday 22 November. Only the level rule
is set in study.yaml; any other change is a code change, made and committed
before the freeze.

- A missing or unreadable manual verdict or level counts as a disagreement.
- A tool ERROR counts as a disagreement: it never equals a manual verdict,
  and it scores 0 in the tool's levels.
- UNASSESSED checks are left out on both sides (protocol section 6).
- Every register entry must be judged (accurate and actionable both
  answered, or either one N); an entry not judged is CRITICAL (exit 3) and
  left out of n.
- Missing-data entries count in H2 like findings: `h2_unit: all-entries` in
  study.yaml (the default) tests the threshold on every entry. `h2_unit:
  findings` tests it on the findings only. agreement reports both either
  way (summary section 4.1, `register_h2.csv`), so choose the pre-registered
  unit before the freeze. An entry for a missing input is close to
  automatically accurate when the input really is missing, so the split
  matters for reading H2.
- A tool ERROR now also has a missing-data register entry (it still counts as
  a disagreement and scores 0, as above).
- The register's threat-source types and threat events are drafted with AI
  assistance: confirm them before the freeze (`docs\sp800-30-review.md`), or
  accept that the baseline outputs say `drafted`, and declare it in the
  AI-use log. H2 then judges entries that carry AI-drafted text.
- Inputs that are present but incomplete stay findings, as the checks score
  them: an attestation entry given as null, ASM-01 or ASM-02 "performed" with
  no date or `interval_days` (PARTIAL), an inventory record without
  `device_id`, `tracked` or `last_reviewed` (FAIL). The one fix per check does
  not always match a PARTIAL result (CTL-02 "no elevation path", ASM-01 and
  ASM-02 "no date or interval"): a known limitation for the actionability
  judgments.
- Prioritization rate = Y / (Y + N): UNSURE is left out of n and counted
  separately; no threshold.
- The level rule (decision 4), in study.yaml:

      level_rule:
        manual: approved          # or tool-cutoffs, or null (not declared)
        tool_side: tool-cutoffs   # or approved
        overall: pooled-checks    # or mean-of-property-ratios, step4-buckets, step4-rounded, or null

  - `manual` is the rule you use to turn your verdicts into levels. The
    lint checks every level you type against it, and refuses to hash a
    sheet until it is declared (with `approved`, `overall` too, for the
    overall levels). agreement reports a typed level that does not follow
    it (a sheet hashed with `--force`) as a WARNING, with rule_only and
    l5_rule_only blank (not counted in summary section 5.6).
    `approved` needs `manual_max_level: {cmmi: 4, cisa-ztmm: 4}`;
    `tool-cutoffs` needs `cmmi: 5`.
  - `tool_side: tool-cutoffs` compares the levels the tool reports;
    `approved` scores the tool's check statuses with the approved rule
    (levels 1-4) and needs `overall`.
  - `overall` is how an overall level comes from the approved rule:
    `mean-of-property-ratios` (its buckets on the mean of the property
    pass ratios), `pooled-checks` (on the pass ratio of all scorable
    checks), `step4-buckets` (on the mean of the Step 3 percentages) or
    `step4-rounded` (1 + the mean of (level - 1), rounded half up).
  - Option (a), `manual: approved` with `tool_side: tool-cutoffs`: the
    sides use different rules (for CMMI, manual levels 1-4 against tool
    levels 1-5), so some mismatches come from the rule alone. Summary
    sections 5.1 and 5.6 count them as "rule only", Level 5 cases included.
  - Option (b), both sides `tool-cutoffs`: one rule, but the manual side may
    assign Level 5, which the approved rule never does (needs the advisor's
    agreement in writing).
  - Option (c), both sides `approved`, with one `overall` rule: one rule,
    levels 1-4.
- Step 3 also needs, on every check that is not UNASSESSED, a pass
  criterion, evidence steps and a procedure source (NONE when no external
  procedure exists), and the sheet's `assessor` and `level_rule`. `ledger
  record` refuses a study.yaml that does not load.

## Before sharing anything

Facts files, tool outputs, worksheets, the ledger and the copies in
`ledger-archive\` hold lab details: IP addresses, hostnames, UUIDs and
hardware serials, user names (for example local administrators and sudo
users) and key paths. Redact them before anything leaves the private
folder, and never share a key. The analysis CSVs contain none of these
(host codes only).

## Thursday 19 November: test checklist (about 3 hours)

Work in scratch folders under `$env:TEMP\miccmac-check`, outside the
repository and the study folder, in a window started with the Setup line.
After the tool change of 20 November, repeat at least steps 1, 2 and 6.
The synthetic outputs show the tool's detail strings, which name its policy
limits; they describe no study host. To repeat the checklist, close Excel,
remove the old scratch folders from outside them, and start again at
step 2:

    Set-Location $HOME; Remove-Item -Recurse -Force $env:TEMP\miccmac-check

1. Tests (10 min). `Set-Location $repo; & $py -m pytest -q`: every test
   passes; a few are skipped (the opt-in live-VM tests, symlink tests
   without the Windows symlink privilege, and one POSIX-only file-mode
   test).
2. Synthetic study (20 min). Build it and run every command on it:

       & $py -m miccmac_study synthetic --out $env:TEMP\miccmac-check\synthetic
       Set-Location $env:TEMP\miccmac-check\synthetic
       & $py -m miccmac_study health --expect-as-of 2026-11-23 --list-checks inputs\list-checks.json (Get-ChildItem outputs\*.json).FullName
       foreach ($h in "H1","H2","H3","H4","H5") { & $py -m miccmac_study health --pair --ledger ledger.csv --host $h "outputs\$h-facts.json" "outputs\$h-cmmi.json" "outputs\$h-cisa-ztmm.json" }
       & $py -m miccmac_study health --inputs --as-of 2026-11-23 --allow-missing firmware_currency (Get-ChildItem inputs\*-attestation.json, inputs\*-inventory-record.json).FullName
       & $py -m miccmac_study ledger verify --ledger ledger.csv
       & $py -m miccmac_study ledger status --ledger ledger.csv --hosts H1,H2,H3,H4,H5

   Then paste the second line `synthetic` printed: it runs agreement, exit
   0. Until the tool is committed, health reports `PROBLEM ...
   tool_tree_clean is true` and agreement WARNINGs about the tool's tree and
   the analysis code; nothing else is a PROBLEM or CRITICAL. H2's facts
   show `(not collected: audit_policy)` on an ok line, as a Windows host
   without elevation would. The kit's H3 attestation leaves
   `firmware_currency` out on purpose, hence `--allow-missing
   firmware_currency` (its ok line names it): H3's register has a CUR-03
   missing-data row, and summary section 4.1 counts it. The `STUDY
   protocol` row of `ledger status` is register-sheet's seal opening while
   the kit was built.
3. Blank worksheet (10 min). Open `blank-worksheets\H1-worksheet.csv` in
   Excel. Confirm it shows no results, thresholds, queries or level cutoffs:
   only check ids, properties, intents, control references, the
   instructions, and levels 1-4.
4. Seal and byte-exact copies (20 min). Copy the folder, change one verdict
   in the copy's `worksheets\H1-worksheet.csv` and save it:

       Copy-Item -Recurse $env:TEMP\miccmac-check\synthetic $env:TEMP\miccmac-check\seal
       Set-Location $env:TEMP\miccmac-check\seal
       & $py -m miccmac_study register-sheet --study-dir .
       & $py -m miccmac_study ledger verify --ledger ledger.csv
       & $py -m miccmac_study agreement --study-dir . --out analysis-seal

   register-sheet and agreement must refuse ("stay sealed", exit 2) and
   name the archive copy; verify shows CHANGED. Restore the sheet as in
   "If a hashed file changed": verify shows OK again. Then check that a
   commit made with the Setup `.gitattributes` gives a facts file back byte
   for byte (git in this scratch folder only); the last line must print
   `True`:

       New-Item -ItemType Directory $env:TEMP\miccmac-check\git-check | Out-Null; Set-Location $env:TEMP\miccmac-check\git-check
       git init -q; git config user.name check; git config user.email check@example.invalid
       Set-Content -Encoding ASCII .gitattributes "* -text"; git add .gitattributes; git commit -q -m "byte for byte"
       Copy-Item $env:TEMP\miccmac-check\synthetic\outputs\H1-facts.json .; git add H1-facts.json; git commit -q -m "facts"
       Remove-Item H1-facts.json; git checkout -- H1-facts.json
       (Get-FileHash H1-facts.json).Hash -eq (Get-FileHash $env:TEMP\miccmac-check\synthetic\outputs\H1-facts.json).Hash

5. `--as-of` (10 min). `tests\test_as_of.py` checks INV-04, ASM-01, ASM-02 and
   CUR-01 under fixed dates. To see it, in the synthetic folder (H1 is a
   "current" host), with `--stdout` to print the report on purpose:

       Set-Location $env:TEMP\miccmac-check\synthetic
       foreach ($d in "2026-11-23", "2027-06-11") { & $py -m miccmac assess --facts outputs/H1-facts.json --attestation inputs/H1-attestation.json --inventory-record inputs/H1-inventory-record.json --as-of $d --format markdown --stdout | Select-String "INV-04|ASM-01|ASM-02|CUR-01" }

   The four lines go from PASS to FAIL, with new day counts and `(as of ...)`.
   The second run warns that the date differs from the one in the facts file.
6. Replay (10 min). Score H1 again from its facts, then compare, ignoring
   `run_at_utc`. Keep the forward slashes: provenance records paths as typed.
   The replay goes to a scratch file, so `--overwrite` lets you repeat it.

       & $py -m miccmac assess --facts outputs/H1-facts.json --attestation inputs/H1-attestation.json --inventory-record inputs/H1-inventory-record.json --methodology cmmi --risk-register --format json --as-of 2026-11-23 -o $env:TEMP\miccmac-check\replay.json --overwrite
       & $py -c "import json,sys; a,b=[json.load(open(p,encoding='utf-8')) for p in sys.argv[1:]]; [d['assessment']['provenance'].pop('run_at_utc') for d in (a,b)]; print('same' if a==b else 'DIFFERENT')" outputs/H1-cmmi.json $env:TEMP\miccmac-check\replay.json

   Then run the first line without its last three words (`-o`, the file,
   `--overwrite`): as a step-5 or step-6 line that lost its `-o`, it must
   stop with `error: this run's report holds results, so it goes to a file
   ...` and print nothing else.
7. Hand-check (30 min), in `analysis\SYNTHETIC-summary.md`:
   - Wilson: redo the worked example in section 7 with z = 1.959964 (4 of 5 gives 0.3755 to 0.9638).
   - Chance baseline (section 5.5): 13 of the 25 pairs of 5 x 5 levels are
     within one step (0.52), and 10 of 16 for 4 x 4 (shown as 5/8 = 0.6250).
     With `manual_max_level` 4 for CMMI the table pairs 5 tool levels with 4
     manual levels: 11 of 20 (0.55).
   - Recount: in `SYNTHETIC-host_levels.csv` keep methodology cmmi and scope overall;
     k = rows with within_one yes, n = rows with yes or no. Compare with
     `SYNTHETIC-agreement_h1.csv` and section 3.
8. Extended facts (5 min). `--save-facts` also keeps, under `facts.extra`:
   on both platforms `osquery_info`, `os_version_full`, `listening_ports_processes`
   and `certificates_all`; on Linux `update_units`, `apt_periodic_config` and
   `audit_rules`; on Windows `update_services`, `update_policy_registry`,
   `update_orchestrator_tasks`, `windows_update_results`, `hotfixes`,
   `audit_registry` and `audit_policy`. No check reads them yet. Whether the
   later CUR-01 / MON-04 re-test uses them is your decision.
9. Rehearsal (45 min). Setup, two hosts and a planned withdrawal in a FAKE
   three-host study, following Setup and Per host exactly in a new window,
   with only these changes:
   - Folder: `New-Item -ItemType Directory $env:TEMP\miccmac-check\fake-study`
     first. Skip the git lines (the folder is not a git repository), the
     freeze, and Per host's steps 3b and 9.
   - In every window, also set `$syn = "$env:TEMP\miccmac-check\synthetic"`.
   - study.yaml: `hosts: [H1, H2, H3]`, `secondary_methodologies:
     [cisa-ztmm]`, `manual_max_level: {cmmi: 4, cisa-ztmm: 4}`, and under
     `level_rule` `manual: approved` and `overall: pooled-checks`
     (`tool_side` stays `tool-cutoffs`). Use `"H1","H2","H3"` in the
     `foreach` lines.
   - Inputs: copy the synthetic ones (their `"synthetic": true` key is read
     by no check): `Copy-Item "$syn\inputs\H1-*.json", "$syn\inputs\H2-*.json", "$syn\inputs\H3-*.json" inputs\`
   - Per host, for H1 and H2 only: `$day = "2026-11-23"` and
     `$commit = git -C $repo rev-parse HEAD`.
   - Step 2: fake values. First type one level that does not follow your
     `level_rule`: step 3 must refuse with a `lint` line and record nothing.
     Correct it and run step 3 again.
   - Step 5, no live run: copy the synthetic facts and score them with
     step 6's command for cmmi, a few seconds after step 3 (the ledger and
     the run times are to the second, and a tie is reported). The warning
     that the target differs is expected (the facts name synthetic-H1).

         Copy-Item "$syn\outputs\$h-facts.json" outputs\
         & $py -m miccmac assess $ip --facts "outputs\$h-facts.json" --as-of $day --attestation "inputs\$h-attestation.json" --inventory-record "inputs\$h-inventory-record.json" --methodology cmmi --risk-register --format json -o "outputs\$h-cmmi.json"

   - Step 6: run it twice; the second run must be refused (`refusing to replace`).
   - Step 8: no PROBLEM line, except `tool_tree_clean` while the tool has
     uncommitted changes; H2's extended facts show `(not collected:
     audit_policy)`.
   - H3 is not assessed: withdraw it as in "Withdrawing a host", with
     `--reason "rehearsal: Windows 11 fallback"`.
   - Then "After the last host" with `--hosts H1,H2,H3` and fake review
     entries (the `git status` line lists files while the instruments have
     uncommitted changes).
     `ledger status` shows H3 as WITHDRAWN. agreement exits 3 with a
     synthetic CRITICAL per host, because the copied facts name the
     synthetic connector (expected here, never on study data), and reports
     H3's withdrawal as a WARNING. For the same reason every analysis file
     is named `SYNTHETIC-...`: fill in `analysis\SYNTHETIC-disagreements.csv`.
   - `$day` is the kit's session date: the kit dates its facts on that day
     at 12:00 UTC, so that they follow your fake worksheet hashes. From 23
     November on they no longer do (step 8: `worksheet hashed before this
     run: no`; agreement: `facts collected before the worksheet was
     hashed`, CRITICAL). Then build the kit in step 2 with `--session-date`
     set to a later day, for example `--session-date 2026-12-15`, and use
     that day wherever steps 2 to 10 say 2026-11-23 (in step 5, with a
     second date about 200 days later).
10. Seal and post-unseal checks (20 min), on copies of the fake study. Drop
    H2's worksheet row: register-sheet and agreement must refuse ("stay
    sealed", naming H2), although the seal was opened before.

        Copy-Item -Recurse $env:TEMP\miccmac-check\fake-study $env:TEMP\miccmac-check\fake-seal
        Set-Location $env:TEMP\miccmac-check\fake-seal
        (Get-Content ledger.csv) | Where-Object { $_ -notlike "*worksheets/H2-worksheet.csv*" } | Set-Content -Encoding UTF8 ledger.csv
        & $py -m miccmac_study register-sheet --study-dir .
        & $py -m miccmac_study agreement --study-dir . --out analysis-seal

    Then change one verdict in `worksheets\H1-worksheet.csv` there, save it,
    and run step 3 for H1 again. It must refuse and name the archive copy:
    restore the sheet from it as in "If a hashed file changed".

        & $py -m miccmac_study ledger record --ledger ledger.csv --host H1 --kind worksheet worksheets\H1-worksheet.csv

    A withdrawal after the seal opened is refused, then recorded with
    `--after-unseal`, and agreement reports it as CRITICAL (a post-hoc
    exclusion). A configuration with another threshold is a CRITICAL,
    labelled sensitivity run. Both agreement runs exit 3; each
    `Select-String` line must find its CRITICAL:

        Copy-Item -Recurse $env:TEMP\miccmac-check\fake-study $env:TEMP\miccmac-check\fake-late
        Set-Location $env:TEMP\miccmac-check\fake-late
        & $py -m miccmac_study ledger withdraw --ledger ledger.csv --host H2 --reason "rehearsal: results looked odd"
        & $py -m miccmac_study ledger withdraw --ledger ledger.csv --host H2 --reason "rehearsal: results looked odd" --after-unseal
        & $py -m miccmac_study agreement --study-dir . --out analysis-late
        Select-String "a post-hoc exclusion; the pre-registered analysis includes" analysis-late\SYNTHETIC-summary.md
        Set-Location $env:TEMP\miccmac-check\fake-study
        (Get-Content study.yaml) -replace '^threshold: .*', 'threshold: 0.60' | Set-Content -Encoding UTF8 study-t060.yaml
        & $py -m miccmac_study agreement --study-dir . --config study-t060.yaml --out analysis-t060
        Select-String "this run is a sensitivity run" analysis-t060\SYNTHETIC-summary.md

11. Log every issue (5 min): the command, what you expected, what happened.
    Fix it or record a decision before the first session.

## Dry run

The synthetic study replaces a dry run on a clone of a study host. Such a
dry run would show that host's results before its blind pass. An optional
live smoke test is acceptable only on a VM that is not one of the five study
hosts; keep its files out of the study folder and its ledger.

## Analysis outputs

In `analysis\` (prefixed `SYNTHETIC-` for synthetic data, which also gets a banner):

- `summary.md`: run information (with a sensitivity-run row that lists every override and configuration difference), integrity checks, H1, H2, secondary measures and a hand-check guide.
- `summary.json`: the same content for programs, plus each pooled row's per-host (k, n) clusters, the ledger rows that are not OK, and what makes a run a sensitivity run (`config.overrides`, `config.config_differences` against `config.config_reference`, and `config.post_hoc_exclusions`).
- `host_levels.csv`: per host, methodology and scope: tool level (reported, used), manual level, difference, exact, within-one, Level 5 rule flag, rule_only flag, note.
- `agreement_h1.csv`: per methodology, scope and measure: k, n, rate, Wilson interval; threshold and result on within-one rows.
- `pooled.csv`: pooled host x property agreement per methodology, measure and subset, with Wilson and host-bootstrap intervals and the number of hosts resampled (boot_hosts).
- `check_verdicts.csv`: per host and check: group (device or input), tool status, manual verdict, compared, agree, note.
- `check_agreement.csv`: verdict agreement for device-observable, input-driven and all checks: k, n, rate, Wilson interval, host-bootstrap interval (boot_*), Cohen's kappa and kappa_note.
- `confusion_levels_<methodology>.csv`: counts of tool level against manual level over host x property pairs, with manual_unassessed and manual_missing columns.
- `confusion_verdicts.csv`: counts of tool status against manual verdict over compared checks.
- `register_h2.csv`: per host and TOTAL: entries, judged, not_judged, accurate Y, actionable Y, k, n, rate, Wilson interval (TOTAL row: threshold result and host-bootstrap interval), prioritized Y/N/UNSURE, prioritization k/n, rate and Wilson interval, missed gaps; then the same H2 counts for findings (with their rate and Wilson interval, and on the TOTAL row their threshold result and bootstrap interval) and for missing-data entries, the optional next_level_accurate and threat_plausible Y/N counts, and on the TOTAL row h2_unit, which says which threshold result is the pre-registered test.
- `disagreements.csv`: every exact level mismatch and verdict mismatch, with rule_only, and blank root_cause, action and assessor_error_note.
