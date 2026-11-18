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
| `ledger` | `record` hashes files and keeps a copy of each in `ledger-archive\` (a worksheet is linted first); `verify` re-hashes them; `status` lists what each host has; `withdraw` takes a host out of the study. |
| `health` | Checks facts files and tool outputs after a run (with `--ledger` and `--host`, against the ledger too), or input files before the study (`--inputs`). Prints ok/PROBLEM lines only, never a result. |
| `register-sheet` | Register review sheets. Refuses until every host of the study has its worksheet hashed and unchanged, or is withdrawn. |
| `agreement` | The analysis plan's counts, rates and intervals, behind the same seal. |
| `synthetic` | A made-up study folder for testing all of the above. Never study data. |

A command that refuses prints `error: ...` and exits 2. Where a message
suggests `python -m miccmac_study ...`, type it as
`& $py -m miccmac_study ...`.

## Keep the study folder private

Keep the study folder outside this public repository, in a private,
versioned folder (for example a git repository with a private remote).
`.gitignore` ignores `study-data/` and `synthetic-study/` only as a safety
net. Keep the SSH private key outside the study folder too, for example
`$HOME\.ssh\miccmac_study_ed25519`. The layout:

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
    New-Item -ItemType Directory -Force inputs, outputs, worksheets, register | Out-Null
    Add-Content -Encoding ASCII .gitignore "keys/", "id_*", "*_ed25519*", "*_rsa*", "*.pem", "*.ppk"
    & $py -m miccmac list-checks --format json > inputs\list-checks.json
    & $py -c "from miccmac_study.formats import config_template; open('study.yaml', 'x', encoding='utf-8').write(config_template(['H1','H2','H3','H4','H5']))"

- The `.gitignore` is a safety net: no key belongs in the study folder. If
  the folder is a git repository, push it once to its private remote
  (`git push -u origin <branch>`), so that the plain `git push` of steps 3b
  and 9 works.
- The last line refuses to replace an existing `study.yaml` (Python then
  ends with `FileExistsError`).
- Edit `study.yaml` for the decisions: `hosts` (decision 1),
  `secondary_methodologies` (decision 2), `level_rule` and
  `manual_max_level` (decision 4; see "Analysis defaults" below) and
  `weighted_kappa`. Leave `synthetic: false`.
- Write `inputs\<H>-attestation.json` and `inputs\<H>-inventory-record.json`
  for each host (decision 3, input files for every host). The assessor gets
  the same files and the same check list.
- Save JSON and YAML as UTF-8 (in Notepad: Save as, Encoding UTF-8). The
  tools also read what PowerShell writes (`>` saves UTF-16), but the ledger
  hashes the bytes, so settle the encoding before you record a file.
  (`list-checks.json` above is UTF-16 and is fine as it is.)

Check every date in the input files before the first session. This runs the
checks on the input files alone and prints only whether each date they read
is readable:

    & $py -m miccmac_study health --inputs --as-of 2026-11-23 (Get-ChildItem inputs\*-attestation.json, inputs\*-inventory-record.json).FullName

Use the first session's date for `--as-of`. Every line must start with
`ok`. A PROBLEM names the field and your value: fix the file and run it
again. Then hash the fixed inputs:

    & $py -m miccmac_study ledger record --ledger ledger.csv --host STUDY --kind list-checks inputs\list-checks.json
    & $py -m miccmac_study ledger record --ledger ledger.csv --host STUDY --kind other --note "study configuration" study.yaml
    foreach ($h in "H1","H2","H3","H4","H5") { & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind input "inputs\$h-attestation.json" "inputs\$h-inventory-record.json" }

Each record prints `<sha256>  <path>` and the `archive copy:` it made. To
correct study.yaml or an input file before the first tool run, edit it and
record it again with the same `--kind`: `ledger verify` then shows the
earlier row as SUPERSEDED. From the first tool run on, study.yaml is fixed.

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

## Per host

One session per host, in the order below. Each session is a new PowerShell
window, so start with the same line as Setup. Windows hosts use
`--connector ssh-osquery-windows` in step 5.

    $repo = "<path to miccmac-zt-readiness>"; $py = "$repo\.venv\Scripts\python.exe"; $env:PYTHONPATH = $repo
    Set-Location "<study folder>"
    $h = "H1"; $ip = "192.0.2.10"; $day = "2026-11-23"   # host code, its address, the session date
    $key = "$HOME\.ssh\miccmac_study_ed25519"; $commit = "<frozen tool commit>"
    # 1. Blank worksheet
    & $py -m miccmac_study worksheet --list-checks inputs\list-checks.json --hosts $h --out worksheets --session-date $day --study-config study.yaml
    # 2. Manual pass, blind: fill the worksheet in Excel, save it as CSV UTF-8, close Excel
    # 3. Lint and hash the worksheet; from now on it never changes
    & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind worksheet "worksheets\$h-worksheet.csv"
    # 3b. Anchor the hash outside this folder; note the commit id or the e-mail's send time in the session log
    git add ledger.csv "worksheets\$h-worksheet.csv"; git commit -q -m "$h worksheet hashed"; git push -q; git rev-parse HEAD
    # 4. Revert the VM to its clean snapshot
    # 5. Tool run, to files only, saving the facts: one live collection per revert
    & $py -m miccmac assess $ip --connector ssh-osquery --ssh-user assessor --ssh-key $key --attestation "inputs\$h-attestation.json" --inventory-record "inputs\$h-inventory-record.json" --methodology cmmi --risk-register --format json -o "outputs\$h-cmmi.json" --as-of $day --save-facts "outputs\$h-facts.json"
    # 6. CISA ZTMM from the saved facts, with no second connection
    & $py -m miccmac assess $ip --facts "outputs\$h-facts.json" --attestation "inputs\$h-attestation.json" --inventory-record "inputs\$h-inventory-record.json" --methodology cisa-ztmm --risk-register --format json -o "outputs\$h-cisa-ztmm.json" --as-of $day
    # 7. Hash the outputs
    & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind facts "outputs\$h-facts.json"
    & $py -m miccmac_study ledger record --ledger ledger.csv --host $h --kind tool-output "outputs\$h-cmmi.json" "outputs\$h-cisa-ztmm.json"
    # 8. Health: shows no results
    & $py -m miccmac_study health --expect-as-of $day --expect-commit $commit --list-checks inputs\list-checks.json --pair --ledger ledger.csv --host $h "outputs\$h-facts.json" "outputs\$h-cmmi.json" "outputs\$h-cisa-ztmm.json"
    # 9. Anchor the output hashes too (quietly: git's own summary would count lines of the sealed outputs)
    git add -A; git commit -q -m "$h outputs hashed"; git push -q

- Step 1: `--study-config` makes each level row state the levels study.yaml
  allows.
- Step 2: a verdict per check (PASS, PARTIAL, FAIL, N/A, or UNASSESSED with
  a reason), your pass criterion, evidence steps and their source (NONE when
  no external procedure exists), the levels, `assessor` and `level_rule`.
  Later corrections go in the disagreement log, never in the sheet.
- Step 3: `ledger record` lints the sheet first: blank or unreadable
  verdicts and levels, levels outside the allowed range or not following
  your `level_rule.manual`, the host code and the synthetic flag. On any
  `lint` line it records nothing: fix the sheet and run step 3 again. Use
  `--force` only with a reason you can defend; the ledger note then lists
  the findings. From now on never open the hashed sheet in Excel: open a copy.
- Step 3b: commit the worksheet and the ledger and push them to the study
  folder's private remote, or e-mail yourself the
  `<sha256>  worksheets/<H>-worksheet.csv` line step 3 printed. A local
  commit alone is dated by your own clock; a push or an e-mail gives an
  outside timestamp. Do it before step 4. Keep `-q` on every commit while
  outputs are sealed (git's summary counts their lines).
- Step 5: one live collection per revert. If step 5 stops with an error and
  wrote no facts file, revert again (step 4) before you repeat it. If it
  ends with `error: cannot write --output ...`, the message names the saved
  facts: do not collect again, but build the CMMI report from them with
  step 6's command, with `cmmi` in place of `cisa-ztmm` (twice).
- Steps 5 and 6: study runs never overwrite a file. A repeated command is
  refused before anything runs (`error: refusing to replace ...`): choose a
  new file name. `--overwrite` is for scratch files only, never `outputs\`.
  A later re-test goes to a new folder, for example `retest-v0.2\`.
- Step 8: every line should start with `ok`. These are expected:
  - `ok ... extended facts: N of M items collected (not collected: ...)`:
    some extended items need elevation; no check reads them.
  - With decision 3 "exclude": `PROBLEM ... inputs match the ledger for H1:
    no input rows for H1 in the ledger` on each output.
  - Only in rehearsals, before the freeze: `PROBLEM ... tool_tree_clean is true`.
  For any other PROBLEM, write the line in the session log. Do not open
  anything in `outputs\`, and do not collect again; it is examined after
  unsealing.
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
("stay sealed") while any worksheet differs from its hash. Restore the exact
bytes. The refusal names the archived copy, for example
`(archived copy: ledger-archive/<sha256>.csv)`:

    Copy-Item ledger-archive\<sha256>.csv worksheets\H1-worksheet.csv
    & $py -m miccmac_study ledger verify --ledger ledger.csv

- Or restore it from your commit or the e-mailed copy. `ledger verify` must
  show OK again.
- Never edit or delete a ledger row. Never record a changed worksheet
  again: a new row does not clear the old one.
- study.yaml or an input file corrected on purpose in time (study.yaml
  before the first tool run, an input before that host's worksheet is
  hashed) is recorded again with the same `--kind`, as in Setup. A later
  change stays CHANGED: record it as a deviation in the protocol log.
- Never open a hashed CSV in Excel, which may save it again: open a copy.
- Register sheets forced early (`register-sheet --force-before-unseal
  --reason TEXT`) are recorded in the ledger, and agreement reports them as
  CRITICAL.

## Withdrawing a host

A host that will not be assessed (for example under the Windows 11
fallback, decision 9) leaves the study only through a dated ledger row:

    & $py -m miccmac_study ledger withdraw --ledger ledger.csv --host H3 --reason "Windows 11 fallback: <what was decided>"

- It cannot be undone. register-sheet and agreement then leave the host
  out; agreement reports the withdrawal (time and reason) as a WARNING, and
  `ledger status` shows the host as WITHDRAWN.
- Do not remove the host from study.yaml, and never pass a `--config` that
  lists fewer hosts: neither opens the seal.
- The row records study.yaml as it is, so withdraw once study.yaml is
  final. If it must still change before the first tool run, record it again
  with `--kind other` and once more with `--kind protocol`.

## After the last host

    & $py -m miccmac_study ledger verify --ledger ledger.csv
    & $py -m miccmac_study ledger status --ledger ledger.csv --hosts H1,H2,H3,H4,H5
    git -C $repo status --porcelain -- miccmac_study
    & $py -m miccmac_study register-sheet --study-dir .
    # fill register\<H>-register-review.csv and register\<H>-missed-gaps.csv; when a host's sheets are final:
    & $py -m miccmac_study ledger record --ledger ledger.csv --host H1 --kind register-review register\H1-register-review.csv
    & $py -m miccmac_study ledger record --ledger ledger.csv --host H1 --kind missed-gaps register\H1-missed-gaps.csv
    & $py -m miccmac_study agreement --study-dir .

- `ledger verify` must show OK or SUPERSEDED on every row, and no
  OUT OF ORDER, before you unseal.
- The analysis code is frozen before unsealing: the `git status` line must
  print nothing (commit and tag any change first). agreement records
  `analysis_tree_clean`.
- Review sheet: accurate Y/N, actionable Y/N, prioritized Y/N/UNSURE, a
  one-line reason. Judge every entry. Missed gaps: gaps found manually that
  have no entry.
- Record each register sheet once, when it is final: like worksheets, they
  are frozen once hashed.
- `agreement` exit 0: outputs written; 3: written, with CRITICAL integrity
  problems (summary section 2); 2: nothing written. For a sensitivity run
  add `--threshold 0.75 --out analysis-t075`, or `--tool-side-rule approved
  --overall-rule pooled-checks --out analysis-rule`; the outputs record it.
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
- Prioritization rate = Y / (Y + N): UNSURE is left out of n and counted
  separately; no threshold.
- The level rule (decision 4), in study.yaml:

      level_rule:
        manual: approved          # or tool-cutoffs, or null (not declared)
        tool_side: tool-cutoffs   # or approved
        overall: pooled-checks    # or mean-of-property-ratios, step4-buckets, step4-rounded, or null

  - `manual` is the rule you use to turn your verdicts into levels; the
    lint checks every level you type against it. `approved` needs
    `manual_max_level: {cmmi: 4, cisa-ztmm: 4}`; `tool-cutoffs` needs `cmmi: 5`.
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
The synthetic outputs show the tool's detail strings, which name its policy
limits; they describe no study host.

1. Tests (10 min). `Set-Location $repo; & $py -m pytest -q`: every test
   passes; a few are skipped (the opt-in live-VM tests, and symlink tests
   without the Windows symlink privilege).
2. Synthetic study (20 min). Build it and run every command on it:

       & $py -m miccmac_study synthetic --out $env:TEMP\miccmac-check\synthetic
       Set-Location $env:TEMP\miccmac-check\synthetic
       & $py -m miccmac_study health --expect-as-of 2026-11-23 --list-checks inputs\list-checks.json (Get-ChildItem outputs\*.json).FullName
       foreach ($h in "H1","H2","H3","H4","H5") { & $py -m miccmac_study health --pair --ledger ledger.csv --host $h "outputs\$h-facts.json" "outputs\$h-cmmi.json" "outputs\$h-cisa-ztmm.json" }
       & $py -m miccmac_study health --inputs --as-of 2026-11-23 (Get-ChildItem inputs\*-attestation.json, inputs\*-inventory-record.json).FullName
       & $py -m miccmac_study ledger verify --ledger ledger.csv
       & $py -m miccmac_study ledger status --ledger ledger.csv --hosts H1,H2,H3,H4,H5

   Then paste the second line `synthetic` printed: it runs agreement, exit
   0. Until the tool is committed, health reports `PROBLEM ...
   tool_tree_clean is true` and agreement WARNINGs about the tool's tree and
   the analysis code; nothing else is a PROBLEM or CRITICAL. H2's facts
   show `(not collected: audit_policy)` on an ok line, as a Windows host
   without elevation would.
3. Blank worksheet (10 min). Open `blank-worksheets\H1-worksheet.csv` in
   Excel. Confirm it shows no results, thresholds, queries or level cutoffs:
   only check ids, properties, intents, control references, the
   instructions, and levels 1-4.
4. Seal (15 min). Copy the folder, change one verdict in the copy's
   `worksheets\H1-worksheet.csv` and save it:

       Copy-Item -Recurse $env:TEMP\miccmac-check\synthetic $env:TEMP\miccmac-check\seal
       Set-Location $env:TEMP\miccmac-check\seal
       & $py -m miccmac_study register-sheet --study-dir .
       & $py -m miccmac_study ledger verify --ledger ledger.csv
       & $py -m miccmac_study agreement --study-dir . --out analysis-seal

   register-sheet and agreement must refuse ("stay sealed", exit 2) and
   name the archived copy; verify shows CHANGED. Restore the sheet as in
   "If a hashed file changed": verify shows OK again.
5. `--as-of` (15 min). `tests\test_as_of.py` checks INV-04, ASM-01, ASM-02 and
   CUR-01 under fixed dates. To see it, in the synthetic folder (H1 is a "current" host):

       Set-Location $env:TEMP\miccmac-check\synthetic
       foreach ($d in "2026-11-23", "2027-06-11") { & $py -m miccmac assess --facts outputs/H1-facts.json --attestation inputs/H1-attestation.json --inventory-record inputs/H1-inventory-record.json --as-of $d --format markdown | Select-String "INV-04|ASM-01|ASM-02|CUR-01" }

   The four lines go from PASS to FAIL, with new day counts and `(as of ...)`.
   The second run warns that the date differs from the one in the facts file.
6. Replay (10 min). Score H1 again from its facts, then compare, ignoring
   `run_at_utc`. Keep the forward slashes: provenance records paths as typed.
   The replay goes to a scratch file, so `--overwrite` lets you repeat it.

       & $py -m miccmac assess --facts outputs/H1-facts.json --attestation inputs/H1-attestation.json --inventory-record inputs/H1-inventory-record.json --methodology cmmi --risk-register --format json --as-of 2026-11-23 -o $env:TEMP\miccmac-check\replay.json --overwrite
       & $py -c "import json,sys; a,b=[json.load(open(p,encoding='utf-8')) for p in sys.argv[1:]]; [d['assessment']['provenance'].pop('run_at_utc') for d in (a,b)]; print('same' if a==b else 'DIFFERENT')" outputs/H1-cmmi.json $env:TEMP\miccmac-check\replay.json

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
9. Rehearsal (45 min). Setup and two hosts in a FAKE study folder,
   following Setup and Per host exactly in a new window, with only these
   changes:
   - Folder: `New-Item -ItemType Directory $env:TEMP\miccmac-check\fake-study`
     first. In study.yaml `hosts: [H1, H2]` and `synthetic: false`; use
     `"H1","H2"` in the `foreach` lines.
   - In every window, also set `$syn = "$env:TEMP\miccmac-check\synthetic"`.
   - Inputs: copy the synthetic ones (their `"synthetic": true` key is read
     by no check): `Copy-Item "$syn\inputs\H1-*.json", "$syn\inputs\H2-*.json" inputs\`
   - Skip the freeze. Per host: `$day = "2026-11-23"` (the synthetic facts'
     date) and `$commit = git -C $repo rev-parse HEAD`; skip the git lines
     of Per host (its steps 3b and 9).
   - Step 2: fake values. First type one level that does not follow your
     `level_rule`: step 3 must refuse with a `lint` line and record nothing.
     Correct it and run step 3 again.
   - Step 5, no live run: copy the synthetic facts and score them with
     step 6's command for cmmi. The warning that the target differs is
     expected (the facts name synthetic-H1).

         Copy-Item "$syn\outputs\$h-facts.json" outputs\
         & $py -m miccmac assess $ip --facts "outputs\$h-facts.json" --attestation "inputs\$h-attestation.json" --inventory-record "inputs\$h-inventory-record.json" --methodology cmmi --risk-register --format json -o "outputs\$h-cmmi.json" --as-of $day

   - Step 6: run it twice; the second run must be refused (`refusing to replace`).
   - Step 8: only the `tool_tree_clean` PROBLEM lines; H2's extended facts
     show `(not collected: audit_policy)`.
   - Then "After the last host" with `--hosts H1,H2` and fake review
     entries (the `git status` line lists files until the freeze).
     agreement exits 3 with a synthetic CRITICAL per host, because the
     copied facts name the synthetic connector: expected here, never on
     study data.
10. Seal without the synthetic flag (15 min). On a copy of the fake study,
    drop H2's worksheet row; register-sheet and agreement must refuse
    ("stay sealed", naming H2), also with a configuration listing only H1:

        Copy-Item -Recurse $env:TEMP\miccmac-check\fake-study $env:TEMP\miccmac-check\fake-seal
        Set-Location $env:TEMP\miccmac-check\fake-seal
        (Get-Content ledger.csv) | Where-Object { $_ -notlike "*worksheets/H2-worksheet.csv*" } | Set-Content -Encoding UTF8 ledger.csv
        (Get-Content study.yaml) -replace '^hosts: .*', 'hosts: [H1]' | Set-Content -Encoding UTF8 study-h1.yaml
        & $py -m miccmac_study register-sheet --study-dir .
        & $py -m miccmac_study register-sheet --study-dir . --config study-h1.yaml
        & $py -m miccmac_study agreement --study-dir . --out analysis-seal
        & $py -m miccmac_study agreement --study-dir . --config study-h1.yaml --out analysis-seal

    Then rehearse a withdrawal on the same copy: after the command below,
    `ledger status` shows H2 as WITHDRAWN, and agreement runs (exit 3 here,
    from the copied facts) and lists H2 under "Withdrawn hosts".

        & $py -m miccmac_study ledger withdraw --ledger ledger.csv --host H2 --reason "rehearsal: Windows 11 fallback"
        & $py -m miccmac_study ledger status --ledger ledger.csv --hosts H1,H2
        & $py -m miccmac_study agreement --study-dir . --out analysis-withdrawn

11. Log every issue (10 min): the command, what you expected, what happened.
    Fix it or record a decision before the first session.

## Dry run

The synthetic study replaces a dry run on a clone of a study host. Such a
dry run would show that host's results before its blind pass. An optional
live smoke test is acceptable only on a VM that is not one of the five study
hosts; keep its files out of the study folder and its ledger.

## Analysis outputs

In `analysis\` (prefixed `SYNTHETIC-` for synthetic data, which also gets a banner):

- `summary.md`: run information, integrity checks, H1, H2, secondary measures and a hand-check guide.
- `summary.json`: the same content for programs, plus each pooled row's per-host (k, n) clusters and the ledger rows that are not OK.
- `host_levels.csv`: per host, methodology and scope: tool level (reported, used), manual level, difference, exact, within-one, Level 5 rule flag, rule_only flag, note.
- `agreement_h1.csv`: per methodology, scope and measure: k, n, rate, Wilson interval; threshold and result on within-one rows.
- `pooled.csv`: pooled host x property agreement per methodology, measure and subset, with Wilson and host-bootstrap intervals and the number of hosts resampled (boot_hosts).
- `check_verdicts.csv`: per host and check: group (device or input), tool status, manual verdict, compared, agree, note.
- `check_agreement.csv`: verdict agreement for device-observable, input-driven and all checks: k, n, rate, Wilson interval, host-bootstrap interval (boot_*), Cohen's kappa and kappa_note.
- `confusion_levels_<methodology>.csv`: counts of tool level against manual level over host x property pairs, with manual_unassessed and manual_missing columns.
- `confusion_verdicts.csv`: counts of tool status against manual verdict over compared checks.
- `register_h2.csv`: per host and TOTAL: entries, judged, not_judged, accurate Y, actionable Y, k, n, rate, Wilson interval (TOTAL row: threshold result and host-bootstrap interval), prioritized Y/N/UNSURE, prioritization k/n, rate and Wilson interval, missed gaps.
- `disagreements.csv`: every exact level mismatch and verdict mismatch, with rule_only, and blank root_cause, action and assessor_error_note.
