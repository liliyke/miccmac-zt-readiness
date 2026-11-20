# Methodology

This document describes how the MICCMAC Zero Trust Device Readiness Toolkit
turns a set of qualitative security properties into a repeatable, comparable
score. It is intended for both users and contributors.

## 1. From MICCMAC to device readiness

Richard Bejtlich's *Defensible Network Architecture 2.0* states that a
defensible system is **Monitored, Inventoried, Controlled, Claimed, Minimized,
Assessed, and Current** -- MICCMAC. These are properties, not metrics: a system
either tends toward them or away from them.

Zero Trust Architecture (NIST SP 800-207) shifts trust decisions to a policy
engine that continuously evaluates each request. For that model to hold, the
*device* being evaluated must itself be defensible. This toolkit therefore
treats the seven MICCMAC properties as the **readiness preconditions** a device
must satisfy before it can be trusted as a participant in a Zero Trust
environment.

## 2. Structure: properties, checks, results

- A **property** is one of the seven MICCMAC letters.
- A **check** is a single, concrete, verifiable question within a property
  (for example, `MON-02: Logs forwarded to a centralized SIEM`).
- A **check result** records the outcome of one check on one device.

Each check result carries a status, a short human-readable detail, optional
evidence (command output, file path, API response identifier), and the control
references it maps to.

## 3. Check statuses

| Status | Meaning |
|---|---|
| `PASS` | The control is fully satisfied. |
| `PARTIAL` | The control is partially satisfied. |
| `FAIL` | The control is not satisfied. |
| `NOT_APPLICABLE` | The check does not apply to this device, or an organizational input it reads was not supplied. |
| `NOT_IMPLEMENTED` | Check logic has not been written yet (scaffold default), or no facts or inputs reached the check. |
| `ERROR` | The check could not be evaluated. |

An `ERROR`, and a `NOT_APPLICABLE` caused only by an organizational input that
was not supplied, get missing-data entries in the risk register (section 9);
a check that does not apply gets none.

## 4. Scoring

Numeric weights: `PASS` = 100, `PARTIAL` = 50, `FAIL` = 0, `ERROR` = 0.

`NOT_APPLICABLE` and `NOT_IMPLEMENTED` checks are **excluded** from scoring.
This is deliberate: an incomplete assessment should report "n/a", not a
misleadingly low score.

- **Property score** = mean weight of the scorable checks in that property.
- **Overall score** = mean of the property scores that could be computed.

## 5. Readiness tiers

| Overall score | Tier | Interpretation |
|---|---|---|
| 90 - 100 | Zero Trust Ready | The device meets the readiness preconditions. |
| 70 - 89 | Defensible | Broadly sound; specific gaps to close. |
| 40 - 69 | Developing | Material gaps; not yet suitable for sensitive access. |
| 0 - 39 | Not Ready | The device should not be trusted as-is. |

Thresholds are intentionally simple. Organizations may tune them in
`miccmac/engine.py` (`READINESS_TIERS`) to match their own risk appetite, and
should record any change here.

Every text/markdown scorecard render (`miccmac/report.py`) ends with a legend
reprinting this table, the MICCMAC property-letter meanings, the check-status
glyphs, and -- whenever a maturity lens is applied, which is CMMI by default
-- the methodology's own score-to-level chart, so the scorecard is
self-explanatory without this doc open alongside it.

## 6. Design choices and limitations

- **Equal property weighting.** The default treats all seven properties
  equally. An organization that considers, say, *Current* more urgent than
  *Claimed* can introduce weights; this is a documented extension point.
- **Point-in-time.** An assessment reflects the device at the moment of the
  run. Zero Trust expects continuous evaluation; schedule the toolkit
  accordingly and trend the scores over time.
- **Authorization.** Only assess devices you own or are explicitly authorized
  to evaluate. See `SECURITY.md`.

## 7. Pluggable maturity-model methodologies

The default scoring above (Section 4-5) is always computed. A maturity lens
additionally re-buckets that same flat 0-100 score into an ordinal maturity
level, without changing the flat score itself. `miccmac assess` applies CMMI
unless told otherwise: `--methodology cisa-ztmm` applies CISA's Zero Trust
Maturity Model instead, and `--methodology none` applies no lens (the flat
score and readiness tier only, as every run did before CMMI became the
default on 2026-11-20). `engine.run_assessment` itself still applies no lens
unless it is given a methodology name. Provenance records the methodology
applied (`cmmi`, `cisa-ztmm`, or null with `none`).

CMMI (5 levels) and CISA's Zero Trust Maturity Model (4 stages) have
different numbers of levels, so a level alone isn't comparable across
methodologies. Percentages are, via a **zero-anchored conversion**:

```
percentage = (level - 1) / (max_level - 1) * 100
```

Level 1 always anchors to 0%, and the top level always anchors to 100%,
regardless of how many levels the methodology defines. Both methodologies
also reuse the tool's existing 20/40/70/90 breakpoints as shared threshold
anchors (CISA's 4 stages map 1:1 onto the default readiness tiers; CMMI's
5th level bisects the bottom band at 20), which is what makes "comparable
regardless of methodology" a defensible design rather than an arbitrary one.

| CMMI level | Label | Min flat score |
|---|---|---|
| 1 | Initial | 0 |
| 2 | Managed | 20 |
| 3 | Defined | 40 |
| 4 | Quantitatively Managed | 70 |
| 5 | Optimizing | 90 |

| CISA ZTMM level | Label | Min flat score |
|---|---|---|
| 1 | Traditional | 0 |
| 2 | Initial | 40 |
| 3 | Advanced | 70 |
| 4 | Optimal | 90 |

A property or overall score of `None` (nothing scorable -- e.g. every check
in that property is still `NOT_IMPLEMENTED`) maps to `level: null,
level_label: "Unassessed"` under both methodologies, never to "Level 1": a
stub is not the same as an assessed-and-immature result.

Implementation: `miccmac/methodology.py`.

## 8. Check exclusion, custom checks, and the fairness control

A YAML config file (`miccmac assess --config path/to/config.yaml`) supports:

```yaml
excluded_checks:
  - check_id: MON-02
    reason: "No centralized SIEM in this pilot's environment."
custom_checks_dir: ./custom_checks
```

Every exclusion **requires a recorded reason** -- a bare check-id string is
rejected. Excluded checks are never silently dropped: they still appear in
the report, with status `NOT_APPLICABLE` and detail `Excluded: <reason>`,
and are removed from that property's scoring denominator the same way any
other `NOT_APPLICABLE` check is -- not counted as a pass or fail. This
prevents the scorecard from being inflated by quietly excluding checks that
would otherwise fail.

**Custom checks** are your own Python modules, one file per module, dropped
into `custom_checks_dir`. Each must define `CHECK_IDS` (a non-empty list of
new check ids), `ATTACH_TO` (one of the seven canonical property keys),
`run_checks(target, context) -> list[CheckResult]`, and `RISK_METADATA`
(a `dict[str, dict]`, one entry per id in `CHECK_IDS`, each with at least a
`cis_ig` of `IG1`/`IG2`/`IG3`). The engine merges each plugin's results into
the matching *existing* property -- there is no code path that creates an
eighth property; the seven letters spell the framework name and are fixed.
Each `CheckResult` you return carries its own `control_refs` field, which
*is* the control mapping -- no separate declaration needed. `RISK_METADATA`
is what lets a custom check plug into the risk register's prioritization the
same way a built-in check does, rather than always sorting last as
`UNRATED`; `fair_frequency`/`fair_magnitude` are optional on top of the
required `cis_ig` -- omit them and the check still gets its CIS IG shown and
used for sort-tiebreaking, but its `risk_rating` stays `UNRATED` since a
rating needs both FAIR axes. `remediation` (a recommended-fix string shown
as the register entry's "Recommended fix" line) is also optional -- omit it
and that line reads "n/a" for the check. So are `threat_source_type` (one of
adversarial, accidental, structural, environmental) and `threat_event` (a
non-empty string), the register's SP 800-30 fields (section 9); without them
those fields read "n/a (not declared)". A plugin check that cannot be
evaluated because an input it reads is absent may return `NOT_APPLICABLE`
with `missing_data=MissingData(...)` (miccmac/model.py) to get a missing-data
register entry; an `ERROR` always gets one. See
`examples/custom_checks/acme_extra_checks.py` and
`examples/miccmac-config.example.yaml` for a worked example.

**Fairness control.** When comparing the tool's automated output against a
manual/human assessment (or against a different methodology run), both sides
must score the exact same set of checks, or the comparison isn't meaningful.
`miccmac list-checks [--config path]` (or `enabled_check_ids()` in code)
deterministically prints the enabled check-id set for a given
configuration -- all built-ins minus exclusions, plus any custom checks --
so a manual scorer can be told exactly which checks to evaluate by hand.

Implementation: `miccmac/config.py`, `enabled_check_ids()` in
`miccmac/engine.py`.

## 9. Risk register: CIS IG + FAIR-inspired rating, structured after NIST SP 800-30 Rev. 1

*This section was rewritten, and the register features it describes beyond
the CIS IG/FAIR rating were drafted, with AI assistance (Claude Code,
Anthropic) for the researcher's review: missing-data entries, next-level
hints, the SP 800-30 Rev. 1 structure and the drafted threat-source types and
threat events.*

`miccmac assess --risk-register` appends a prioritized remediation view. It
is not a new scoring methodology: it enriches the results of a completed
assessment.

### Which checks get an entry

| Check result | Entry | `entry_type` |
|---|---|---|
| `FAIL`, `PARTIAL` | yes | `finding` |
| `ERROR` (any check, built-in or custom) | yes | `missing-data` |
| `NOT_APPLICABLE` because an organizational input was not supplied: no `--attestation` or `--inventory-record`, or the file has no entry for the check | yes | `missing-data` |
| `NOT_APPLICABLE` because the check does not apply (for example CUR-02 with no third-party software), or a custom check's own `NOT_APPLICABLE` | no | - |
| Excluded by the config (`NOT_APPLICABLE`, `Excluded: <reason>`) | no | - |
| `NOT_IMPLEMENTED` | no | - |
| `PASS` | no | - |

A check whose control is missing is a `FAIL` finding; a missing-data entry is
a check the tool could not evaluate. The tool tells the two kinds of
`NOT_APPLICABLE` apart without reading detail text: a check that returns
`NOT_APPLICABLE` for an input that was not supplied, or `ERROR` for a value it
cannot read, also sets a structured marker on its result
(`CheckResult.missing_data`: source `attestation`, `inventory_record` or
`facts`; problem `not-supplied`, `missing-field` or `invalid-value`; the field
read and what valid data looks like). The JSON shows the marker on the check
as `missing_data`, only when it is set. These checks set it:

| Check | Marker set when | Source / field |
|---|---|---|
| INV-01, INV-04 | no inventory record (`not-supplied`; `missing-field` when the file holds null) | `inventory_record` |
| INV-04 | `last_reviewed` is not a valid date (`ERROR`) | `inventory_record` / `last_reviewed` |
| CTL-03, CLM-01, CLM-02, CLM-03, ASM-01, ASM-02, ASM-03, CUR-03 | no attestation (`not-supplied`), or no entry for the check's key (`missing-field`) | `attestation` / the key |
| ASM-01, ASM-02 | the scan or assessment date is not a valid date (`ERROR`) | `attestation` / e.g. `vulnerability_scanning.last_scan` |
| CUR-01 (Windows) | the last update install time is not a valid timestamp (`ERROR`) | `facts` / `last_update_installed_iso` |

`not-supplied` means the option was not given at all; a file given with no
entry for the check, or holding JSON null, is `missing-field`. Detail strings
are unchanged. Some incomplete inputs stay findings, as the check logic
decides them: an attestation entry that is present with a null value, ASM-01
or ASM-02 "performed" with no date or interval (`PARTIAL`), and an inventory
record without `device_id`, `tracked` or `last_reviewed` (`FAIL`).

**Why NOT_IMPLEMENTED gets no entry.** In a built-in check it means that the
run gave the check's property no data at all (no facts for the device
checks, an empty context for Claimed and Assessed); in a custom check it marks
a placeholder. Either way it is a condition of the run, not a gap of the
device: one entry per check would add up to 26 identical "run with
--connector or --facts" rows. The text and markdown registers say instead,
in one line, how many checks are `NOT_IMPLEMENTED` and that they have no
entry. Study runs always have facts, so built-in checks never report it
there.

### Metadata

Every built-in check is tagged, in `data/control-mappings.yaml`'s `checks:`
section, with:

- **`cis_ig`** -- the lowest CIS Controls v8 Implementation Group (IG1/IG2)
  at which its closest Safeguard first appears. IG1 checks are basic cyber
  hygiene expected of every organization; IG2 checks require more
  organizational maturity to operate (centralized tooling, scheduled
  processes, identity integration). No built-in check is IG3 in this
  release -- IG3 is reserved for checks a custom plugin might add for
  organizations facing sophisticated/targeted threats.
- **`fair_frequency`** / **`fair_magnitude`** -- a simplified, *qualitative*
  LOW/MEDIUM/HIGH rating inspired by FAIR (Factor Analysis of Information
  Risk), not quantitative FAIR/Monte Carlo, which is out of scope. Frequency
  is how often the underlying failure mode is actually the thing adversaries
  exploit in the wild; magnitude is the blast radius if it is. Checks tied
  to top real-world initial-access/lateral-movement vectors (missing EDR,
  unmanaged endpoint, unrestricted local admin, no host firewall, unpatched
  software) are rated HIGH/HIGH. Administrative/record-keeping checks
  (ownership records, review cadence) are rated LOW/LOW.
- **`remediation`** -- a short recommended fix for a FAIL/PARTIAL result on
  this check (e.g. "Enroll the device in the organization's central
  configuration-management/MDM platform" for CTL-01). Required for every
  built-in check and shown as each entry's recommended fix. It is one fixed
  text per check, so for some `PARTIAL` results it does not match the gap
  (CTL-02 "no elevation path at all"; ASM-01 and ASM-02 "performed, but no
  date or interval"): a known limitation.

The `threats:` section, added in version 0.3.0 of the file, adds per check
(drafted with AI assistance and marked `review: drafted`):

- **`threat_source_type`** -- the NIST SP 800-30 Rev. 1 Appendix D type of
  threat source most likely to exploit a failure of the check: adversarial,
  accidental, structural or environmental. A judgment per check, not an
  analysis of any organization's threats.
- **`threat_event`** -- a short, generic threat event for the check, not
  threat intelligence.

The 26 drafted rows await the researcher's review in
[`docs/sp800-30-review.md`](sp800-30-review.md), which says how to confirm
them before the study's baseline freeze, or how to record the review without
touching the tool during the study. The section is read only for the risk
register: `list-checks`, an assessment without `--risk-register`, and the
study's worksheet and input checks read `checks:` alone, so a typo there
stops only register runs (before anything is collected). When present, the
section must cover every check of `checks:`.

### Rating and order

The two FAIR bands combine into an overall risk rating via a 3x3 qualitative
lookup table (deliberately a lookup, not a numeric product -- ordinal
LOW/MEDIUM/HIGH values cannot be validly multiplied):

| Frequency \\ Magnitude | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **LOW** | LOW | LOW | MODERATE |
| **MEDIUM** | LOW | MODERATE | HIGH |
| **HIGH** | MODERATE | HIGH | CRITICAL |

A missing-data entry carries its check's own ratings: those the finding would
have if the control turned out to be absent (`sp800_30.risk_basis`
`if-control-absent`). The register lists findings first, then missing-data
entries, so an unconfirmed gap never outranks a confirmed finding. Within
each group it sorts by risk rating (fix CRITICALs before HIGHs regardless of
IG), then by CIS IG as the tiebreaker within a rating band (an IG1 failure is
more foundational, expected of every organization, than an IG2 failure at the
same risk level, so it is remediated first), then by check id. A check with no
metadata entry (e.g. an unrated custom check) sorts last in its group as
`UNRATED` rather than being dropped. The order depends only on the assessment
and the metadata, never on the methodology, so the CMMI and CISA ZTMM outputs
of one run list the same entries in the same order and a `--facts` replay
reproduces it; findings keep exactly the order they had before missing-data
entries existed.

### What a missing-data entry says

Each missing-data entry has a `missing_data` object: the marker's source,
problem, field and expected value, `what` (what is missing) and
`how_to_supply` (how to supply it). For example, with no attestation:

- what: `No attestation file was given (--attestation), so CTL-03 could not be evaluated.`
- how to supply it: `Give an --attestation JSON file with the entry "identity_aware_access": {"enabled": true or false}, recording this device's facts, and run the assessment again. If this check does not apply to this device, exclude it with a reason in the --config file (excluded_checks) instead.`

The recommended response of a missing-data entry is how to supply the data,
then "If the check then fails: " and the check's fix. An `ERROR` without a
marker (a custom check) gets generic texts that point to its detail.

### Next level

With a maturity lens (CMMI unless `--methodology` names CISA ZTMM or none),
each entry states its property's level now and what fixing this check does
toward the property's next level ("fix mapped to the next maturity level").
Definitions:

- A fix means the check re-tests as `PASS` and nothing else changes. Scores
  and levels after a fix use the engine's own scoring and the methodology's
  cutoffs, so a hint agrees with what a re-test would report.
- The current level is the one the assessment reports for the property.
- The open entries of a property are its `FAIL`, `PARTIAL` and `ERROR`
  checks, taken largest score gain first (`FAIL` and `ERROR` before
  `PARTIAL`, then by check id), which gives the fewest fixes for a level.
- Hints are per property; the overall level gets none.

The `effect`, and what the text says:

| Effect | When | The text says |
|---|---|---|
| `alone` | this fix alone reaches the next level | the level reached and the score change, citing the cutoff of the level reached (a fix can jump two levels) |
| `with-others` | it does not, and every fewest set of fixes that reaches the next level includes this check | which other fixes reach it with this one (K fixes), and whether the next level can be reached without this check at all |
| `not-needed` | it does not, and a fewest set of fixes reaches the next level without this check | that the next level does not need it, which fixes reach it, and the score with this check fixed too |
| `top-level` | the property is at the methodology's top level | that there is no next level |
| `not-scored` | the check is `NOT_APPLICABLE` until its data is supplied | that it is not scored until then and its result can change the level (no arithmetic) |

Examples (real cutoffs, CMMI 20/40/70/90 and CISA ZTMM 40/70/90):

- Controlled with CTL-01 `FAIL`, CTL-02 `PARTIAL`, two `PASS` (62.5, CMMI
  level 3): CTL-01: "Fixing this check alone raises Controlled from CMMI
  level 3 (Defined) to level 4 (Quantitatively Managed): score 62.5 -> 87.5
  (level 4 needs 70)."
- Claimed with CLM-01 `FAIL`, CLM-02 `PASS`, CLM-03 `PARTIAL` (50.0): CLM-03:
  "... Fixing this check alone gives 66.7. Level 4 does not need this check:
  fixing CLM-01 reaches it (score 83.3). Together with CLM-01, this check
  gives 100.0."
- Current with three `FAIL`s and CUR-02 not applying (0.0): under CMMI each
  fix alone reaches level 2; under CISA ZTMM (stage 2 needs 40) each is
  `not-needed`, since any two of the three reach it.
- Current with CUR-03 not supplied: "Current is at CMMI level 1 (Initial)
  without this check, which is not scored until its data is supplied; its
  result can then change that level." Missing data changes the denominator:
  with CUR-03 unscored, one fix gives 50.0 instead of 33.3.

CISA's Zero Trust Maturity Model calls its levels stages, and the hints do
too. Levels and stages are this tool's score bands under CMMI or CISA ZTMM
names (section 7), not a CMMI appraisal or a CISA assessment; the top band
(CMMI level 5, CISA ZTMM stage 4) reflects one snapshot scoring 90 or more,
not sustained improvement. With `--methodology none` there is no hint.

### NIST SP 800-30 Rev. 1 structure

Each entry's `sp800_30` object arranges the register's own fields as the
risk factors of SP 800-30 Rev. 1's risk model, plus a recommended response.
Its direction, from each weakness found to a threat event that could
exploit it, resembles the vulnerability-oriented analysis approach SP 800-30
describes (section 2.3.3); it follows that approach in structure only.

| Element | Key | From | Note |
|---|---|---|---|
| Threat source (type) | `threat_source_type` | `threats:` | Appendix D type; drafted, pending review |
| Threat event | `threat_event` | `threats:` | generic per check; drafted, pending review |
| Vulnerability or predisposing condition | `vulnerability` | the finding (the check's detail, or its name when the detail is empty) | null for missing data: not determined |
| Likelihood | `likelihood` | `fair_frequency` | 3 levels, not SP 800-30's 5-level scale; not derived through SP 800-30's tables or from the device's exposure |
| Impact | `impact` | `fair_magnitude` | the same caveat |
| Risk | `risk` | `risk_rating` | this register's 3x3 matrix, not SP 800-30's risk table; `risk_basis` says whether it rates a finding or applies if the control is absent |
| Recommended response | `response` | `remediation`; for missing data, how to supply the data, then the fix | an assessment informs the response; choosing it (accept, avoid, mitigate, share or transfer) is the organization's decision, as in NIST SP 800-39 |
| (review state) | `review` | `threats:` | `drafted` or `confirmed`; null for a custom check |

What this is not: it is not an SP 800-30 risk assessment. There is no
organization-specific threat analysis, no SP 800-30 assessment scale or
table, and no quantitative estimate (FAIR/Monte Carlo or other); no SP 800-30
table is reproduced. The FAIR bands were rated for how often adversaries
exploit the failure in the wild, so on a row whose threat-source type is
accidental or structural they stand in for likelihood and impact and were
not rated for that source; the review table asks whether they fit.

### Output

Every text/markdown render of the register opens with a legend explaining
`IG1`/`IG2`/`IG3`, FAIR frequency/magnitude, the risk-rating scale, the entry
types, the SP 800-30 elements with the notes above, which threat fields are
still drafted, and the next-level hint; then the order, the "Not evaluated"
line when checks are `NOT_IMPLEMENTED`, and the entries in two groups,
findings and missing data, numbered in order (`#n`, the study's review-sheet
`entry_no`). The scorecard's legend adds, only when some check lacks an
input, that `[ N/A]` can also mean "not evaluated: an organizational input it
reads was not supplied".

In JSON, `risk_register` is a list of entries. Each keeps the original keys
in their original order (`check_id`, `property_key`, `name`, `status`,
`cis_ig`, `fair_frequency`, `fair_magnitude`, `risk_rating`, `detail`,
`remediation`) and adds four: `entry_type`, `missing_data` (null for
findings), `next_level` (null without a lens; `methodology`, `effect`,
`current_level`, `current_label`, `current_score`, `max_level`,
`target_level`, `target_label`, `target_min_score`, `score_if_fixed`,
`level_if_fixed`, `level_if_fixed_label`, `fixes_needed`, `with_check_ids`,
`fewest_fixes`, `target_reachable_without_this`, `without_check_ids`, `text`)
and `sp800_30`. An entry's `status` can now also be `ERROR` or
`NOT_APPLICABLE`: a consumer that counts entries as findings should filter on
`entry_type` (or on `status` `FAIL`/`PARTIAL`, which gives the same entries),
and should read a missing-data entry's ratings as applying if the control is
absent.

Implementation: `miccmac/risk_register.py`, `miccmac/metadata.py`.

**Provenance:** the `cis_ig`/`fair_frequency`/`fair_magnitude` values for all
26 built-in checks were assigned by the researcher (Isaac Ojeh) and reviewed
against a per-check rationale table on 2026-08-29; all 26 ratings were
confirmed as-is with no adjustments. These are qualitative judgment calls,
not derived from an external framework or SME panel beyond the researcher's
own analysis. The remediation text was not part of that review. The
`threat_source_type` and `threat_event` values were drafted with AI
assistance on 2026-11-20; their review (with the remediation text) is
pending, in docs/sp800-30-review.md.

## 10. Target connectors and real detection logic

As of this release, **all seven MICCMAC properties have real, working
detection logic** -- Monitored, Inventoried, Controlled, Claimed, Minimized,
Assessed, and Current (all 26 checks) -- proven end-to-end against a real
Ubuntu 26.04 LTS VM. This section documents the pattern used throughout, and
the real findings (and real bugs, caught and fixed) that came out of testing
against a live target rather than only synthetic fixtures.

**Connector architecture** (`miccmac/connectors/`): a connector's only job is
to collect facts about a target and return them as `context["facts"]` --
check modules never talk to a target directly. `miccmac/connectors/base.py`
defines the `Connector` protocol (`collect_facts(target, extended=False) ->
dict`; `extended=True` also collects the extended facts of section 11).
`miccmac/connectors/ssh_osquery.py` implements it: the tool runs on the
assessor's machine and SSHes out to run `osqueryi --json` against the
target, which is the realistic pattern for assessing a fleet device (vs.
requiring miccmac to be installed on every target). Enable it with
`miccmac assess <host> --connector ssh-osquery --ssh-user <user> --ssh-key
<path>`.

**Windows targets.** `miccmac/connectors/ssh_osquery_windows.py` implements
the same `Connector` protocol for Windows (OpenSSH Server + `osqueryi.exe`
over SSH, plus a couple of PowerShell one-offs for facts osquery's Windows
table set doesn't cover -- built-in-Administrator-account state and Windows
Defender Firewall profile status). Enable it with `--connector
ssh-osquery-windows`. Every check module branches internally on
`facts["os"]["platform"] == "windows"` to interpret Windows-native facts
(Windows services in place of systemd units, installed programs in place of
deb packages, Administrators-group membership in place of sudo, a sample of
registry hardening settings in place of kernel sysctls, and so on) --
same check IDs, names, and control mappings on both platforms, just a
different evidence source. Genuinely cross-platform osquery tables
(`system_info`, `listening_ports`, `certificates`) reuse the identical fact
key on both platforms, so INV-02 and CUR-04 need no platform branch at all.
Unit-tested against fake Windows facts (`tests/test_windows_checks.py`,
`tests/test_ssh_osquery_windows_connector.py`), and proven end-to-end
against **both** named Windows platforms from the project's 3-platform
scope:

- **Windows 11 Enterprise 25H2**: overall score 60.8/100, "Developing," CMMI
  Level 3/5 "Defined."
- **Windows Server 2025 Standard**: overall score 47.5/100, "Developing,"
  CMMI Level 3/5 "Defined."

All 26 checks ran with real, evidence-backed results on both -- no errors,
no stub fallbacks. Real findings from these runs:

- MON-03 (EDR/telemetry agent) PASSes on both because osqueryd itself
  registers as a running Windows service, the same way MON-03 PASSes on
  Linux via the osqueryd systemd unit.
- CUR-04 (expired certificates) legitimately FAILs on both because Windows'
  default trust store ships several long-expired legacy root CAs (e.g. the
  original VeriSign/Thawte timestamping roots) -- a real finding about the
  platform, not a bug in the check.
- CTL-02 (least privilege) PASSed on Windows 11 (built-in Administrator
  disabled by default) but legitimately FAILed on Windows Server (built-in
  Administrator enabled by default) -- a genuine difference in the two
  platforms' out-of-the-box posture, correctly distinguished by the same
  check logic on both.
- CUR-01 (OS patch cadence) PASSed on Windows 11 but FAILed on Windows
  Server because the Windows Update service (wuauserv) was not yet running
  on the freshly installed Server VM -- Server's update service starts
  on-demand rather than persistently, unlike the client SKU.

**External data, not just device facts.** Two of the four Inventoried checks
(INV-01, INV-04) are NOT derivable from the device alone -- whether a device
is tracked in an authoritative asset inventory, and when that record was
last reviewed, are facts about an *external* system (a CMDB), not something
osquery can query on the box. Rather than faking these as device checks,
they read `context["inventory_record"]` (via `--inventory-record
<path-to-json>`), and correctly report `NOT_APPLICABLE` -- not a false
`FAIL` -- when no such integration is configured. This is a deliberate
design choice, not a gap: a check should say what it can and cannot
determine, honestly.

The same pattern generalizes as **`--attestation <path-to-json>`**
(`context["attestation"]`), for organizational facts that aren't
device-observable at all -- not because there's no external record to check
against (as with `inventory_record`), but because the control is enforced
somewhere the device can't see, e.g. CTL-03 (identity-aware / conditional-
access policy), which lives in a cloud identity provider (Azure AD,
Okta, ...), not on the box. `inventory_record` and `attestation` stay
separate, purpose-named inputs rather than one generic bag, so each check's
data dependency stays self-documenting from the flag name alone.

**Backward compatibility.** Every check with real logic starts with a guard:
if `context` has no `"facts"` key at all (the default invocation, with
neither `--connector` nor `--facts`; `--facts` supplies saved facts without
a connector), it falls back to the identical `NOT_IMPLEMENTED` stub behavior.
This is why `miccmac assess <target> --methodology none` stays byte-for-byte
identical to the original Alpha scaffold's output (the output of a plain
`miccmac assess <target>` before CMMI became the default lens) -- verified by
`tests/test_golden_stub.py` against goldens captured at commit 9f1d101. The
default run adds only the CMMI lens, every value of it "Unassessed" in a stub
run.

**A real finding from live testing:** INV-02 (hardware attributes recorded)
reliably FAILs against a stock VMware VM, because osquery's `system_info`
table reads hardware vendor/model/serial from `/sys/class/dmi/id/`, which
requires root on most Linux distributions -- and the connector intentionally
does not require or request root over SSH. This is a legitimate, evidence-
backed finding (least-privilege fact collection has real coverage
trade-offs), not a bug in the check logic.

**When osquery's SQL surface doesn't cover a fact:** osquery exposes file
*metadata* (the `file` table) but not file *content*, and MON-02 (log
forwarding) needs to read whether rsyslog's config declares a remote
destination. Rather than force-fitting this into an osquery query that
doesn't exist, the connector runs one small, explicit raw shell command
(`grep` against `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf`) over the
same SSH session. This is still local, read-only fact collection within the
connector's stated job -- it's a documented, narrow exception, not a
precedent for arbitrary shell access.

**Two more real findings from live testing (Monitored):** MON-03 (EDR /
endpoint telemetry agent) legitimately PASSes because `osqueryd` -- the same
agent the connector uses to collect facts -- is itself the telemetry agent
being evaluated; this is honest, not circular, since the check verifies the
*systemd service* is enabled and running continuously, not merely that a
one-off query succeeded. MON-04 (audit policy) FAILs on a stock Ubuntu
Desktop install because `auditd` is not installed by default -- a real,
common gap, and the check currently only verifies the daemon is active, not
that its rules cover authentication/privilege/process events specifically;
deepening that check (parsing `auditctl -l` / `/etc/audit/rules.d/`) is a
natural next refinement, not required for this pass.

**Findings from live testing (Controlled):** CTL-02 (least privilege) is
checked via osquery's `shadow` table, which is readable by an unprivileged
user for the `password_status` (lock state) column specifically -- this
avoids the connector needing root just to confirm root login is disabled,
matching the least-privilege design used throughout. On the test VM, root is
locked and exactly one account holds sudo, so CTL-02 PASSes; CTL-01 (no
config-management agent) and CTL-04 (no hardening-baseline tool) both FAIL
on a stock install, which is accurate -- neither ships by default.

**Claimed is entirely external -- and that changes its stub gate.** All
three Claimed checks (business owner, system administrator, business
purpose/data classification) are organizational record-keeping facts with
no device-local signal whatsoever, so `miccmac/checks/claimed.py` reads
`context["attestation"]` exclusively and never touches `context["facts"]`.
Because of that, its fallback-to-stub gate differs from every other property
implemented so far: instead of gating on facts-presence (which would be
meaningless here), it gates on the context being entirely empty -- the true
default invocation. Any other invocation, including `--attestation` alone
with no `--connector` at all, reaches real per-check logic, each reporting
its own `NOT_APPLICABLE` if its specific attestation key is missing. This
was verified directly: `miccmac assess <target> --attestation
attestation.json` (no `--connector`) correctly PASSes all three CLM checks
from attestation data alone.

**Two real bugs caught by live-VM testing (Minimized):** the first
implementation of MIN-02 (unused/unauthorized software) matched legacy
package names as a *substring*, and `"nis"` false-positived on the unrelated
package `libunistring5` (`libu-NIS-tring5`) -- fixed to exact package-name
matching. The first implementation of MIN-03 (unused network ports) counted
every listening port regardless of bind address, and flagged loopback-only
services (`127.0.0.53` systemd-resolved, `127.0.0.1`/`::1` CUPS and chrony)
as "unexpected exposed ports" even though loopback-bound sockets aren't
reachable from the network and aren't real attack surface -- fixed by
excluding `127.0.0.0/8` and `::1` in the connector's `listening_ports`
query. Both were caught only because the check ran against a real VM, not
synthetic test fixtures -- exactly the value real-target testing is for.
MIN-04 (hardening baseline) is a genuinely nuanced real finding, not a bug:
the test VM matches 2 of 4 sampled CIS-recommended kernel parameters
(`kernel.dmesg_restrict`, `kernel.kptr_restrict` are already hardened by
Ubuntu's defaults; `fs.suid_dumpable` and `net.ipv4.conf.all.rp_filter` are
not), correctly scoring `PARTIAL` -- distinct from CTL-04, which only checks
whether a hardening *tool* is installed, not whether hardening was actually
*applied*.

**Assessed follows Claimed's pattern, for the same reason.** All three
checks -- vulnerability scanning, compliance assessment, and finding
remediation SLA tracking -- ask whether an activity was *performed on
schedule* or *is tracked over time*, which is scan-history / GRC-process
data, not a point-in-time device fact. An installed scanner agent wouldn't
even prove the schedule claim, so `miccmac/checks/assessed.py` doesn't try
-- it reads `context["attestation"]` exclusively, using the same empty-
context stub gate as Claimed. ASM-01 and ASM-02 reuse the recency-vs-policy-
interval pattern from INV-04 (`last_scan`/`last_assessment` compared against
`interval_days`), rather than duplicating a new one -- three uses of the
same shape (INV-04, ASM-01, ASM-02) confirms it's a real recurring pattern
worth keeping consistent, not coincidence.

**Current combines all three prior patterns in one property.** CUR-01
(patch cadence) and CUR-02 (third-party update cadence) are device-observable
via `systemd_units` (`apt-daily-upgrade.timer`) and the `file` table's mtime
for `/var/lib/apt/periodic/update-success-stamp` -- notably, this stayed
within osquery's own SQL surface (`file` exposes metadata), unlike MON-02's
raw-command exception. CUR-02 also introduced a third gate shape: `NOT_APPLICABLE`
when the test VM's `apt_sources` contains zero third-party repositories --
not because the data is unreachable (as with CTL-03/Claimed/Assessed), but
because the question itself doesn't apply when there's no third-party
software to have a policy for. CUR-04 (certificate expiry) is directly and
fully device-observable via osquery's `certificates` table -- no gaps, no
external data needed. CUR-03 (firmware/BIOS currency) is the one check in
this property that's irreducibly external even *with* root access: a device
can report its current firmware version, never whether that's the *latest
available* one, since there's no local oracle for that, only a vendor feed
-- so it reads `context["attestation"]`, same as CTL-03.

## 11. Reproducibility: reference date, saved facts and provenance

*This section, and the features it describes, were drafted with AI
assistance (Claude Code, Anthropic) for the researcher's review.*

Three `assess` options make a run repeatable and traceable: `--as-of`,
`--save-facts` and `--facts`. A run that uses none of them (and no
`--connector`) gives exactly the output it gave before they existed. The
`--output` safeguards (below) apply to every run.

### Reference date (`--as-of`)

Four checks compare a recorded date with "today", so without a fixed
reference the same facts can give a different verdict on a different day:

| Check | Recorded date | Policy limit |
|---|---|---|
| INV-04 | inventory record's `last_reviewed` | 90 days |
| ASM-01 | attestation's `vulnerability_scanning.last_scan` | the attestation's `interval_days` |
| ASM-02 | attestation's `compliance_assessment.last_assessment` | the attestation's `interval_days` |
| CUR-01 | last successful OS update (Linux: apt's update-success stamp; Windows: the newest hotfix install date) | 7 days (Linux), 30 days (Windows) |

`--as-of YYYY-MM-DD` (exactly that form; anything else is an error) makes
all four count days to that date instead of today. Thresholds and verdict
rules do not change. INV-04, ASM-01 and ASM-02 subtract calendar dates.
CUR-01 compares timestamps and keeps its existing arithmetic, the whole
number of days in (reference time minus last update), rounded down. For it,
the `--as-of` date stands for the last moment of that day in UTC
(23:59:59.999999). With that choice the age equals the number of UTC
calendar days between the update and the reference date, whatever the time
of day of the update: an update at 00:00 or at 23:59 UTC on 2026-11-16 is 7
days old as of 2026-11-23, and one at 23:59 UTC on 2026-11-15 is 8 days old.
Taking the start of the day instead would count an update made later in a
day as one day younger, so the verdict would depend on the time of day,
which an assessor counting calendar days before the session date would not
do. A timestamp with a UTC offset is compared as an absolute time, so its
calendar day is its UTC date.

When `--as-of` is used, the detail of each of these four results that
reports an age ends with ` (as of YYYY-MM-DD)`, so a result file shows which
reference date produced it. Without `--as-of` the four checks read the real
clock as before, and their details are unchanged. A reference date earlier
than a recorded date gives a negative age, which the existing rules count
as within policy; a replay (below) warns when `--as-of` is earlier than the
date the facts were collected, unless it is the date the facts file itself
records. With no facts and no input file there is nothing for the
reference date to feed, so `assess <target> --as-of <date>` alone gives
exactly the results of the same run without it (every check keeps its
`NOT_IMPLEMENTED` placeholder); it only adds the provenance block, which
records the date.

The `--as-of` date is the session's local date, whatever the hour. After
19:00 US Eastern (00:00 UTC) the UTC date has already moved on, so a live
run then records a `collected_at_utc` one day after its `as_of`, and an
update made that evening counts on its UTC date (it can show as `-1 day(s)
ago`, which is within policy). Ages are always counted in UTC calendar days,
so for an age within a day of a limit, compare the record's UTC date.

**CUR-04 is not affected.** Its list of expired certificates is computed on
the device when the facts are collected (osquery's `strftime('%s', 'now')`),
so `--as-of` does not move it, and a replay reports the certificates that had
expired at collection time. The extended facts below keep every
certificate's expiry date, so that a later version could judge expiry
against the reference date instead.

### Saved facts (`--save-facts`) and replay (`--facts`)

`--save-facts FILE` requires `--connector`. Before connecting, the tool
refuses a FILE that already exists (raw study data is never replaced; not
even `--overwrite` changes that) or whose folder does not exist, and checks
`--output` as described below, so a foreseeable `--output` problem (a blank
name, no `--output` and no `--stdout`, a missing folder, an existing file,
an input file, a saved facts file) stops the run before it connects or
saves facts. After collection it writes FILE in one step (a
temporary file in the same folder, then a rename) before any check runs, so
the raw facts survive a later failure; the checks then read the facts back
as written, exactly as a replay will. The file is JSON (UTF-8, indented by
2, ending in a newline), format `miccmac-facts/1`, with these keys in order:

| Key | Content |
|---|---|
| `facts_format` | `"miccmac-facts/1"` |
| `tool_version`, `tool_commit` | miccmac version, and its git commit (null when unknown) |
| `connector`, `target` | the connector used, and the target as given |
| `collected_at_utc` | when collection finished, `YYYY-MM-DDTHH:MM:SSZ` |
| `as_of` | the run's `--as-of` date, or null |
| `facts` | the facts the checks read, including `extra` (below) |

`--facts FILE` scores a saved file without connecting to anything. It
cannot be combined with `--connector` or `--save-facts`, and the file must
be a `miccmac-facts/1` file whose `facts` contain `os`; anything else is an
error. `--attestation`, `--inventory-record` and `--config` still come from
the command line, and provenance records their hashes. With no target on
the command line the file's target is used; a different target is allowed
(it only labels the report) and prints a warning. With no `--as-of`, the
replay uses the file's `as_of`, or, when that is null, the UTC date on which
the facts were collected, and prints a note naming the date. In the second
case the note also says that the live run used the real clock (it had no
`--as-of`), so its date-dependent verdicts may differ from the replay's. An
explicit `--as-of` that differs from the file's `as_of` prints a warning, and
so does one earlier than the UTC collection date, unless it equals the
file's `as_of`: replaying an evening session with its own session date (one
day before the UTC collection date) is the normal case and prints nothing.
A replay writes its report to `--output`, or prints it only with `--stdout`
(see "Report file" below). Notes and warnings go to stderr, so a JSON report
printed with `--stdout` stays parseable.

A replay repeats the checks' inputs, not the device. If the check logic, the
control mappings, the configuration or the input files change, the result
can change; that is what re-testing fixed logic relies on, and the
provenance block records the versions and hashes involved so that any
difference can be traced to its cause.

**Extended facts.** With `--save-facts` the connector also collects extended
facts, after all of its usual queries, and stores them under
`facts["extra"]`, each item either `{"ok": true, "data": ...}` or
`{"ok": false, "error": "..."}`. A failing item (non-zero exit, unparseable
output, timeout) is recorded as such and collection carries on. Every
extended command is bounded by the connector's channel timeout (15 seconds
on Linux, 20 on Windows): its output is read before its exit status is
awaited, so a command that prints nothing for that long, or reports no exit
status that long after its output ended, is recorded as a timeout instead
of stopping the run. The usual queries are unchanged: a failure in one of
them still stops the run, and unlike the extended items they are not cut off
by a timeout. Every extended item is a query or a read-only command and
requests no elevation (no `sudo` or run-as); some report a permission error
without it, which is recorded as it is. One Windows item may change state on
the target: asking the Windows Update COM object for its results
(`windows_update_results`) may start the Windows Update service (wuauserv)
on demand, as any Windows Update client can. It runs after the usual queries
and after `update_services`, so no service state in the same run's facts can
reflect it, but a second live collection from the same snapshot could;
collect live once per revert. **No check reads
`facts["extra"]` in this version.** The items are kept so that later fixes
to check logic can be re-tested from the same saved facts:

| Item | Platform | Kept for |
|---|---|---|
| `osquery_info`, `os_version_full` | both | osquery version and OS build (recorded in provenance) |
| `listening_ports_processes` | both | MIN-03: which process owns each network-reachable listener |
| `certificates_all` | both | CUR-04: every certificate's expiry date |
| `update_units`, `apt_periodic_config` | Linux | CUR-01: unattended-upgrade units and apt's periodic settings |
| `audit_rules` | Linux | MON-04: audit rule coverage (often unreadable without root) |
| `update_services`, `update_policy_registry`, `update_orchestrator_tasks`, `windows_update_results`, `hotfixes` | Windows | CUR-01: update services and their start types, update policy, scheduled update tasks, last successful search and install, the hotfix list |
| `audit_registry`, `audit_policy` | Windows | MON-04: command-line capture for process creation, subcategory policy override, the `auditpol` report (which usually needs elevation) |

Without `--save-facts` no extended facts are collected, and the commands
sent to the target are the same as before.

### Report file (`--output`)

`-o FILE` writes the report to FILE instead of stdout, and stdout then shows
only `Report written to FILE`. These checks are made before anything is read
for scoring, before any connection and before `--save-facts` writes
anything:

- A blank file name for `--output`, `--facts`, `--save-facts`,
  `--attestation`, `--inventory-record`, `--config` or `--ssh-key` is an
  error, `error: <option> needs a file name` (for example `error: --output
  needs a file name`; also for `list-checks --config`): in bash an unset
  `"$VAR"` passes an empty value, which would otherwise send the whole
  report to stdout, turn a replay into a stub run, drop the facts save, or
  drop an input file, so that the input-driven checks would run without it.
  Windows PowerShell 5.1 drops an empty variable from a native command line
  instead; the run then stops with argparse's `error: argument <option>:
  expected one argument` (or, before the target, takes the target as the
  file name and cannot read it), exit 2 in every case.
- A file name holding a line break or another control character is an
  error too (`error: <option> holds a line break or another control
  character ...`): a command wrapped inside a quoted file name when pasted
  carries one, and it would otherwise pass every check and fail only when
  the file is written, after the collection.
- A live run with `--save-facts` or `--as-of` needs an explicit target:
  with an empty `$ip` PowerShell drops the argument, and the run would
  otherwise collect from `localhost`, the researcher's own machine. Any
  live run refuses a blank target (bash passes one for an unset `"$IP"`,
  and it resolves to the machine's own addresses) and one holding a line
  break (a wrapped paste), before it connects.
- A run whose report holds study results, one with `--facts` or
  `--save-facts`, or with `--connector` and `--as-of` (the protocol's tool
  runs), needs `-o FILE` or `--stdout`. With neither it stops with `error:
  this run's report holds results, so it goes to a file: give -o FILE, or
  --stdout to print it here`. The study guide's step-5 command starts with
  `--save-facts` and `--as-of` and ends with `-o`, and its step-6 command
  starts with `--facts`, so either command cut or wrapped anywhere when
  pasted is refused before it connects, and cannot show a host's results
  on the terminal before the later hosts' blind passes (a test checks every
  cut of both lines and a line break inside every quoted file name). The
  few cuts that run (right after `assess`, inside or right after the
  target, or `assess <target> --`) print only the stub report, with no
  result and no connection. `--stdout` prints the report on
  purpose, for example in a rehearsal on synthetic data, and `--stdout`
  with `-o` is an error. Every other run (a plain run, `--connector`
  without `--as-of`, `--as-of` alone) prints as before, with or without
  `--stdout`.
- FILE's folder must exist, and FILE must not be a folder.
- FILE can never be one of the run's input files (`--attestation`,
  `--inventory-record`, `--config`, `--facts`), whatever the spelling and
  also through a hard or symbolic link, nor the `--save-facts` file.
- FILE is never a saved facts file, in any run and even with
  `--overwrite`. When FILE exists and its first 64 KiB contain both
  `"facts_format"` and `miccmac-facts/1` (through a link, its target's), the
  run stops with `error: refusing to replace FILE: it is a saved facts file
  (miccmac-facts/1), which a report must never replace`. An existing file
  that cannot be read cannot be checked, so it is refused too (`error:
  refusing to replace FILE: it cannot be read to check that it is not a
  saved facts file (<reason>)`). The check is made again just before the
  report replaces FILE.
- A study run (one with `--connector`, `--facts`, `--save-facts` or
  `--as-of`) refuses an existing FILE unless `--overwrite` is given:
  `error: refusing to replace FILE: study runs never overwrite a file; choose
  a new file name or pass --overwrite`. A plain run replaces an existing
  FILE, as it always did. `--overwrite` never lets FILE replace one of the
  run's input files or a saved facts file, and `--save-facts` never
  overwrites a file, with or without it.

The report is written whole or not at all: to a temporary file in the same
folder, flushed to disk, then renamed over FILE. On any failure the
temporary file is removed and an existing FILE is left as it was; the error
is `error: cannot write --output FILE: <reason>` (or, for a file that
appeared during the run, one of the refusals above) with exit status 2, and
after a live run with `--save-facts` it adds that the facts were saved, so
the report can be rebuilt from them with `--facts` and no new collection.
The file's bytes are the same as before these safeguards existed (UTF-8
text with the platform's line endings). A re-test of fixed logic therefore
goes to a new folder, never over the baseline outputs.

### Provenance

When `--connector`, `--facts`, `--as-of` or `--save-facts` is used, the
assessment in the JSON output gains a `provenance` block, format
`miccmac-provenance/1`. Text and markdown reports do not show it, and a run
without these options has no block. Its fields, in order:

- `provenance_format`, `tool_version`, `tool_commit` (`git rev-parse HEAD` in
  the repository that holds the miccmac package, or null), `tool_tree_clean`
  (true when `git status --porcelain --untracked-files=normal -- miccmac data`
  shows nothing: no change to a tracked file and no untracked file under
  `miccmac/` or `data/`, files that `.gitignore` ignores aside; false when it
  shows anything, null when it cannot tell). An untracked module counts
  because the recorded commit would not contain it and so could not
  reproduce the run: `git add` new files before the commit that freezes the
  tool;
- `python_version` and `platform` of the machine running the tool;
- `run_at_utc` (the real clock when the run started, never the reference
  date), `as_of`, and `as_of_source` (`cli`, `facts-file`,
  `facts-collected-date`, or null when no reference date was set);
- `methodology` (the maturity methodology applied: `cmmi` unless
  `--methodology` says otherwise, or null with `--methodology none`),
  `risk_register`, `target`;
- `facts_source` (`connector`, `facts-file` or `none`), `connector` (used by
  this run), `facts_collected_at_utc`, and `facts_file` (`path`, `sha256`,
  and `role`: `saved` or `replayed`);
- `inputs`: `attestation`, `inventory_record` and `config`, each
  `{path, sha256}` or null;
- `enabled_check_ids`, as `miccmac list-checks` prints them for the same
  configuration, and `enabled_check_ids_fingerprint`, the first 16 hex
  characters of the SHA-256 of those ids joined by commas;
- `os` (`platform`, `name` and `version` from the facts, `build` from the
  extended facts), `osquery_version` (from the extended facts), and
  `extended_facts` (whether the facts include them).

File paths are recorded exactly as given on the command line, never made
absolute, so local folder names do not end up in a shared result file.
Hashes are of the files' bytes as read.

`--attestation` and `--inventory-record` are read as JSON in UTF-8, with or
without a byte-order mark, or in UTF-16 or UTF-32, the forms Windows
PowerShell 5.1 saves (`Out-File -Encoding utf8` adds a byte-order mark; `>`
writes UTF-16); anything else, such as ANSI text with accented letters, is
an error. The recorded hash is of the bytes as read, so saving the same
content in another encoding changes it. A saved facts file must be UTF-8
without a byte-order mark, as `--save-facts` writes it.

Implementation: `miccmac/clock.py`, `miccmac/facts_file.py`,
`miccmac/provenance.py`, `miccmac/cli.py`.

## 12. Extending the toolkit

To implement a check, edit the relevant module in `miccmac/checks/` and replace
the `NOT_IMPLEMENTED` stub with real detection logic that sets `status`,
`detail`, and `evidence`. Device facts can be passed in through the `context`
dictionary so that collection logic stays separate from evaluation logic.
