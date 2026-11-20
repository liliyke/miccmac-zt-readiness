# MICCMAC Zero Trust Device Readiness Toolkit

> An open-source toolkit for measuring whether a device is *ready* to participate
> in a Zero Trust Architecture, based on Richard Bejtlich's MICCMAC properties
> of a defensible system.

![status: alpha](https://img.shields.io/badge/status-alpha-orange)
![license: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![python: 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)

<!-- After the first release, add a Zenodo DOI badge here. See "Citing this work". -->

## Why this exists

Zero Trust Architecture assumes no implicit trust and verifies every request.
But a device cannot safely participate in a Zero Trust environment unless the
device itself is defensible. A laptop that is unmonitored, unpatched, and
unowned does not become trustworthy because a policy engine sits in front of it.

This toolkit makes "device readiness" measurable. It evaluates a device against
the seven MICCMAC properties of a defensible system and produces a Zero Trust
readiness scorecard, with control mappings and remediation guidance for each
finding.

## Background

**MICCMAC** is the set of seven properties of a defensible system described in
Richard Bejtlich's *Defensible Network Architecture 2.0*: a defensible system
is **M**onitored, **I**nventoried, **C**ontrolled, **C**laimed, **M**inimized,
**A**ssessed, and **C**urrent.

This toolkit operationalizes those properties as a practical, measurable
device-readiness framework for Zero Trust Architecture, as described in:

> Ojeh, I. (2025). *Getting Devices Ready for Zero Trust Architecture by
> Complying with Richard Bejtlich's MICCMAC Framework.* Proceedings of the
> 24th European Conference on Cyber Warfare and Security (ECCWS 2025).
> https://doi.org/10.34190/eccws.24.1.3531

The MICCMAC properties are the original work of Richard Bejtlich. This toolkit
is an independent implementation and Zero Trust extension; it is **not**
affiliated with or endorsed by Mr. Bejtlich.

## The seven properties

| Letter | Property | The question it answers |
|---|---|---|
| M | Monitored | Is the device's security-relevant activity logged and watched? |
| I | Inventoried | Is the device known and tracked in an authoritative inventory? |
| C | Controlled | Is configuration and access centrally governed by enforced policy? |
| C | Claimed | Does the device have an accountable owner, admin, and purpose? |
| M | Minimized | Is the attack surface reduced to what the device actually needs? |
| A | Assessed | Is the device regularly assessed for vulnerabilities and weakness? |
| C | Current | Is the device patched, updated, and free of expired crypto material? |

Each property is mapped to NIST SP 800-207 (Zero Trust Architecture),
NIST SP 800-53 Rev 5, and CIS Controls v8 in
[`data/control-mappings.yaml`](data/control-mappings.yaml).

## Installation

Requires Python 3.9 or newer. Besides the standard library, the toolkit needs
PyYAML (control mappings and config files) and paramiko (the SSH
connectors); `pip install -e .` installs both.

```bash
git clone https://github.com/liliyke/miccmac-zt-readiness.git
cd miccmac-zt-readiness
python -m pip install -e .
```

## Usage

```bash
# Assess a device and print a text report
miccmac assess my-laptop-01

# Or run without installing
python -m miccmac assess my-laptop-01

# Markdown or JSON output
miccmac assess my-laptop-01 --format markdown
miccmac assess my-laptop-01 --format json

# Write the report to a file
miccmac assess my-laptop-01 --format markdown --output reports/my-laptop-01.md

# Every assessment also shows CMMI maturity levels (the default lens); choose
# CISA's Zero Trust Maturity Model instead, or no maturity lens at all
miccmac assess my-laptop-01 --methodology cisa-ztmm
miccmac assess my-laptop-01 --methodology none

# Exclude built-in checks / add your own via a config file (see
# examples/miccmac-config.example.yaml and examples/custom_checks/)
miccmac assess my-laptop-01 --config my-config.yaml

# Append the risk register: findings and missing-data entries with a CIS
# Implementation Group + FAIR-inspired rating, next-level hints, and the
# fields arranged after NIST SP 800-30 Rev. 1
miccmac assess my-laptop-01 --risk-register

# Print the exact enabled check-id set for a configuration -- the "fairness
# control" for comparing automated output against a manual assessment
miccmac list-checks --config my-config.yaml
```

Pluggable scoring methodologies, check exclusion/custom checks, and the risk
register are documented in full, including the scoring tables and rationale,
in [`docs/methodology.md`](docs/methodology.md).

The risk register lists one entry per `FAIL` or `PARTIAL` check (a finding)
and one per check the tool could not evaluate because data was missing (an
`ERROR`, or an organizational input that was not supplied), saying what is
missing and how to supply it. Each entry gives the check's CIS IG and
FAIR-inspired rating, a hint at what fixing it does toward the property's
next maturity level, and its fields arranged as the risk factors of NIST SP
800-30 Rev. 1 plus a recommended response. That arrangement is not an SP
800-30 risk assessment, and no rating is quantitative. The threat-source
types and threat events it shows were drafted with AI assistance and await
the researcher's review ([`docs/sp800-30-review.md`](docs/sp800-30-review.md)).

### Reproducible study runs

- `--as-of YYYY-MM-DD` sets the reference date that the date-dependent checks
  (INV-04, ASM-01, ASM-02, CUR-01) count days against, instead of today, so
  the same facts give the same verdicts whenever the run happens. Ages are
  whole UTC calendar days up to the end of that date: a recorded timestamp
  counts on its UTC date, so an update made at 20:00 US Eastern on
  2026-11-15 (01:00 UTC on 2026-11-16) is 7 days old as of 2026-11-23, not 8.
- `--save-facts FILE` (with `--connector`) saves the facts the connector
  collected, plus extended facts kept for later re-tests, before the checks
  run. It never overwrites an existing file.
- `--facts FILE` scores saved facts again without connecting to the target,
  for example under a second methodology, or after a fix to check logic.

Any of these flags, or `--connector`, adds a `provenance` block to the JSON
output (tool version and commit, input-file hashes, reference date, facts
source, enabled check ids), and makes the run a study run for `-o`: it never
replaces an existing `-o` file unless `--overwrite` is given (a plain run
replaces it, as before). In every run, `-o` must name a file in a folder
that exists and can never be one of the run's input files, nor a saved facts
file (an existing file whose first 64 KiB hold `"facts_format"` and
`miccmac-facts/1`), not even with `--overwrite`; the report is written whole
or not at all, and stdout shows only `Report written to <path>`.

A run with `--facts` or `--save-facts`, or with `--connector` and `--as-of`,
holds study results, so it never prints its report by accident: it needs
`-o FILE`, and stops otherwise (`error: this run's report holds results, so
it goes to a file: give -o FILE, or --stdout to print it here`). `--stdout`
prints such a report on purpose, for example in a rehearsal on synthetic
data, and cannot be combined with `-o`. Every other run (a plain run,
`--connector` without `--as-of`, `--as-of` alone) prints as before, so the
study guide puts `--save-facts` and `--as-of` before `--connector`: a copy
of its command cut short anywhere is then refused before it connects. A
blank value for `-o`, `--facts`, `--save-facts`, `--attestation`,
`--inventory-record`, `--config` or `--ssh-key` (as bash passes for an unset
`"$VAR"`) is an error (`error: <option> needs a file name`), so an input
file never silently drops out of a run. Windows PowerShell drops an empty
variable from the command line instead, so the run stops with argparse's
`error: argument <option>: expected one argument`. A file name holding a
line break (a command wrapped when pasted) is an error too, and a live run
with `--save-facts` or `--as-of` needs an explicit target: it never falls
back to `localhost`. No live run accepts a blank target or one holding a
line break.

Collect once and score against CMMI, then score CISA ZTMM from the same
saved facts with no second collection. Study commands always name
`--methodology`: CMMI is the default lens, so a command that lost its
`--methodology cisa-ztmm` would write CMMI levels under the CISA ZTMM name
(the study instruments refuse to record or pass such a file):

```bash
python -m miccmac assess 192.0.2.10 --save-facts H1-facts.json --as-of 2026-11-23 \
    --connector ssh-osquery --ssh-user assessor --ssh-key ~/.ssh/miccmac_study_ed25519 \
    --attestation attestation.json --inventory-record inventory-record.json \
    --methodology cmmi --risk-register --format json -o H1-cmmi.json

python -m miccmac assess 192.0.2.10 --facts H1-facts.json \
    --attestation attestation.json --inventory-record inventory-record.json \
    --methodology cisa-ztmm --risk-register --format json -o H1-cisa-ztmm.json \
    --as-of 2026-11-23
```

Keep the SSH private key outside the study folder, so it can never be
committed or shared with the study data. To re-test fixed check logic later
against the same raw facts, run the second command again with the same
`--as-of` date, writing to a new folder (for example
`-o retest-v0.2/H1-cisa-ztmm.json`), never over the baseline outputs; the
tool refuses to replace them anyway. Details, including what `--as-of` does
not change, are in
[`docs/methodology.md`](docs/methodology.md#11-reproducibility-reference-date-saved-facts-and-provenance).
The reproducible-run features (`--as-of`, `--save-facts`, `--facts`, the
provenance block and the `-o` and `--stdout` safeguards), the study
instruments in [`miccmac_study/`](miccmac_study/README.md), CMMI as the
default lens, the register's missing-data entries, next-level hints and SP
800-30 structure, and the drafted threat-source types and events were
drafted with AI assistance (Claude Code, Anthropic) for the researcher's
review.

## Example output

```
================================================================
  MICCMAC ZERO TRUST DEVICE READINESS ASSESSMENT
================================================================
  Target          : my-laptop-01
  Overall score   : 71.4/100
  Readiness tier  : Defensible
  CMMI            : Level 4/5 - Quantitatively Managed (75.0%)
================================================================

  M  Monitored  (87.5/100)  [CMMI: Level 4/5 - Quantitatively Managed (75.0%)]
  ------------------------------------------------------------
   [PASS] MON-01  Endpoint security logging enabled
   [PASS] MON-02  Logs forwarded to a centralized SIEM / log platform
   [PART] MON-03  EDR / endpoint telemetry agent installed and healthy
   [PASS] MON-04  Audit policy covers authentication, privilege, and process events
  ...
```

A full sample report is in [`examples/sample-report.md`](examples/sample-report.md), and
illustrative HTML scorecard renderings (from real assessments against all three live targets, with
a target switcher) are in [`examples/sample-scorecard.html`](examples/sample-scorecard.html)
(CMMI methodology) and [`examples/sample-scorecard-cisa-ztmm.html`](examples/sample-scorecard-cisa-ztmm.html)
(CISA ZTMM methodology, same underlying check results) -- the two editions are kept side by
side to show both maturity-methodology lenses on the same data. The two HTML scorecards are
illustrations made before the risk register gained missing-data entries, next-level hints and
its SP 800-30 layout, and do not show those.

## How scoring works

Each check returns `PASS`, `PARTIAL`, `FAIL`, `NOT_APPLICABLE`, `ERROR` (the
check could not be evaluated, for example because a date in an input file is
not a valid date), or `NOT_IMPLEMENTED` (no facts or inputs to evaluate it
from, as in a run with no flags). A property score is the average of its
scorable checks (`PASS` = 100, `PARTIAL` = 50, `FAIL` = 0, `ERROR` = 0);
`NOT_APPLICABLE` and `NOT_IMPLEMENTED` are left out. The overall score
is the mean of the property scores, which maps to a readiness tier:

| Overall score | Readiness tier |
|---|---|
| 90 - 100 | Zero Trust Ready |
| 70 - 89 | Defensible |
| 40 - 69 | Developing |
| 0 - 39 | Not Ready |

By default a run also maps the property and overall scores to CMMI maturity
levels (levels 1-5 from 0, 20, 40, 70 and 90); `--methodology cisa-ztmm`
maps them to CISA ZTMM stages instead (stages 1-4 from 0, 40, 70 and 90),
and `--methodology none` to no levels at all. A score with nothing scorable
is "Unassessed", never level 1. The levels are this tool's score bands under those models' names,
not a CMMI appraisal or a CISA assessment.

Scoring and tier thresholds are documented, and can be tuned, in
[`docs/methodology.md`](docs/methodology.md).

## Project status

This repository started as an **alpha scaffold** — v0.1.0 — and now has real
detection logic for all seven MICCMAC properties, proven end-to-end against
a live target. See [`docs/methodology.md`](docs/methodology.md) for the full
architecture and design rationale.

### What works today

| Component | State |
|---|---|
| CLI (`miccmac assess <target>`) | Working — Python 3.9+ core, PyYAML for config/mappings |
| Engine, scoring, readiness tiers | Working |
| Text / Markdown / JSON renderers | Working |
| 7 property modules with 26 named checks | Defined, with control references |
| Per-check NIST 800-207 / 800-53 / CIS v8 mappings | Complete (see [`data/control-mappings.yaml`](data/control-mappings.yaml)) |
| Pluggable CMMI / CISA ZTMM scoring methodologies | Working: CMMI by default; `--methodology cisa-ztmm` or `none` |
| Check exclusion + custom-check plugins, fairness control | Working (`--config`, `list-checks`) |
| Risk register: findings and missing-data entries, CIS IG + FAIR-inspired rating, next-level hints, NIST SP 800-30 Rev. 1 structure | Working (`--risk-register`); the drafted threat-source types and events await review |
| SSH + osquery target connectors | Working — `--connector ssh-osquery` (Linux, proven against a live Ubuntu 26.04 LTS VM) and `--connector ssh-osquery-windows` (Windows, proven against both live Windows 11 Enterprise 25H2 and Windows Server 2025 Standard VMs) |
| All 7 MICCMAC properties, all 26 checks — real detection logic | Working, all 3 named platforms — see [`docs/methodology.md`](docs/methodology.md#10-target-connectors-and-real-detection-logic) |

All three platforms named in the project's original scope (Ubuntu Desktop
26.04 LTS, Windows 11 Enterprise, Windows Server 2025 Standard) are now
proven end-to-end against real, live VMs — the vertical slice is complete.

### What does not ship yet

- **macOS connector** is not yet built.
- **No inventory/GRC/scanning system integrations** beyond the
  `--inventory-record` and `--attestation` file-based inputs.

Running `python -m miccmac assess <target>` with no `--connector` or
`--facts` flag still prints the *structure* of a real assessment without
inspecting anything. With `--methodology none` it is byte-identical to the
original scaffold's output (test-verified against goldens captured at
commit 4644c33, `tests/test_golden_stub.py`); the default run adds the CMMI
lens, every value of it "Unassessed" in such a run.
(Adding `--as-of` to such a run changes no result; it only adds the
provenance block to JSON output. `--facts` scores facts saved by an earlier
run.) Add `--connector
ssh-osquery --ssh-user <u> --ssh-key <path>` for a Linux target, or
`--connector ssh-osquery-windows --ssh-user <u> --ssh-key <path>` for a
Windows target (plus `--inventory-record` and `--attestation` for the
checks that need external data) to get real, evidence-backed results across
all seven properties.

### Architecture (OS-agnostic by design)

`engine.run_assessment(target, context)` passes a free-form `context` dict
to every check module. From the docstring:

> *a free-form dict passed to each check module. Use it to supply connection
> details, collected device facts, API clients, etc.*

That `context` is the extensibility seam. A real implementation collects facts
about the target *upstream* of the engine and passes them in:

```python
from miccmac.engine import run_assessment

facts = {
    "os":       "windows",
    "hostname": "wks-12",
    "sysmon":   {"installed": True, "version": "15.14"},
    "edr":      {"vendor": "defender", "healthy": True},
    "patches":  {"latest_install_date": "2026-05-20"},
    # ... whatever your fact-collector produces
}
assessment = run_assessment("wks-12", context={"facts": facts})
```

Each check then branches on `facts["os"]` (or whichever fact schema you
choose) and calls platform-specific detection logic. Where a check genuinely
doesn't apply to a given platform, return `Status.NOT_APPLICABLE` so it's
excluded from scoring rather than failed.

### Roadmap beyond the first platform

| Layer | Status | What's left |
|---|---|---|
| **Target connector** | `SSHOsqueryConnector` done | WinRM / EDR API / MDM API connectors for other platforms |
| **OS detector** | `context["facts"]["os"]` populated by the connector | Per-OS branching inside checks (currently Linux-only logic) |
| **Check bodies** | All 26 checks have real logic (Linux) | Port/extend to Windows and macOS fact schemas |
| **Inventory / asset lookups** | `--inventory-record` (file-based) works | Live CMDB integration (ServiceNow, Snipe-IT, Intune, etc.) |
| **Attestation** | `--attestation` (file-based) works | Live GRC/IdP integration (Azure AD, a scan-management API, etc.) |
| **Cloud variants** | Not started | AWS SSM Inventory, Azure Arc, GCP OS Config rather than direct host access |
| **Audit/review worksheet** | Not started | A `miccmac assess --review-worksheet` output mode generating a manual-vs-automated verification worksheet (raw-evidence command + blank verdict per check, plus risk-register accuracy/actionability fields) for auditing the tool's own results against independent manual review. Prototyped once by hand for this project's own fairness-control research pass; would need the raw-evidence commands derived from the connector/check code itself (not hand-maintained separately) to avoid drifting out of sync as checks change.

### Lowest-effort first concrete targets — done for Linux + osquery, all 7 properties

All seven vertical slices are implemented and proven end-to-end against a
live Ubuntu 26.04 LTS VM, via `miccmac/connectors/ssh_osquery.py`:

- **Inventoried** (`miccmac/checks/inventoried.py`) — all four `INV-*`
  checks; two of which (INV-01, INV-04) correctly draw on an external
  `--inventory-record` input rather than the device itself.
- **Monitored** (`miccmac/checks/monitored.py`) — all four `MON-*` checks,
  via osquery's `systemd_units` table (journald/rsyslog/syslog-ng/osqueryd/
  auditd service state) plus one raw-command fact for rsyslog forwarding
  config (osquery's SQL surface doesn't expose file content).
- **Controlled** (`miccmac/checks/controlled.py`) — all four `CTL-*` checks,
  via osquery's `shadow`/`users`/`user_groups` tables (root lock state, sudo
  membership) and `deb_packages` (config-mgmt / hardening-tool presence);
  CTL-03 correctly draws on a new `--attestation` input, since identity-aware
  access policy lives in a cloud IdP, not on the device.
- **Claimed** (`miccmac/checks/claimed.py`) — all three `CLM-*` checks,
  entirely from `--attestation` (business owner, system administrator,
  business purpose/data classification are pure record-keeping facts with no
  device-local signal at all) — works standalone, with or without
  `--connector`.
- **Minimized** (`miccmac/checks/minimized.py`) — all four `MIN-*` checks,
  via `deb_packages`/`systemd_units` (legacy service/package presence), ufw
  state + `listening_ports` filtered to real network-reachable listeners
  (loopback-only services excluded), and a sample of CIS-recommended kernel
  `system_controls` for MIN-04.
- **Assessed** (`miccmac/checks/assessed.py`) — all three `ASM-*` checks,
  entirely from `--attestation` (scan/assessment schedule and SLA tracking
  are process-history facts, not device state) — reuses the same
  recency-vs-policy-interval pattern as INV-04.
- **Current** (`miccmac/checks/current.py`) — all four `CUR-*` checks: patch
  and third-party update cadence via `apt-daily-upgrade.timer` and the
  `file` table's mtime for apt's update-success stamp, certificate expiry
  directly via osquery's `certificates` table, and CUR-03 (firmware/BIOS
  currency) via `--attestation`, since even root access only reveals the
  *current* version, never whether it's the *latest available* one.

See
[`docs/methodology.md`](docs/methodology.md#10-target-connectors-and-real-detection-logic)
for the design rationale and real findings from live testing (e.g. why
INV-02 and MON-04 legitimately FAIL on a stock install).

```bash
miccmac assess 192.168.1.50 --connector ssh-osquery \
    --ssh-user miccmac --ssh-key ~/.ssh/miccmac_vm_key \
    --inventory-record inventory-record.json \
    --attestation attestation.json --risk-register
```

All 26 checks now have real detection logic on Linux. Reasonable next
targets, following the same pattern:

- **Windows + Sysmon + Defender** — a `WinRMConnector` alongside
  `SSHOsqueryConnector`; implement `MON-03` by checking the Sysmon driver and
  parsed config; `INV-03` via `Get-Package`; `CUR-01` via Windows Update
  history (`Get-HotFix`).
- **macOS + Jamf / Kandji** — implement `INV-*` via the MDM API; `CTL-*` by
  inspecting configuration profiles.

Contributions for any platform are very welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Repository layout

```
miccmac-zt-readiness/
  miccmac/                 Python package
    cli.py                 command-line interface
    engine.py              runs checks, scores, builds the assessment
    report.py              text / markdown / JSON rendering
    model.py               data model (CheckResult, PropertyResult, ...)
    checks/                one module per MICCMAC property
    connectors/            SSH + osquery fact collection (Linux, Windows)
    clock.py               reference date for --as-of
    facts_file.py          saved facts files (--save-facts, --facts)
    provenance.py          the provenance block in JSON output
  miccmac_study/           study instruments for the validation study, separate
                           from the tool under test (see miccmac_study/README.md)
  data/control-mappings.yaml   property -> 800-207 / 800-53 / CIS v8
  docs/methodology.md      framework and scoring methodology
  examples/sample-report.md
  tests/                   unit tests
```

## Citing this work

If you use this toolkit or the framework, please cite **both** the software and
the paper. A machine-readable citation is in [`CITATION.cff`](CITATION.cff).

**Paper:** Ojeh, I. (2025). *Getting Devices Ready for Zero Trust Architecture
by Complying with Richard Bejtlich's MICCMAC Framework.* ECCWS 2025.
DOI: [10.34190/eccws.24.1.3531](https://doi.org/10.34190/eccws.24.1.3531)

**Software:** cite the GitHub repository, or the Zenodo DOI once a release has
been archived.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

## Author

Isaac Ojeh -- cybersecurity practitioner and researcher. Built as the reference
implementation of the MICCMAC Zero Trust device-readiness framework.
