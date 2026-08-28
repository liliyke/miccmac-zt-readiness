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

Requires Python 3.9 or newer. The core toolkit uses the standard library only.

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

# Score against a maturity-model methodology in addition to the default score
miccmac assess my-laptop-01 --methodology cmmi
miccmac assess my-laptop-01 --methodology cisa-ztmm

# Exclude built-in checks / add your own via a config file (see
# examples/miccmac-config.example.yaml and examples/custom_checks/)
miccmac assess my-laptop-01 --config my-config.yaml

# Append a CIS Implementation Group + FAIR-inspired risk register
miccmac assess my-laptop-01 --risk-register

# Print the exact enabled check-id set for a configuration -- the "fairness
# control" for comparing automated output against a manual assessment
miccmac list-checks --config my-config.yaml
```

Pluggable scoring methodologies, check exclusion/custom checks, and the risk
register are documented in full, including the scoring tables and rationale,
in [`docs/methodology.md`](docs/methodology.md).

## Example output

```
================================================================
  MICCMAC ZERO TRUST DEVICE READINESS ASSESSMENT
================================================================
  Target          : my-laptop-01
  Overall score   : 71.4/100
  Readiness tier  : Defensible
================================================================

  M  Monitored  (87.5/100)
  ------------------------------------------------------------
   [PASS] MON-01  Endpoint security logging enabled
   [PASS] MON-02  Logs forwarded to a centralized SIEM / log platform
   [PART] MON-03  EDR / endpoint telemetry agent installed and healthy
   [PASS] MON-04  Audit policy covers authentication, privilege, and process events
  ...
```

A full sample report is in [`examples/sample-report.md`](examples/sample-report.md).

## How scoring works

Each check returns `PASS`, `PARTIAL`, `FAIL`, `NOT_APPLICABLE`, or (in the
current scaffold) `NOT_IMPLEMENTED`. A property score is the average of its
scorable checks (`PASS` = 100, `PARTIAL` = 50, `FAIL` = 0). The overall score
is the mean of the property scores, which maps to a readiness tier:

| Overall score | Readiness tier |
|---|---|
| 90 - 100 | Zero Trust Ready |
| 70 - 89 | Defensible |
| 40 - 69 | Developing |
| 0 - 39 | Not Ready |

Scoring and tier thresholds are documented, and can be tuned, in
[`docs/methodology.md`](docs/methodology.md).

## Project status

This repository is an **alpha scaffold** — v0.1.0. The framework, scoring
engine, control mappings, reporting, and CLI are complete and working. The
individual device checks in `miccmac/checks/` are stubbed
(`NOT_IMPLEMENTED`) and ready for real detection logic.

### What works today

| Component | State |
|---|---|
| CLI (`miccmac assess <target>`) | Working — Python 3.9+ core, PyYAML for config/mappings |
| Engine, scoring, readiness tiers | Working |
| Text / Markdown / JSON renderers | Working |
| 7 property modules with 26 named checks | Defined, with control references |
| Per-check NIST 800-207 / 800-53 / CIS v8 mappings | Complete (see [`data/control-mappings.yaml`](data/control-mappings.yaml)) |
| Pluggable CMMI / CISA ZTMM scoring methodologies | Working (`--methodology`) |
| Check exclusion + custom-check plugins, fairness control | Working (`--config`, `list-checks`) |
| CIS IG + FAIR-inspired risk register | Working (`--risk-register`) |

### What does not ship yet

- **No target connector.** Nothing connects to a real host. The `target`
  argument is currently a label printed in the report header.
- **No OS detection or branching.** Each check is a single function that
  doesn't know whether the target is Windows, Linux, macOS, or cloud.
- **No check bodies.** All 26 checks return `Status.NOT_IMPLEMENTED`.
- **No inventory or EDR / MDM / cloud API clients.**

Running the smoke test (`python -m miccmac assess test-device`) therefore
prints the *structure* of a real assessment without actually inspecting
anything. That structure — properties, checks, control references, scoring,
tiers — is the contribution. The detection mechanics are environment-specific.

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

### Roadmap to a real implementation

| Layer | What to add | Where it goes |
|---|---|---|
| **Target connector** | SSH / WinRM / EDR API / MDM API / "run locally" client | A new `miccmac/connectors/` package |
| **OS detector** | Detect platform, populate `context["facts"]["os"]` | Inside the connector, before calling `run_assessment` |
| **Per-OS check bodies** | Replace `NOT_IMPLEMENTED` stubs with real evaluations | Inside each `miccmac/checks/*.py` |
| **Inventory / asset lookups** | Query your CMDB (ServiceNow, Snipe-IT, Intune, etc.) | Connector layer feeds facts |
| **Cloud variants** | AWS SSM Inventory, Azure Arc, GCP OS Config rather than direct host access | Separate cloud-aware connectors |

### Lowest-effort first concrete target

Pick whichever environment you already have a lab in. Reasonable first targets:

- **Linux + osquery** — implement `INV-01..04` via `osquery` queries against
  `system_info`, `os_version`, and `programs`; implement `MON-01..04` by
  inspecting `/etc/rsyslog.d/`, `auditctl -l`, and the EDR agent's PID.
- **Windows + Sysmon + Defender** — implement `MON-03` by checking the
  Sysmon driver and parsed config; `INV-03` via `Get-Package` over WinRM;
  `CUR-01` via Windows Update history (`Get-HotFix`).
- **macOS + Jamf / Kandji** — implement `INV-*` via the MDM API; `CTL-*` by
  inspecting configuration profiles.

Implement one property's worth of checks for one platform (e.g. all four
`monitored` checks for Linux), ship a v0.2.0, then grow from there.

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
