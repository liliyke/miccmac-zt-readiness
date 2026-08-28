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
| `NOT_APPLICABLE` | The check does not apply to this device. |
| `NOT_IMPLEMENTED` | Check logic has not been written yet (scaffold default). |
| `ERROR` | The check could not be evaluated. |

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

The default scoring above (Section 4-5) is always computed. Passing
`--methodology cmmi` or `--methodology cisa-ztmm` additionally re-buckets
that same flat 0-100 score into an ordinal maturity level under the chosen
model, without changing the flat score itself.

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
  - MON-02          # dropped entirely: not shown, not scored
custom_checks_dir: ./custom_checks
```

**Custom checks** are your own Python modules, one file per module, dropped
into `custom_checks_dir`. Each must define `CHECK_IDS` (a non-empty list of
new check ids), `ATTACH_TO` (one of the seven canonical property keys), and
`run_checks(target, context) -> list[CheckResult]`. The engine merges each
plugin's results into the matching *existing* property -- there is no code
path that creates an eighth property; the seven letters spell the framework
name and are fixed. See `examples/custom_checks/acme_extra_checks.py` and
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

## 9. CIS Implementation Group + FAIR-inspired risk register

`miccmac assess --risk-register` appends a prioritized remediation view. It
is not a new scoring methodology -- it enriches the findings from a
completed assessment.

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

These two ratings combine into an overall risk rating via a 3x3 qualitative
lookup table (deliberately a lookup, not a numeric product -- ordinal
LOW/MEDIUM/HIGH values cannot be validly multiplied):

| Frequency \\ Magnitude | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **LOW** | LOW | LOW | MODERATE |
| **MEDIUM** | LOW | MODERATE | HIGH |
| **HIGH** | MODERATE | HIGH | CRITICAL |

The register lists every `FAIL`/`PARTIAL` check, sorted by risk rating first
(fix CRITICALs before HIGHs regardless of IG -- rating reflects actual
measured exposure) and CIS IG as the tiebreaker within a rating band (an IG1
failure is more foundational, expected of every organization, than an IG2
failure at the same risk level, so it is remediated first). A check with no
metadata entry (e.g. an unrated custom check) sorts last as `UNRATED` rather
than being dropped.

Implementation: `miccmac/risk_register.py`.

## 10. Extending the toolkit

To implement a check, edit the relevant module in `miccmac/checks/` and replace
the `NOT_IMPLEMENTED` stub with real detection logic that sets `status`,
`detail`, and `evidence`. Device facts can be passed in through the `context`
dictionary so that collection logic stays separate from evaluation logic.
