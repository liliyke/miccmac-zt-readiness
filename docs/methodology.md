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

## 7. Extending the toolkit

To implement a check, edit the relevant module in `miccmac/checks/` and replace
the `NOT_IMPLEMENTED` stub with real detection logic that sets `status`,
`detail`, and `evidence`. Device facts can be passed in through the `context`
dictionary so that collection logic stays separate from evaluation logic.
