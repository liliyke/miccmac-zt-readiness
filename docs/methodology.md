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

Every text/markdown scorecard render (`miccmac/report.py`) ends with a legend
reprinting this table, the MICCMAC property-letter meanings, the check-status
glyphs, and -- when `--methodology` is used -- the selected methodology's own
score-to-level chart, so the scorecard is self-explanatory without this doc
open alongside it.

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
and that line reads "n/a" for the check. See
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
- **`remediation`** -- a short, actionable recommended fix for a FAIL/PARTIAL
  result on this check (e.g. "Enroll the device in the organization's central
  configuration-management/MDM platform" for CTL-01). Required for every
  built-in check; shown as each register entry's "Recommended fix" line so
  the register reads as a prioritized action plan, not just a list of gaps.

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

Every text/markdown render of the register opens with a legend explaining
`IG1`/`IG2`/`IG3`, FAIR frequency/magnitude, and the risk-rating scale above,
and entries are sorted highest-priority first so the register itself reads as
the recommended order of operations -- fix the top entry first.

Implementation: `miccmac/risk_register.py`.

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
defines the `Connector` protocol (`collect_facts(target) -> dict`).
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
if `context` has no `"facts"` key at all (the default, no-`--connector`
invocation), it falls back to the identical `NOT_IMPLEMENTED` stub behavior.
This is why `miccmac assess <target>` with no flags has stayed byte-for-byte
identical to the original Alpha scaffold's output through every pass of
this architecture work -- verified by diffing against the original commit,
not just by inspection.

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

## 12. Extending the toolkit

To implement a check, edit the relevant module in `miccmac/checks/` and replace
the `NOT_IMPLEMENTED` stub with real detection logic that sets `status`,
`detail`, and `evidence`. Device facts can be passed in through the `context`
dictionary so that collection logic stays separate from evaluation logic.
