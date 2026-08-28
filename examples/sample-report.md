<!-- This is an ILLUSTRATIVE sample produced with simulated check results, to show the report format (including the legend) of a completed assessment, and the risk register produced from the same data via `--risk-register`. Regenerate by re-running the data behind this file through miccmac.report/miccmac.risk_register if the rendering format changes. -->

# MICCMAC Zero Trust Device Readiness Assessment

- **Target:** finance-laptop-042
- **Overall score:** 72.0/100
- **Readiness tier:** Defensible
- **CMMI:** Level 4/5 - Quantitatively Managed (75.0%)

## M &mdash; Monitored (87.5/100) &mdash; CMMI: Level 4/5 - Quantitatively Managed (75.0%)

| Check | Name | Status | Detail |
|---|---|---|---|
| MON-01 | Endpoint security logging enabled | PASS | Windows Security + Sysmon logging enabled. |
| MON-02 | Logs forwarded to a centralized SIEM / log platform | PASS | Events forwarded to Microsoft Sentinel. |
| MON-03 | EDR / endpoint telemetry agent installed and healthy | PARTIAL | EDR agent installed; last check-in 4 days ago. |
| MON-04 | Audit policy covers authentication, privilege, and process events | PASS | Advanced audit policy covers logon, privilege, process. |

## I &mdash; Inventoried (62.5/100) &mdash; CMMI: Level 3/5 - Defined (50.0%)

| Check | Name | Status | Detail |
|---|---|---|---|
| INV-01 | Device present in the authoritative asset inventory | PASS | Present in Intune and the CMDB. |
| INV-02 | Hardware attributes recorded (make, model, serial) | PASS | Make/model/serial recorded. |
| INV-03 | Installed-software inventory maintained for the device | PARTIAL | Software inventory present but 30+ days stale. |
| INV-04 | Inventory record reviewed within the policy interval | FAIL | Inventory record not reviewed within 90-day policy. |

## C &mdash; Controlled (62.5/100) &mdash; CMMI: Level 3/5 - Defined (50.0%)

| Check | Name | Status | Detail |
|---|---|---|---|
| CTL-01 | Device enrolled in central configuration management / MDM | PASS | Enrolled in Microsoft Intune. |
| CTL-02 | Administrative privileges restricted (least privilege) | FAIL | Primary user holds standing local admin rights. |
| CTL-03 | Access governed by identity-aware / conditional-access policy | PASS | Conditional Access enforced for all resource access. |
| CTL-04 | Configuration baseline enforced and drift-monitored | PARTIAL | Baseline applied; drift monitoring not configured. |

## C &mdash; Claimed (66.7/100) &mdash; CMMI: Level 3/5 - Defined (50.0%)

| Check | Name | Status | Detail |
|---|---|---|---|
| CLM-01 | Accountable business owner assigned and recorded | PASS | Business owner recorded in CMDB. |
| CLM-02 | Responsible system administrator identified | PASS | Responsible admin group assigned. |
| CLM-03 | Business purpose and data classification documented | FAIL | No documented purpose or data classification. |

## M &mdash; Minimized (87.5/100) &mdash; CMMI: Level 4/5 - Quantitatively Managed (75.0%)

| Check | Name | Status | Detail |
|---|---|---|---|
| MIN-01 | Unnecessary services and daemons disabled | PASS | Unnecessary services disabled per baseline. |
| MIN-02 | Unused or unauthorized software removed | PARTIAL | Two unapproved applications detected. |
| MIN-03 | Host firewall enabled; unused network ports closed | PASS | Host firewall on; only required ports open. |
| MIN-04 | Recognized hardening baseline (e.g. CIS Benchmark) applied | PASS | CIS Benchmark Level 1 applied. |

## A &mdash; Assessed (50.0/100) &mdash; CMMI: Level 3/5 - Defined (50.0%)

| Check | Name | Status | Detail |
|---|---|---|---|
| ASM-01 | Authenticated vulnerability scanning performed on schedule | PASS | Authenticated scan completed 6 days ago. |
| ASM-02 | Configuration / compliance assessment performed on schedule | PARTIAL | Compliance scan run; cadence exceeds policy. |
| ASM-03 | Findings tracked to remediation against defined SLAs | FAIL | 12 findings open past remediation SLA. |

## C &mdash; Current (87.5/100) &mdash; CMMI: Level 4/5 - Quantitatively Managed (75.0%)

| Check | Name | Status | Detail |
|---|---|---|---|
| CUR-01 | Operating-system patch level within policy | PASS | OS patch level current. |
| CUR-02 | Third-party software updated within policy | PARTIAL | Two third-party apps one cycle behind. |
| CUR-03 | Firmware / BIOS current | PASS | Firmware current. |
| CUR-04 | Certificates and cryptographic material valid and unexpired | PASS | No expired certificates detected. |

**Legend**

- **MICCMAC properties** (framework name spelled out by the property order): **M** Monitored, **I** Inventoried, **C** Controlled, **C** Claimed, **M** Minimized, **A** Assessed, **C** Current.
- **Check status:** `[PASS]` control fully satisfied; `[PART]` control partially satisfied; `[FAIL]` control not satisfied; `[TODO]` check logic not yet implemented; `[ N/A]` excluded by config, or not applicable to this device; `[ ERR]` check could not be evaluated (e.g. data source unreachable).
- **Overall score -> readiness tier** (always computed; thresholds are tunable): `90-100` Zero Trust Ready; `70-89` Defensible; `40-69` Developing; `0-39` Not Ready.
- **CMMI** (Capability Maturity Model Integration) **maturity levels**, shown alongside the readiness tier above, not instead of it: `0-19` Level 1 Initial; `20-39` Level 2 Managed; `40-69` Level 3 Defined; `70-89` Level 4 Quantitatively Managed; `90-100` Level 5 Optimizing.

---

## Risk Register (CIS IG + FAIR-inspired rating)

**Legend**

- **CIS IG** (CIS Controls v8 Implementation Group -- who is expected to have this control in place): `IG1` basic cyber hygiene, expected of every organization; `IG2` requires more organizational maturity (centralized tooling, scheduled processes, identity integration); `IG3` reserved for controls facing sophisticated/targeted threats (no built-in check is IG3; a custom check plugin may add one).
- **FAIR** (Factor Analysis of Information Risk, simplified/qualitative here, not quantitative FAIR/Monte Carlo): *frequency* = how often this failure mode is actually exploited in the wild; *magnitude* = the blast radius if it is. Both are banded LOW/MEDIUM/HIGH.
- **Risk rating** (frequency x magnitude, via the matrix in `miccmac/risk_register.py`): `CRITICAL` HIGH+HIGH FAIR rating -- fix immediately, ahead of everything else below it; `HIGH` HIGH+MEDIUM or MEDIUM+HIGH -- fix in the current remediation cycle; `MODERATE` MEDIUM+MEDIUM, LOW+HIGH, or HIGH+LOW -- schedule into the normal backlog; `LOW` LOW+LOW, LOW+MEDIUM, or MEDIUM+LOW -- track, but not urgent; `UNRATED` no CIS IG/FAIR metadata on file for this check_id -- rate it manually.

Sorted highest priority first -- work top to bottom as your next course of action.

| Risk | Check | Name | Status | CIS IG | FAIR (freq/mag) | Detail | Recommended fix |
|---|---|---|---|---|---|---|---|
| CRITICAL | CTL-02 | Administrative privileges restricted (least privilege) | FAIL | IG1 | HIGH/HIGH | Primary user holds standing local admin rights. | Remove standing local-administrator rights from routine accounts; grant elevation via a just-in-time/PAM mechanism instead. |
| CRITICAL | CUR-02 | Third-party software updated within policy | PARTIAL | IG1 | HIGH/HIGH | Two third-party apps one cycle behind. | Update out-of-date third-party applications and enroll the device in third-party patch management. |
| CRITICAL | MON-03 | EDR / endpoint telemetry agent installed and healthy | PARTIAL | IG2 | HIGH/HIGH | EDR agent installed; last check-in 4 days ago. | Install and start the standard EDR/endpoint telemetry agent for this fleet; confirm the agent service is running and reporting healthy. |
| MODERATE | ASM-03 | Findings tracked to remediation against defined SLAs | FAIL | IG1 | MEDIUM/MEDIUM | 12 findings open past remediation SLA. | Load this device's open findings into the remediation-tracking system with SLA due dates and named owners. |
| MODERATE | INV-03 | Installed-software inventory maintained for the device | PARTIAL | IG1 | MEDIUM/MEDIUM | Software inventory present but 30+ days stale. | Confirm the device's package manager (apt/dpkg, etc.) is queryable and its installed-software list is being collected into inventory. |
| MODERATE | MIN-02 | Unused or unauthorized software removed | PARTIAL | IG1 | MEDIUM/MEDIUM | Two unapproved applications detected. | Uninstall software packages that are not on the approved/required list for this device's role. |
| MODERATE | CTL-04 | Configuration baseline enforced and drift-monitored | PARTIAL | IG2 | MEDIUM/MEDIUM | Baseline applied; drift monitoring not configured. | Assign the device a configuration baseline (e.g. GPO/Ansible/Intune profile) and enable drift detection/auto-remediation. |
| LOW | ASM-02 | Configuration / compliance assessment performed on schedule | PARTIAL | IG2 | LOW/MEDIUM | Compliance scan run; cadence exceeds policy. | Enroll the device in a recurring configuration/compliance assessment (e.g. CIS-CAT, SCAP). |
| LOW | CLM-03 | Business purpose and data classification documented | FAIL | IG2 | LOW/MEDIUM | No documented purpose or data classification. | Document the device's business purpose and assign it a data classification label. |
| LOW | INV-04 | Inventory record reviewed within the policy interval | FAIL | IG2 | LOW/LOW | Inventory record not reviewed within 90-day policy. | Re-review and re-date the device's inventory record, and schedule a recurring review so it never again exceeds the policy interval. |
