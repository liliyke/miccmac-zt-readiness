<!-- This is an ILLUSTRATIVE sample produced with simulated check results, to show the report format (including the legend) of a completed assessment under the default CMMI lens, and the risk register produced from the same data via `--risk-register`. Regenerate by re-running the data behind this file through miccmac.report/miccmac.risk_register if the rendering format changes; it was last regenerated on 2026-11-20, with the register's next-level hints and NIST SP 800-30 Rev. 1 fields, from the same simulated statuses (every entry here is a finding: no input is missing). -->

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

## Risk Register (structured after NIST SP 800-30 Rev. 1; CIS IG + FAIR-inspired rating)

**Legend**

- **CIS IG** (CIS Controls v8 Implementation Group -- who is expected to have this control in place): `IG1` basic cyber hygiene, expected of every organization; `IG2` requires more organizational maturity (centralized tooling, scheduled processes, identity integration); `IG3` reserved for controls facing sophisticated/targeted threats (no built-in check is IG3; a custom check plugin may add one).
- **FAIR** (Factor Analysis of Information Risk, simplified/qualitative here, not quantitative FAIR/Monte Carlo): *frequency* = how often this failure mode is actually exploited in the wild; *magnitude* = the blast radius if it is. Both are banded LOW/MEDIUM/HIGH.
- **Risk rating** (frequency x magnitude, via the matrix in `miccmac/risk_register.py`): `CRITICAL` HIGH+HIGH FAIR rating -- fix immediately, ahead of everything else below it; `HIGH` HIGH+MEDIUM or MEDIUM+HIGH -- fix in the current remediation cycle; `MODERATE` MEDIUM+MEDIUM, LOW+HIGH, or HIGH+LOW -- schedule into the normal backlog; `LOW` LOW+LOW, LOW+MEDIUM, or MEDIUM+LOW -- track, but not urgent; `UNRATED` no CIS IG/FAIR metadata on file for this check_id -- rate it manually.
- **Entries:** *finding* = FAIL or PARTIAL: the control is missing or incomplete; *missing data* = ERROR (the data the check reads cannot be read), or NOT_APPLICABLE only because an organizational input (the attestation or inventory record, or one of its entries) was not supplied. The entry says what is missing and how to supply it. Its ratings are those the check would carry if the control turned out to be absent. Checks that do not apply, checks excluded by the config and NOT_IMPLEMENTED checks get no entry; a check whose control is missing is a FAIL finding.
- **NIST SP 800-30 Rev. 1 risk factors, plus a recommended response: this register's own fields arranged in SP 800-30's terms; not an SP 800-30 risk assessment.** *threat source type* = the SP 800-30 Appendix D type of source most likely to exploit a failure of the check (adversarial, accidental, structural or environmental); a judgment per check, not an analysis of this organization's threats; *threat event* = a short, generic event per check, not threat intelligence; *vulnerability* = the finding (for missing data: not determined); *likelihood* = the FAIR frequency band (3 levels, not SP 800-30's 5-level scale; not derived through SP 800-30's tables or from this device's exposure); *impact* = the FAIR magnitude band (same caveat); *risk* = this register's risk rating (its own 3x3 matrix, not SP 800-30's table); for missing data, the rating if the control is absent; *response* = the recommended mitigation step (for missing data: supply the data, then the fix); choosing a response (accept, avoid, mitigate, share or transfer, as in NIST SP 800-39) stays the organization's decision. Qualitative throughout: no quantitative (FAIR/Monte Carlo) estimate. The FAIR bands were rated for how often adversaries exploit the failure in the wild; on an accidental or structural row they stand in for likelihood and impact and were not rated for that threat source. (drafted) marks a threat source type and event drafted with AI assistance for the researcher's review and not yet confirmed (docs/sp800-30-review.md).
- **Next level (CMMI):** the property's level now and what fixing this check does toward the next level: on its own, or together with the fewest other open entries in the property (largest score gain first), and whether that next level needs this check at all. A fix means the check re-tests as PASS and nothing else changes. A check that is not scored (missing input) gets no estimate, and the overall level gets no hint. Levels and stages are this tool's score bands under CMMI or CISA ZTMM names (docs/methodology.md section 7), not a CMMI appraisal or a CISA assessment; the top band (CMMI level 5, CISA ZTMM stage 4) reflects one snapshot scoring 90 or more, not sustained improvement.

Findings first (FAIL, PARTIAL), then missing-data entries (ERROR, or an input not supplied); within each: risk rating, then CIS IG, then check id. Work top to bottom.

### Findings (FAIL, PARTIAL)

| # | Risk | Check | Name | Status | CIS IG | Threat source type | Threat event | Vulnerability (finding) | Likelihood (FAIR freq.) | Impact (FAIR mag.) | Recommended fix | Next level (CMMI) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | CRITICAL | CTL-02 | Administrative privileges restricted (least privilege) | FAIL | IG1 | adversarial (drafted) | An attacker who compromises a routine account, or logs on directly as root or the built-in Administrator, gains full control of the device. | Primary user holds standing local admin rights. | HIGH | HIGH | Remove standing local-administrator rights from routine accounts; grant elevation via a just-in-time/PAM mechanism instead. | Fixing this check alone raises Controlled from CMMI level 3 (Defined) to level 4 (Quantitatively Managed): score 62.5 -> 87.5 (level 4 needs 70). |
| 2 | CRITICAL | CUR-02 | Third-party software updated within policy | PARTIAL | IG1 | adversarial (drafted) | An attacker exploits a known vulnerability in an out-of-date third-party application on the device. | Two third-party apps one cycle behind. | HIGH | HIGH | Update out-of-date third-party applications and enroll the device in third-party patch management. | Fixing this check alone raises Current from CMMI level 4 (Quantitatively Managed) to level 5 (Optimizing): score 87.5 -> 100.0 (level 5 needs 90). |
| 3 | CRITICAL | MON-03 | EDR / endpoint telemetry agent installed and healthy | PARTIAL | IG2 | adversarial (drafted) | Malware runs on the device and spreads, with no endpoint telemetry agent to detect or contain it. | EDR agent installed; last check-in 4 days ago. | HIGH | HIGH | Install and start the standard EDR/endpoint telemetry agent for this fleet; confirm the agent service is running and reporting healthy. | Fixing this check alone raises Monitored from CMMI level 4 (Quantitatively Managed) to level 5 (Optimizing): score 87.5 -> 100.0 (level 5 needs 90). |
| 4 | MODERATE | ASM-03 | Findings tracked to remediation against defined SLAs | FAIL | IG1 | adversarial (drafted) | An attacker exploits a vulnerability that was found but never fixed, because findings are not tracked to remediation. | 12 findings open past remediation SLA. | MEDIUM | MEDIUM | Load this device's open findings into the remediation-tracking system with SLA due dates and named owners. | Fixing this check alone raises Assessed from CMMI level 3 (Defined) to level 4 (Quantitatively Managed): score 50.0 -> 83.3 (level 4 needs 70). |
| 5 | MODERATE | INV-03 | Installed-software inventory maintained for the device | PARTIAL | IG1 | adversarial (drafted) | An attacker exploits vulnerable or unauthorized software the organization cannot see on the device, so it is never patched or removed. | Software inventory present but 30+ days stale. | MEDIUM | MEDIUM | Confirm the device's package manager (apt/dpkg, etc.) is queryable and its installed-software list is being collected into inventory. | Fixing this check alone raises Inventoried from CMMI level 3 (Defined) to level 4 (Quantitatively Managed): score 62.5 -> 75.0 (level 4 needs 70). |
| 6 | MODERATE | MIN-02 | Unused or unauthorized software removed | PARTIAL | IG1 | adversarial (drafted) | An attacker exploits a flaw in legacy or unneeded software, or in an enabled legacy feature such as SMBv1, on the device. | Two unapproved applications detected. | MEDIUM | MEDIUM | Uninstall software packages that are not on the approved/required list for this device's role. | Fixing this check alone raises Minimized from CMMI level 4 (Quantitatively Managed) to level 5 (Optimizing): score 87.5 -> 100.0 (level 5 needs 90). |
| 7 | MODERATE | CTL-04 | Configuration baseline enforced and drift-monitored | PARTIAL | IG2 | accidental (drafted) | A change by an administrator or user moves the device away from its secure baseline, and the drift is neither detected nor reverted. | Baseline applied; drift monitoring not configured. | MEDIUM | MEDIUM | Assign the device a configuration baseline (e.g. GPO/Ansible/Intune profile) and enable drift detection/auto-remediation. | Fixing this check alone raises Controlled from CMMI level 3 (Defined) to level 4 (Quantitatively Managed): score 62.5 -> 75.0 (level 4 needs 70). |
| 8 | LOW | ASM-02 | Configuration / compliance assessment performed on schedule | PARTIAL | IG2 | adversarial (drafted) | An attacker exploits a configuration weakness on the device that a scheduled compliance assessment would have reported. | Compliance scan run; cadence exceeds policy. | LOW | MEDIUM | Enroll the device in a recurring configuration/compliance assessment (e.g. CIS-CAT, SCAP). | Assessed is at CMMI level 3 (Defined), score 50.0; level 4 (Quantitatively Managed) needs 70. Fixing this check alone gives 66.7. Level 4 does not need this check: fixing ASM-03 reaches it (score 83.3). Together with ASM-03, this check gives 100.0. |
| 9 | LOW | CLM-03 | Business purpose and data classification documented | FAIL | IG2 | accidental (drafted) | Sensitive data on the device is handled without the protection its classification calls for, because its purpose and classification are not documented. | No documented purpose or data classification. | LOW | MEDIUM | Document the device's business purpose and assign it a data classification label. | Fixing this check alone raises Claimed from CMMI level 3 (Defined) to level 5 (Optimizing): score 66.7 -> 100.0 (level 5 needs 90). |
| 10 | LOW | INV-04 | Inventory record reviewed within the policy interval | FAIL | IG2 | accidental (drafted) | Administrators act on an out-of-date asset record, so changes to the device's owner, role or configuration go unnoticed. | Inventory record not reviewed within 90-day policy. | LOW | LOW | Re-review and re-date the device's inventory record, and schedule a recurring review so it never again exceeds the policy interval. | Fixing this check alone raises Inventoried from CMMI level 3 (Defined) to level 4 (Quantitatively Managed): score 62.5 -> 87.5 (level 4 needs 70). |
