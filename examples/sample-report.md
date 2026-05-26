<!-- This is an ILLUSTRATIVE sample produced with simulated check results, to show the report format of a completed assessment. -->

# MICCMAC Zero Trust Device Readiness Assessment

- **Target:** finance-laptop-042
- **Overall score:** 72.0/100
- **Readiness tier:** Defensible

## M &mdash; Monitored (87.5/100)

| Check | Name | Status | Detail |
|---|---|---|---|
| MON-01 | Endpoint security logging enabled | PASS | Windows Security + Sysmon logging enabled. |
| MON-02 | Logs forwarded to a centralized SIEM / log platform | PASS | Events forwarded to Microsoft Sentinel. |
| MON-03 | EDR / endpoint telemetry agent installed and healthy | PARTIAL | EDR agent installed; last check-in 4 days ago. |
| MON-04 | Audit policy covers authentication, privilege, and process events | PASS | Advanced audit policy covers logon, privilege, process. |

## I &mdash; Inventoried (62.5/100)

| Check | Name | Status | Detail |
|---|---|---|---|
| INV-01 | Device present in the authoritative asset inventory | PASS | Present in Intune and the CMDB. |
| INV-02 | Hardware attributes recorded (make, model, serial) | PASS | Make/model/serial recorded. |
| INV-03 | Installed-software inventory maintained for the device | PARTIAL | Software inventory present but 30+ days stale. |
| INV-04 | Inventory record reviewed within the policy interval | FAIL | Inventory record not reviewed within 90-day policy. |

## C &mdash; Controlled (62.5/100)

| Check | Name | Status | Detail |
|---|---|---|---|
| CTL-01 | Device enrolled in central configuration management / MDM | PASS | Enrolled in Microsoft Intune. |
| CTL-02 | Administrative privileges restricted (least privilege) | FAIL | Primary user holds standing local admin rights. |
| CTL-03 | Access governed by identity-aware / conditional-access policy | PASS | Conditional Access enforced for all resource access. |
| CTL-04 | Configuration baseline enforced and drift-monitored | PARTIAL | Baseline applied; drift monitoring not configured. |

## C &mdash; Claimed (66.7/100)

| Check | Name | Status | Detail |
|---|---|---|---|
| CLM-01 | Accountable business owner assigned and recorded | PASS | Business owner recorded in CMDB. |
| CLM-02 | Responsible system administrator identified | PASS | Responsible admin group assigned. |
| CLM-03 | Business purpose and data classification documented | FAIL | No documented purpose or data classification. |

## M &mdash; Minimized (87.5/100)

| Check | Name | Status | Detail |
|---|---|---|---|
| MIN-01 | Unnecessary services and daemons disabled | PASS | Unnecessary services disabled per baseline. |
| MIN-02 | Unused or unauthorized software removed | PARTIAL | Two unapproved applications detected. |
| MIN-03 | Host firewall enabled; unused network ports closed | PASS | Host firewall on; only required ports open. |
| MIN-04 | Recognized hardening baseline (e.g. CIS Benchmark) applied | PASS | CIS Benchmark Level 1 applied. |

## A &mdash; Assessed (50.0/100)

| Check | Name | Status | Detail |
|---|---|---|---|
| ASM-01 | Authenticated vulnerability scanning performed on schedule | PASS | Authenticated scan completed 6 days ago. |
| ASM-02 | Configuration / compliance assessment performed on schedule | PARTIAL | Compliance scan run; cadence exceeds policy. |
| ASM-03 | Findings tracked to remediation against defined SLAs | FAIL | 12 findings open past remediation SLA. |

## C &mdash; Current (87.5/100)

| Check | Name | Status | Detail |
|---|---|---|---|
| CUR-01 | Operating-system patch level within policy | PASS | OS patch level current. |
| CUR-02 | Third-party software updated within policy | PARTIAL | Two third-party apps one cycle behind. |
| CUR-03 | Firmware / BIOS current | PASS | Firmware current. |
| CUR-04 | Certificates and cryptographic material valid and unexpired | PASS | No expired certificates detected. |
