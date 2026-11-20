Drafted with AI assistance (Claude Code, Anthropic) for the researcher's review.

# NIST SP 800-30 Rev. 1 fields: review table

`data/control-mappings.yaml` holds, in its `threats:` section, one
threat-source type and one short threat event per built-in check. The risk
register shows them as two of its NIST SP 800-30 Rev. 1 fields
(docs/methodology.md section 9). Both were drafted with AI assistance and
carry `review: drafted` until you confirm them, the way you confirmed the CIS
IG and FAIR ratings on 2026-08-29.

The table shows, beside the drafted fields, the fields the register maps onto
SP 800-30's other elements: likelihood is the FAIR frequency band and impact
the FAIR magnitude band (both confirmed on 2026-08-29), risk is the register's
matrix rating, and the recommended response is the check's remediation text.
The remediation text was not part of the 2026-08-29 review, so it gets its own
column here.

## Threat-source types

Paraphrased from SP 800-30 Rev. 1, Appendix D:

- **adversarial**: individuals, groups, organizations or states that intend
  to cause harm, from outside or inside the organization;
- **accidental**: mistakes that users or administrators make in the course of
  their normal work;
- **structural**: failures of equipment, environmental controls or software,
  through ageing, resource exhaustion or use beyond their limits;
- **environmental**: natural or man-made disasters, and outages of the
  infrastructure the organization depends on.

## What each review column asks

- **Type confirmed**: is this the type of source most likely to exploit a
  failure of the check? Write Y, or the type you would use instead.
- **Event confirmed**: is the event a fair, generic description of what can go
  wrong when the check fails? It is generic per check, not threat intelligence
  about any organization. Write Y, or your corrected text.
- **FAIR bands fit this threat source**: the FAIR bands were rated for how
  often adversaries exploit the failure in the wild. On a row whose type is
  accidental or structural they stand in for likelihood and impact without
  having been rated for that source. Write Y if they fit anyway, or N and what
  would fit in Notes.
- **Response text confirmed**: is the remediation text a specific, actionable
  next step? It is one fixed text per check, so for some PARTIAL results it
  does not match the gap (CTL-02 "no elevation path at all", ASM-01 and ASM-02
  "performed, but no date or interval"); note such cases. Write Y, or your
  corrected text.

## How to record a confirmation

1. Fill in the four review columns and Notes below, and the reviewer and date
   line.
2. In `data/control-mappings.yaml`, set `review: confirmed` on each confirmed
   row of `threats:`, and copy in any corrected type or event text. Keep the
   table and the file in step: `tests/test_sp800_30_metadata.py` checks that
   the table's drafted columns equal the file.
3. Record the date and the reviewer in docs/methodology.md section 9, under
   "Provenance", as the 2026-08-29 record does.
4. Run the test suite and the synthetic kit again (miccmac_study/README.md,
   test checklist steps 1 and 2) before the freeze.

## Timing and the baseline freeze

- Confirm before the baseline freeze (Sunday 22 November 2026), then commit
  and freeze as miccmac_study/README.md describes.
- If the review cannot finish before the freeze, record your confirmations in
  this file only, which is outside `miccmac/` and `data/`, until the last
  host's tool run. Apply them to `data/control-mappings.yaml` afterwards, as a
  later tool version recorded in the protocol log, never during the study:
  any edit there between the freeze and the last tool run makes
  `tool_tree_clean` false, and a commit splits the study's outputs across two
  tool commits. The baseline outputs then say `review: drafted`; declare that
  in the AI-use log.
- To drop the drafted fields instead, delete the `threats:` section from
  `data/control-mappings.yaml` before the freeze. The register then shows
  "n/a (not declared)" for the threat-source type and event and keeps the
  mapped fields. Remove the two tests that require the section and this table
  (`test_the_shipped_mappings_cover_every_check_with_valid_drafted_fields` and
  `test_the_review_table_lists_every_check_with_the_drafted_fields` in
  `tests/test_sp800_30_metadata.py`).

Reviewer: ______   Date: ______

| Check | Property | Check name | Threat source type (drafted) | Threat event (drafted) | Likelihood = FAIR frequency (confirmed 2026-08-29) | Impact = FAIR magnitude (confirmed 2026-08-29) | Risk (matrix) | Response = remediation text (not part of the 2026-08-29 review) | Type confirmed (Y, or the corrected type) | Event confirmed (Y, or the corrected text) | FAIR bands fit this threat source (Y/N) | Response text confirmed (Y, or the corrected text) | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MON-01 | Monitored | Endpoint security logging enabled | adversarial | An intruder acts on the device without leaving a security-log record, so the compromise is neither detected nor investigated. | HIGH | MEDIUM | HIGH | Enable OS-native security/audit logging (e.g. Windows Event Logging, Linux auditd) on the device and confirm it is actively generating events. |  |  |  |  |  |
| MON-02 | Monitored | Logs forwarded to a centralized SIEM / log platform | adversarial | An intruder deletes or alters the device's local logs to hide a compromise, and no copy of them exists off the device. | MEDIUM | MEDIUM | MODERATE | Deploy a log-forwarding agent and point it at the organization's centralized SIEM/log platform so this device's logs are retained off-host. |  |  |  |  |  |
| MON-03 | Monitored | EDR / endpoint telemetry agent installed and healthy | adversarial | Malware runs on the device and spreads, with no endpoint telemetry agent to detect or contain it. | HIGH | HIGH | CRITICAL | Install and start the standard EDR/endpoint telemetry agent for this fleet; confirm the agent service is running and reporting healthy. |  |  |  |  |  |
| MON-04 | Monitored | Audit policy covers authentication, privilege, and process events | adversarial | An attacker logs on with stolen credentials or escalates privileges, and those logons, privilege use and processes are not audited. | MEDIUM | MEDIUM | MODERATE | Apply the organization's baseline audit policy (or auditd rules) so authentication, privilege-use, and process-creation events are captured. |  |  |  |  |  |
| INV-01 | Inventoried | Device present in the authoritative asset inventory | adversarial | An attacker targets a device the organization does not know it has, which therefore misses patching, monitoring and policy. | MEDIUM | MEDIUM | MODERATE | Register the device in the authoritative CMDB/asset inventory system (or supply it via --inventory-record) so it is tracked as a known asset. |  |  |  |  |  |
| INV-02 | Inventoried | Hardware attributes recorded (make, model, serial) | adversarial | A device is stolen or its hardware swapped, and the change cannot be traced because its make, model and serial are not recorded. | LOW | LOW | LOW | Populate hardware make/model/serial (e.g. via DMI/SMBIOS) so osquery's system_info table returns non-empty vendor/model/serial values. |  |  |  |  |  |
| INV-03 | Inventoried | Installed-software inventory maintained for the device | adversarial | An attacker exploits vulnerable or unauthorized software the organization cannot see on the device, so it is never patched or removed. | MEDIUM | MEDIUM | MODERATE | Confirm the device's package manager (apt/dpkg, etc.) is queryable and its installed-software list is being collected into inventory. |  |  |  |  |  |
| INV-04 | Inventoried | Inventory record reviewed within the policy interval | accidental | Administrators act on an out-of-date asset record, so changes to the device's owner, role or configuration go unnoticed. | LOW | LOW | LOW | Re-review and re-date the device's inventory record, and schedule a recurring review so it never again exceeds the policy interval. |  |  |  |  |  |
| CTL-01 | Controlled | Device enrolled in central configuration management / MDM | adversarial | An attacker exploits an insecure local setting that no central configuration-management system enforces or corrects. | HIGH | HIGH | CRITICAL | Enroll the device in the organization's central configuration-management/MDM platform. |  |  |  |  |  |
| CTL-02 | Controlled | Administrative privileges restricted (least privilege) | adversarial | An attacker who compromises a routine account, or logs on directly as root or the built-in Administrator, gains full control of the device. | HIGH | HIGH | CRITICAL | Remove standing local-administrator rights from routine accounts; grant elevation via a just-in-time/PAM mechanism instead. |  |  |  |  |  |
| CTL-03 | Controlled | Access governed by identity-aware / conditional-access policy | adversarial | An attacker with stolen credentials reaches the device's resources from an untrusted context, because access is not checked against identity-aware policy. | MEDIUM | HIGH | HIGH | Place the device behind an identity-aware proxy or conditional-access policy tied to the organization's IdP. |  |  |  |  |  |
| CTL-04 | Controlled | Configuration baseline enforced and drift-monitored | accidental | A change by an administrator or user moves the device away from its secure baseline, and the drift is neither detected nor reverted. | MEDIUM | MEDIUM | MODERATE | Assign the device a configuration baseline (e.g. GPO/Ansible/Intune profile) and enable drift detection/auto-remediation. |  |  |  |  |  |
| CLM-01 | Claimed | Accountable business owner assigned and recorded | accidental | Decisions about the device's risks, such as fixes, exceptions or retirement, are never made, because no accountable business owner is on record. | LOW | LOW | LOW | Record a named accountable business owner for the device in the asset/inventory system. |  |  |  |  |  |
| CLM-02 | Claimed | Responsible system administrator identified | accidental | Security alerts, patches and incidents for the device go unhandled, because no responsible administrator or team is identified. | LOW | LOW | LOW | Record the responsible system administrator or owning team for the device. |  |  |  |  |  |
| CLM-03 | Claimed | Business purpose and data classification documented | accidental | Sensitive data on the device is handled without the protection its classification calls for, because its purpose and classification are not documented. | LOW | MEDIUM | LOW | Document the device's business purpose and assign it a data classification label. |  |  |  |  |  |
| MIN-01 | Minimized | Unnecessary services and daemons disabled | adversarial | An attacker exploits a legacy or unneeded network service running on the device, such as telnet, rsh, FTP or SNMP. | MEDIUM | MEDIUM | MODERATE | Disable and stop any running services/daemons not required for the device's documented purpose. |  |  |  |  |  |
| MIN-02 | Minimized | Unused or unauthorized software removed | adversarial | An attacker exploits a flaw in legacy or unneeded software, or in an enabled legacy feature such as SMBv1, on the device. | MEDIUM | MEDIUM | MODERATE | Uninstall software packages that are not on the approved/required list for this device's role. |  |  |  |  |  |
| MIN-03 | Minimized | Host firewall enabled; unused network ports closed | adversarial | An attacker on the network reaches an exposed port or service that a host firewall would have blocked. | HIGH | HIGH | CRITICAL | Enable the host firewall and stop listening on any network-reachable port not required by an approved service. |  |  |  |  |  |
| MIN-04 | Minimized | Recognized hardening baseline (e.g. CIS Benchmark) applied | adversarial | An attacker takes advantage of insecure default operating-system settings that a recognized hardening baseline would have changed. | MEDIUM | MEDIUM | MODERATE | Apply a recognized hardening baseline (e.g. a CIS Benchmark) appropriate to the device's OS. |  |  |  |  |  |
| ASM-01 | Assessed | Authenticated vulnerability scanning performed on schedule | adversarial | An attacker exploits a known vulnerability on the device that a scheduled authenticated scan would have found. | MEDIUM | MEDIUM | MODERATE | Enroll the device in the organization's authenticated vulnerability-scanning schedule. |  |  |  |  |  |
| ASM-02 | Assessed | Configuration / compliance assessment performed on schedule | adversarial | An attacker exploits a configuration weakness on the device that a scheduled compliance assessment would have reported. | LOW | MEDIUM | LOW | Enroll the device in a recurring configuration/compliance assessment (e.g. CIS-CAT, SCAP). |  |  |  |  |  |
| ASM-03 | Assessed | Findings tracked to remediation against defined SLAs | adversarial | An attacker exploits a vulnerability that was found but never fixed, because findings are not tracked to remediation. | MEDIUM | MEDIUM | MODERATE | Load this device's open findings into the remediation-tracking system with SLA due dates and named owners. |  |  |  |  |  |
| CUR-01 | Current | Operating-system patch level within policy | adversarial | An attacker exploits a published operating-system vulnerability for which a patch exists but is not installed. | HIGH | HIGH | CRITICAL | Apply pending OS security patches and confirm the patch cadence meets policy (e.g. via unattended-upgrades/WSUS). |  |  |  |  |  |
| CUR-02 | Current | Third-party software updated within policy | adversarial | An attacker exploits a known vulnerability in an out-of-date third-party application on the device. | HIGH | HIGH | CRITICAL | Update out-of-date third-party applications and enroll the device in third-party patch management. |  |  |  |  |  |
| CUR-03 | Current | Firmware / BIOS current | adversarial | An attacker exploits a known firmware or BIOS flaw to gain persistent control below the operating system. | LOW | MEDIUM | LOW | Update the device's firmware/BIOS to the vendor's current supported version. |  |  |  |  |  |
| CUR-04 | Current | Certificates and cryptographic material valid and unexpired | structural | Certificates or keys on the device pass their validity period, so services that rely on them fail or outdated trust material stays in use. | MEDIUM | MEDIUM | MODERATE | Renew or replace any expired/expiring certificates and rotate stale cryptographic material before it lapses. |  |  |  |  |  |
