"""MICCMAC property: Assessed (A).

Intent: The device is regularly and authoritatively assessed for vulnerabilities and configuration weakness.

Like Claimed, none of these three checks are device-observable: whether
vulnerability scans or compliance assessments were performed *on schedule*,
and whether findings are tracked against remediation SLAs, are facts about
an external scanning/GRC process and its history -- not something a
point-in-time device query can answer (an installed scanner *agent* doesn't
prove scans actually ran on schedule). All three read
context["attestation"] (via --attestation <path-to-json>).

Follows Claimed's stub-gate pattern: gates on the context being entirely
empty (the true default invocation), not on facts-presence, since this
property never uses context["facts"] at all. See
miccmac/checks/claimed.py's module docstring for the full rationale.
"""
from __future__ import annotations

import datetime

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "assessed"
LETTER = "A"
TITLE = "Assessed"

_CONTROL_REFS = {
    "ASM-01": ["NIST 800-53 RA-5", "CIS v8 7.5"],
    "ASM-02": ["NIST 800-53 CA-2", "CIS v8 7.6"],
    "ASM-03": ["NIST 800-53 CA-7", "CIS v8 7.1"],
}

_NAMES = {
    "ASM-01": "Authenticated vulnerability scanning performed on schedule",
    "ASM-02": "Configuration / compliance assessment performed on schedule",
    "ASM-03": "Findings tracked to remediation against defined SLAs",
}


def _stub_result(check_id: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        name=_NAMES[check_id],
        status=Status.NOT_IMPLEMENTED,
        detail="Check not yet implemented.",
        control_refs=_CONTROL_REFS[check_id],
    )


def _stub_checks() -> list[CheckResult]:
    return [_stub_result(cid) for cid in ("ASM-01", "ASM-02", "ASM-03")]


def _not_applicable(check_id: str, missing_key: str) -> CheckResult:
    return CheckResult(
        check_id=check_id, name=_NAMES[check_id], status=Status.NOT_APPLICABLE,
        detail=f"No --attestation supplied for {missing_key!r}; scan/assessment history is "
               f"an external process fact, not observable from the device itself.",
        control_refs=_CONTROL_REFS[check_id],
    )


def _check_scheduled_activity(check_id: str, missing_key: str, record: dict,
                              date_field: str, activity_label: str) -> CheckResult:
    """Shared logic for ASM-01/ASM-02: performed=bool + a last-run date
    checked against an interval_days policy, mirroring INV-04's recency
    check for inventory review."""
    if not record.get("performed"):
        return CheckResult(
            check_id=check_id, name=_NAMES[check_id], status=Status.FAIL,
            detail=f"Attestation states {activity_label} is not performed.",
            control_refs=_CONTROL_REFS[check_id],
        )
    last_date = record.get(date_field)
    interval_days = record.get("interval_days")
    if not last_date or not interval_days:
        return CheckResult(
            check_id=check_id, name=_NAMES[check_id], status=Status.PARTIAL,
            detail=f"Attestation states {activity_label} is performed, but no {date_field!r} "
                   f"and/or 'interval_days' policy was supplied to verify cadence.",
            control_refs=_CONTROL_REFS[check_id],
        )
    try:
        parsed_date = datetime.date.fromisoformat(last_date)
    except ValueError:
        return CheckResult(
            check_id=check_id, name=_NAMES[check_id], status=Status.ERROR,
            detail=f"Attestation's {date_field}={last_date!r} is not a valid ISO date.",
            control_refs=_CONTROL_REFS[check_id],
        )
    age_days = (datetime.date.today() - parsed_date).days
    if age_days <= interval_days:
        status = Status.PASS
        detail = f"{activity_label} last performed {age_days} day(s) ago (policy: {interval_days})."
    else:
        status = Status.FAIL
        detail = (f"{activity_label} last performed {age_days} day(s) ago, exceeding the "
                 f"{interval_days}-day policy interval.")
    return CheckResult(
        check_id=check_id, name=_NAMES[check_id], status=status, detail=detail,
        control_refs=_CONTROL_REFS[check_id],
    )


def _check_asm01(attestation: dict | None) -> CheckResult:
    if attestation is None or "vulnerability_scanning" not in attestation:
        return _not_applicable("ASM-01", "vulnerability_scanning")
    return _check_scheduled_activity(
        "ASM-01", "vulnerability_scanning", attestation["vulnerability_scanning"] or {},
        "last_scan", "Vulnerability scanning",
    )


def _check_asm02(attestation: dict | None) -> CheckResult:
    if attestation is None or "compliance_assessment" not in attestation:
        return _not_applicable("ASM-02", "compliance_assessment")
    return _check_scheduled_activity(
        "ASM-02", "compliance_assessment", attestation["compliance_assessment"] or {},
        "last_assessment", "Compliance assessment",
    )


def _check_asm03(attestation: dict | None) -> CheckResult:
    if attestation is None or "finding_remediation_sla" not in attestation:
        return _not_applicable("ASM-03", "finding_remediation_sla")
    sla = attestation["finding_remediation_sla"] or {}
    if sla.get("tracked"):
        sla_days = sla.get("sla_days")
        status = Status.PASS
        detail = (f"Attestation confirms findings are tracked to remediation"
                 f"{f' against a {sla_days}-day SLA' if sla_days else ''}.")
    else:
        status = Status.FAIL
        detail = "Attestation states findings are NOT tracked to remediation against an SLA."
    return CheckResult(
        check_id="ASM-03", name=_NAMES["ASM-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["ASM-03"],
    )


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    if not context:
        return _stub_checks()

    attestation = context.get("attestation")
    return [
        _check_asm01(attestation),
        _check_asm02(attestation),
        _check_asm03(attestation),
    ]


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Assessed property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
