"""MICCMAC property: Claimed (C).

Intent: The device has a known, accountable owner and administrator, and a documented business purpose.

None of these three checks are device-observable: whether a device has an
accountable business owner, a named administrator, or a documented business
purpose/data classification are organizational record-keeping facts, not
something osquery (or any device-local connector) can query. All three read
context["attestation"] (via --attestation <path-to-json>), the same external
-fact mechanism CTL-03 uses -- see docs/methodology.md.

Because this property never uses context["facts"] at all, its stub-fallback
gate is different from Inventoried/Monitored/Controlled: those gate on
facts-presence (their primary data source); Claimed gates on whether
*anything* was supplied at all (an empty context -- the true default
invocation), falling back to the original NOT_IMPLEMENTED stub only then.
Any other invocation (e.g. --connector alone, --attestation alone) reaches
real logic, and each check reports NOT_APPLICABLE for itself if its specific
attestation key is missing, rather than blanket NOT_IMPLEMENTED for checks
that were, in fact, evaluated.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "claimed"
LETTER = "C"
TITLE = "Claimed"

_CONTROL_REFS = {
    "CLM-01": ["NIST 800-53 CM-8", "CIS v8 1.1"],
    "CLM-02": ["NIST 800-53 PS-2", "CIS v8 1.1"],
    "CLM-03": ["NIST 800-53 RA-2", "CIS v8 3.2"],
}

_NAMES = {
    "CLM-01": "Accountable business owner assigned and recorded",
    "CLM-02": "Responsible system administrator identified",
    "CLM-03": "Business purpose and data classification documented",
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
    return [_stub_result(cid) for cid in ("CLM-01", "CLM-02", "CLM-03")]


def _not_applicable(check_id: str, missing_key: str) -> CheckResult:
    return CheckResult(
        check_id=check_id, name=_NAMES[check_id], status=Status.NOT_APPLICABLE,
        detail=f"No --attestation supplied for {missing_key!r}; this is an organizational "
               f"record-keeping fact, not observable from the device itself.",
        control_refs=_CONTROL_REFS[check_id],
    )


def _check_clm01(attestation: dict | None) -> CheckResult:
    if attestation is None or "business_owner" not in attestation:
        return _not_applicable("CLM-01", "business_owner")
    owner = attestation["business_owner"] or {}
    if owner.get("assigned") and owner.get("name"):
        status, detail = Status.PASS, f"Business owner recorded: {owner['name']!r}."
    else:
        status, detail = Status.FAIL, "Attestation states no business owner is assigned/recorded."
    return CheckResult(
        check_id="CLM-01", name=_NAMES["CLM-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CLM-01"],
    )


def _check_clm02(attestation: dict | None) -> CheckResult:
    if attestation is None or "system_administrator" not in attestation:
        return _not_applicable("CLM-02", "system_administrator")
    admin = attestation["system_administrator"] or {}
    if admin.get("assigned") and admin.get("name"):
        status, detail = Status.PASS, f"Responsible system administrator identified: {admin['name']!r}."
    else:
        status, detail = Status.FAIL, "Attestation states no responsible system administrator is identified."
    return CheckResult(
        check_id="CLM-02", name=_NAMES["CLM-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CLM-02"],
    )


def _check_clm03(attestation: dict | None) -> CheckResult:
    if attestation is None or "business_purpose" not in attestation:
        return _not_applicable("CLM-03", "business_purpose")
    purpose = attestation["business_purpose"] or {}
    documented = bool(purpose.get("documented"))
    classification = purpose.get("data_classification")
    if documented and classification:
        status = Status.PASS
        detail = f"Business purpose documented; data classification: {classification!r}."
    elif documented:
        status = Status.PARTIAL
        detail = "Business purpose documented, but no data classification recorded."
    else:
        status = Status.FAIL
        detail = "Attestation states business purpose is not documented."
    return CheckResult(
        check_id="CLM-03", name=_NAMES["CLM-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CLM-03"],
    )


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    if not context:
        return _stub_checks()

    attestation = context.get("attestation")
    return [
        _check_clm01(attestation),
        _check_clm02(attestation),
        _check_clm03(attestation),
    ]


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Claimed property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
