"""MICCMAC property: Claimed (C).

Intent: The device has a known, accountable owner and administrator, and a documented business purpose.

Each check below is a SCAFFOLD. Replace the body of ``_run_checks`` with real
detection logic (local collection, agent query, API call, config parse, etc.)
and set each CheckResult's ``status``, ``detail``, and ``evidence`` accordingly.
The methodology and scoring rules are described in docs/methodology.md.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "claimed"
LETTER = "C"
TITLE = "Claimed"


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    """Return one CheckResult per check for this property.

    TODO(implementer): replace the NOT_IMPLEMENTED stubs below with real
    evaluations. A check should set:
        status   -> Status.PASS / PARTIAL / FAIL / NOT_APPLICABLE
        detail   -> short human-readable finding
        evidence -> command output, file path, API response id, etc.
    """
    results: list[CheckResult] = []
    # --- CLM-01: Accountable business owner assigned and recorded ---
    results.append(CheckResult(
        check_id="CLM-01",
        name="Accountable business owner assigned and recorded",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-8', 'CIS v8 1.1'],
    ))
    # --- CLM-02: Responsible system administrator identified ---
    results.append(CheckResult(
        check_id="CLM-02",
        name="Responsible system administrator identified",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 PS-2', 'CIS v8 1.1'],
    ))
    # --- CLM-03: Business purpose and data classification documented ---
    results.append(CheckResult(
        check_id="CLM-03",
        name="Business purpose and data classification documented",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 RA-2', 'CIS v8 3.2'],
    ))

    return results


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Claimed property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
