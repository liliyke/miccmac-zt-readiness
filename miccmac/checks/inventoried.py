"""MICCMAC property: Inventoried (I).

Intent: The device is known to the organization and tracked in an authoritative hardware and software inventory.

Each check below is a SCAFFOLD. Replace the body of ``_run_checks`` with real
detection logic (local collection, agent query, API call, config parse, etc.)
and set each CheckResult's ``status``, ``detail``, and ``evidence`` accordingly.
The methodology and scoring rules are described in docs/methodology.md.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "inventoried"
LETTER = "I"
TITLE = "Inventoried"


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    """Return one CheckResult per check for this property.

    TODO(implementer): replace the NOT_IMPLEMENTED stubs below with real
    evaluations. A check should set:
        status   -> Status.PASS / PARTIAL / FAIL / NOT_APPLICABLE
        detail   -> short human-readable finding
        evidence -> command output, file path, API response id, etc.
    """
    results: list[CheckResult] = []
    # --- INV-01: Device present in the authoritative asset inventory ---
    results.append(CheckResult(
        check_id="INV-01",
        name="Device present in the authoritative asset inventory",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-8', 'CIS v8 1.1'],
    ))
    # --- INV-02: Hardware attributes recorded (make, model, serial) ---
    results.append(CheckResult(
        check_id="INV-02",
        name="Hardware attributes recorded (make, model, serial)",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-8', 'CIS v8 1.1'],
    ))
    # --- INV-03: Installed-software inventory maintained for the device ---
    results.append(CheckResult(
        check_id="INV-03",
        name="Installed-software inventory maintained for the device",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-8(2)', 'CIS v8 2.1'],
    ))
    # --- INV-04: Inventory record reviewed within the policy interval ---
    results.append(CheckResult(
        check_id="INV-04",
        name="Inventory record reviewed within the policy interval",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 PM-5', 'CIS v8 1.1'],
    ))

    return results


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Inventoried property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
