"""MICCMAC property: Monitored (M).

Intent: The device's security-relevant activity is logged, retained, and continuously monitored so that compromise can be detected.

Each check below is a SCAFFOLD. Replace the body of ``_run_checks`` with real
detection logic (local collection, agent query, API call, config parse, etc.)
and set each CheckResult's ``status``, ``detail``, and ``evidence`` accordingly.
The methodology and scoring rules are described in docs/methodology.md.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "monitored"
LETTER = "M"
TITLE = "Monitored"


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    """Return one CheckResult per check for this property.

    TODO(implementer): replace the NOT_IMPLEMENTED stubs below with real
    evaluations. A check should set:
        status   -> Status.PASS / PARTIAL / FAIL / NOT_APPLICABLE
        detail   -> short human-readable finding
        evidence -> command output, file path, API response id, etc.
    """
    results: list[CheckResult] = []
    # --- MON-01: Endpoint security logging enabled ---
    results.append(CheckResult(
        check_id="MON-01",
        name="Endpoint security logging enabled",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 AU-2', 'CIS v8 8.2'],
    ))
    # --- MON-02: Logs forwarded to a centralized SIEM / log platform ---
    results.append(CheckResult(
        check_id="MON-02",
        name="Logs forwarded to a centralized SIEM / log platform",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 AU-6', 'CIS v8 8.9'],
    ))
    # --- MON-03: EDR / endpoint telemetry agent installed and healthy ---
    results.append(CheckResult(
        check_id="MON-03",
        name="EDR / endpoint telemetry agent installed and healthy",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 SI-4', 'CIS v8 13.7'],
    ))
    # --- MON-04: Audit policy covers authentication, privilege, and process events ---
    results.append(CheckResult(
        check_id="MON-04",
        name="Audit policy covers authentication, privilege, and process events",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 AU-2', 'CIS v8 8.5'],
    ))

    return results


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Monitored property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
