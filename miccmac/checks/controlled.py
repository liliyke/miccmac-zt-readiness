"""MICCMAC property: Controlled (C).

Intent: Configuration and access to the device are centrally governed by enforced policy, not left to local discretion.

Each check below is a SCAFFOLD. Replace the body of ``_run_checks`` with real
detection logic (local collection, agent query, API call, config parse, etc.)
and set each CheckResult's ``status``, ``detail``, and ``evidence`` accordingly.
The methodology and scoring rules are described in docs/methodology.md.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "controlled"
LETTER = "C"
TITLE = "Controlled"


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    """Return one CheckResult per check for this property.

    TODO(implementer): replace the NOT_IMPLEMENTED stubs below with real
    evaluations. A check should set:
        status   -> Status.PASS / PARTIAL / FAIL / NOT_APPLICABLE
        detail   -> short human-readable finding
        evidence -> command output, file path, API response id, etc.
    """
    results: list[CheckResult] = []
    # --- CTL-01: Device enrolled in central configuration management / MDM ---
    results.append(CheckResult(
        check_id="CTL-01",
        name="Device enrolled in central configuration management / MDM",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-2', 'CIS v8 4.1'],
    ))
    # --- CTL-02: Administrative privileges restricted (least privilege) ---
    results.append(CheckResult(
        check_id="CTL-02",
        name="Administrative privileges restricted (least privilege)",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 AC-6', 'CIS v8 5.4'],
    ))
    # --- CTL-03: Access governed by identity-aware / conditional-access policy ---
    results.append(CheckResult(
        check_id="CTL-03",
        name="Access governed by identity-aware / conditional-access policy",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-207 Tenet 4', 'NIST 800-53 AC-3', 'CIS v8 6.7'],
    ))
    # --- CTL-04: Configuration baseline enforced and drift-monitored ---
    results.append(CheckResult(
        check_id="CTL-04",
        name="Configuration baseline enforced and drift-monitored",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-6', 'CIS v8 4.2'],
    ))

    return results


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Controlled property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
