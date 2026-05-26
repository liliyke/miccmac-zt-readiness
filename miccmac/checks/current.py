"""MICCMAC property: Current (C).

Intent: The device is kept in its most secure state: patched, updated, and free of expired cryptographic material.

Each check below is a SCAFFOLD. Replace the body of ``_run_checks`` with real
detection logic (local collection, agent query, API call, config parse, etc.)
and set each CheckResult's ``status``, ``detail``, and ``evidence`` accordingly.
The methodology and scoring rules are described in docs/methodology.md.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "current"
LETTER = "C"
TITLE = "Current"


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    """Return one CheckResult per check for this property.

    TODO(implementer): replace the NOT_IMPLEMENTED stubs below with real
    evaluations. A check should set:
        status   -> Status.PASS / PARTIAL / FAIL / NOT_APPLICABLE
        detail   -> short human-readable finding
        evidence -> command output, file path, API response id, etc.
    """
    results: list[CheckResult] = []
    # --- CUR-01: Operating-system patch level within policy ---
    results.append(CheckResult(
        check_id="CUR-01",
        name="Operating-system patch level within policy",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 SI-2', 'CIS v8 7.3'],
    ))
    # --- CUR-02: Third-party software updated within policy ---
    results.append(CheckResult(
        check_id="CUR-02",
        name="Third-party software updated within policy",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 SI-2', 'CIS v8 7.4'],
    ))
    # --- CUR-03: Firmware / BIOS current ---
    results.append(CheckResult(
        check_id="CUR-03",
        name="Firmware / BIOS current",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 SI-2', 'CIS v8 7.3'],
    ))
    # --- CUR-04: Certificates and cryptographic material valid and unexpired ---
    results.append(CheckResult(
        check_id="CUR-04",
        name="Certificates and cryptographic material valid and unexpired",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 SC-12', 'CIS v8 3.10'],
    ))

    return results


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Current property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
