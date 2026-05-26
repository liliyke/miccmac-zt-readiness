"""MICCMAC property: Assessed (A).

Intent: The device is regularly and authoritatively assessed for vulnerabilities and configuration weakness.

Each check below is a SCAFFOLD. Replace the body of ``_run_checks`` with real
detection logic (local collection, agent query, API call, config parse, etc.)
and set each CheckResult's ``status``, ``detail``, and ``evidence`` accordingly.
The methodology and scoring rules are described in docs/methodology.md.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "assessed"
LETTER = "A"
TITLE = "Assessed"


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    """Return one CheckResult per check for this property.

    TODO(implementer): replace the NOT_IMPLEMENTED stubs below with real
    evaluations. A check should set:
        status   -> Status.PASS / PARTIAL / FAIL / NOT_APPLICABLE
        detail   -> short human-readable finding
        evidence -> command output, file path, API response id, etc.
    """
    results: list[CheckResult] = []
    # --- ASM-01: Authenticated vulnerability scanning performed on schedule ---
    results.append(CheckResult(
        check_id="ASM-01",
        name="Authenticated vulnerability scanning performed on schedule",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 RA-5', 'CIS v8 7.5'],
    ))
    # --- ASM-02: Configuration / compliance assessment performed on schedule ---
    results.append(CheckResult(
        check_id="ASM-02",
        name="Configuration / compliance assessment performed on schedule",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CA-2', 'CIS v8 7.6'],
    ))
    # --- ASM-03: Findings tracked to remediation against defined SLAs ---
    results.append(CheckResult(
        check_id="ASM-03",
        name="Findings tracked to remediation against defined SLAs",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CA-7', 'CIS v8 7.1'],
    ))

    return results


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Assessed property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
