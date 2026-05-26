"""MICCMAC property: Minimized (M).

Intent: The device's attack surface is reduced to the minimum required for its documented purpose.

Each check below is a SCAFFOLD. Replace the body of ``_run_checks`` with real
detection logic (local collection, agent query, API call, config parse, etc.)
and set each CheckResult's ``status``, ``detail``, and ``evidence`` accordingly.
The methodology and scoring rules are described in docs/methodology.md.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "minimized"
LETTER = "M"
TITLE = "Minimized"


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    """Return one CheckResult per check for this property.

    TODO(implementer): replace the NOT_IMPLEMENTED stubs below with real
    evaluations. A check should set:
        status   -> Status.PASS / PARTIAL / FAIL / NOT_APPLICABLE
        detail   -> short human-readable finding
        evidence -> command output, file path, API response id, etc.
    """
    results: list[CheckResult] = []
    # --- MIN-01: Unnecessary services and daemons disabled ---
    results.append(CheckResult(
        check_id="MIN-01",
        name="Unnecessary services and daemons disabled",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-7', 'CIS v8 4.8'],
    ))
    # --- MIN-02: Unused or unauthorized software removed ---
    results.append(CheckResult(
        check_id="MIN-02",
        name="Unused or unauthorized software removed",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-7(1)', 'CIS v8 2.3'],
    ))
    # --- MIN-03: Host firewall enabled; unused network ports closed ---
    results.append(CheckResult(
        check_id="MIN-03",
        name="Host firewall enabled; unused network ports closed",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 SC-7', 'CIS v8 4.5'],
    ))
    # --- MIN-04: Recognized hardening baseline (e.g. CIS Benchmark) applied ---
    results.append(CheckResult(
        check_id="MIN-04",
        name="Recognized hardening baseline (e.g. CIS Benchmark) applied",
        status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
        detail="Check not yet implemented.",
        control_refs=['NIST 800-53 CM-6', 'CIS v8 4.1'],
    ))

    return results


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Minimized property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
