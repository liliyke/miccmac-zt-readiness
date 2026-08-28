"""Example custom check plugin: an org-specific control attached to the
Controlled (C) property.

Drop a .py file like this one into your custom_checks_dir (see
examples/miccmac-config.example.yaml) and the engine will merge its checks
into the matching built-in property -- never as a new, eighth property.
"""
from __future__ import annotations

from miccmac.model import CheckResult, Status

CHECK_IDS = ["ACME-01"]
ATTACH_TO = "controlled"

# Required: one entry per CHECK_IDS id, with at least a CIS Implementation
# Group, so this check plugs into risk-register prioritization the same way
# a built-in check does (fair_frequency/fair_magnitude are optional -- omit
# them and the entry still gets its CIS IG, but its risk_rating stays
# UNRATED, since a rating needs both FAIR axes).
RISK_METADATA = {
    "ACME-01": {"cis_ig": "IG2", "fair_frequency": "MEDIUM", "fair_magnitude": "MEDIUM"},
}


def run_checks(target: str, context: dict) -> list[CheckResult]:
    return [
        CheckResult(
            check_id="ACME-01",
            name="Device enrolled in Acme Corp PAM vault",
            status=Status.NOT_IMPLEMENTED,  # TODO: implement detection logic
            detail="Check not yet implemented.",
            control_refs=["Acme Internal Policy 4.2"],
        )
    ]
