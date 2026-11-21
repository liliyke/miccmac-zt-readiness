"""MICCMAC property: Inventoried (I).

Intent: The device is known to the organization and tracked in an authoritative hardware and software inventory.

Real detection logic (INV-02, INV-03) reads osquery facts from
context["facts"] (see miccmac/connectors/ssh_osquery.py). INV-01 and INV-04
are NOT derivable from the device alone -- whether a device is tracked in an
authoritative asset inventory, and when that record was last reviewed, are
facts about an *external* inventory system (a CMDB), not something the
device can self-report. Those two checks read context["inventory_record"],
a caller-supplied dict representing that external system's record for this
device (see miccmac/cli.py's --inventory-record).

On Windows targets (facts["os"]["platform"] == "windows", populated by
miccmac/connectors/ssh_osquery_windows.py), INV-03 branches to count
facts["programs"] (Win32 programs from the registry Uninstall keys) instead
of facts["deb_packages"]. INV-02 needs no branch -- it already reads the
cross-platform facts["system_info"] key on both platforms.

When no connector was used at all (context has no "facts" key -- the
scaffold/default invocation), all four checks fall back to the original
NOT_IMPLEMENTED stub behavior, so the check results of `miccmac assess
<target>` with no flags are unchanged from the Alpha scaffold (the report
itself now adds the default CMMI lens, every level Unassessed).

INV-04 counts the age of the last review against miccmac.clock's reference
date: the --as-of date when one was given (context["as_of"]), otherwise
today.

With an --as-of date, a detail that reports an age ends in " (as of ...)".
The missing-data markers (CheckResult.missing_data) of INV-01 and INV-04
cover the inventory record not supplied (NOT_APPLICABLE), and INV-04's
unreadable last_reviewed date (ERROR), with the whole record as each
marker's example.
"""
from __future__ import annotations

import datetime
import json

from miccmac import clock
from miccmac.model import CheckResult, MissingData, PropertyResult, Status

KEY = "inventoried"
LETTER = "I"
TITLE = "Inventoried"

# NIST SP 800-53 PM-5 doesn't mandate a specific review cadence; 90 days is a
# common, defensible baseline for asset-inventory review policy.
INVENTORY_REVIEW_INTERVAL_DAYS = 90

_CONTROL_REFS = {
    "INV-01": ["NIST 800-53 CM-8", "CIS v8 1.1"],
    "INV-02": ["NIST 800-53 CM-8", "CIS v8 1.1"],
    "INV-03": ["NIST 800-53 CM-8(2)", "CIS v8 2.1"],
    "INV-04": ["NIST 800-53 PM-5", "CIS v8 1.1"],
}

# What valid inventory-record data looks like, for the risk register's
# missing-data entries (upper-case placeholders, no <> or |, which markdown
# would hide or split). INV-01 and INV-04 read one shared record, and an
# entry absent from a supplied record counts against the device (a FAIL), so
# each check's example gives the whole record: following one entry's example
# must not turn the other check into a finding.
INVENTORY_RECORD_EXPECTED = '{"device_id": "ASSET ID", "tracked": true or false, "last_reviewed": "YYYY-MM-DD"}'
INV01_EXPECTED = INVENTORY_RECORD_EXPECTED
INV04_EXPECTED = INVENTORY_RECORD_EXPECTED
DATE_EXPECTED = "a YYYY-MM-DD date"

_NAMES = {
    "INV-01": "Device present in the authoritative asset inventory",
    "INV-02": "Hardware attributes recorded (make, model, serial)",
    "INV-03": "Installed-software inventory maintained for the device",
    "INV-04": "Inventory record reviewed within the policy interval",
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
    return [_stub_result(cid) for cid in ("INV-01", "INV-02", "INV-03", "INV-04")]


def _no_record(record_given: bool | None, expected: str) -> MissingData:
    """The marker for a run without an inventory record: not-supplied when
    --inventory-record was not given, missing-field when it was given but
    holds no record (JSON null). ``record_given`` None: not given."""
    return MissingData("inventory_record", "missing-field" if record_given else "not-supplied",
                       None, expected)


def _check_inv01(record: dict | None, *, record_given: bool | None = None) -> CheckResult:
    """``record_given``: whether --inventory-record was given at all (None:
    taken as not given when ``record`` is None)."""
    if record is None:
        return CheckResult(
            check_id="INV-01", name=_NAMES["INV-01"], status=Status.NOT_APPLICABLE,
            detail="No inventory-system integration configured (no --inventory-record "
                   "supplied); device presence in an external CMDB cannot be assessed "
                   "from the device alone.",
            control_refs=_CONTROL_REFS["INV-01"],
            missing_data=_no_record(record_given, INV01_EXPECTED),
        )
    device_id = record.get("device_id")
    tracked = bool(record.get("tracked"))
    if device_id and tracked:
        status, detail = Status.PASS, f"Device {device_id!r} present and tracked in the supplied inventory record."
    else:
        status, detail = Status.FAIL, "Supplied inventory record does not mark this device as tracked."
    return CheckResult(
        check_id="INV-01", name=_NAMES["INV-01"], status=status, detail=detail,
        evidence=json.dumps(record), control_refs=_CONTROL_REFS["INV-01"],
    )


def _check_inv02(system_info: dict) -> CheckResult:
    vendor = (system_info.get("hardware_vendor") or "").strip()
    model = (system_info.get("hardware_model") or "").strip()
    serial = (system_info.get("hardware_serial") or "").strip()
    present = [v for v in (vendor, model, serial) if v]

    if len(present) == 3:
        status = Status.PASS
        detail = f"Hardware attributes recorded: vendor={vendor!r}, model={model!r}, serial={serial!r}."
    elif present:
        status = Status.PARTIAL
        detail = f"Only {len(present)}/3 hardware attributes (vendor/model/serial) reported."
    else:
        status = Status.FAIL
        detail = "No hardware attributes (vendor/model/serial) reported by osquery system_info."

    return CheckResult(
        check_id="INV-02", name=_NAMES["INV-02"], status=status, detail=detail,
        evidence=json.dumps(system_info), control_refs=_CONTROL_REFS["INV-02"],
    )


def _check_inv03(deb_packages: list) -> CheckResult:
    count = len(deb_packages)
    if count > 0:
        status = Status.PASS
        detail = f"{count} installed packages enumerated via osquery deb_packages."
    else:
        status = Status.FAIL
        detail = "osquery deb_packages query returned no results; software inventory cannot be confirmed."
    return CheckResult(
        check_id="INV-03", name=_NAMES["INV-03"], status=status, detail=detail,
        evidence=f"{count} rows", control_refs=_CONTROL_REFS["INV-03"],
    )


def _check_inv03_windows(programs: list) -> CheckResult:
    count = len(programs)
    if count > 0:
        status = Status.PASS
        detail = f"{count} installed programs enumerated via osquery programs."
    else:
        status = Status.FAIL
        detail = "osquery programs query returned no results; software inventory cannot be confirmed."
    return CheckResult(
        check_id="INV-03", name=_NAMES["INV-03"], status=status, detail=detail,
        evidence=f"{count} rows", control_refs=_CONTROL_REFS["INV-03"],
    )


def _check_inv04(record: dict | None, *, today: datetime.date | None = None,
                 as_of_label: str | None = None, record_given: bool | None = None) -> CheckResult:
    """``today`` is the reference date to count the review's age against
    (None: the real date, through miccmac.clock). ``as_of_label`` (e.g.
    " (as of 2026-11-23)") is appended to a detail that reports an age.
    ``record_given`` works as in _check_inv01."""
    if record is None:
        return CheckResult(
            check_id="INV-04", name=_NAMES["INV-04"], status=Status.NOT_APPLICABLE,
            detail="No inventory-system integration configured (no --inventory-record "
                   "supplied); review recency cannot be assessed from the device alone.",
            control_refs=_CONTROL_REFS["INV-04"],
            missing_data=_no_record(record_given, INV04_EXPECTED),
        )
    last_reviewed = record.get("last_reviewed")
    if not last_reviewed:
        return CheckResult(
            check_id="INV-04", name=_NAMES["INV-04"], status=Status.FAIL,
            detail="Supplied inventory record has no last_reviewed date.",
            control_refs=_CONTROL_REFS["INV-04"],
        )
    try:
        reviewed_date = datetime.date.fromisoformat(last_reviewed)
    except ValueError:
        return CheckResult(
            check_id="INV-04", name=_NAMES["INV-04"], status=Status.ERROR,
            detail=f"Supplied inventory record's last_reviewed={last_reviewed!r} is not a valid ISO date.",
            control_refs=_CONTROL_REFS["INV-04"],
            missing_data=MissingData("inventory_record", "invalid-value", "last_reviewed", DATE_EXPECTED),
        )
    if today is None:
        today = clock.reference_date(None)
    age_days = (today - reviewed_date).days
    if age_days <= INVENTORY_REVIEW_INTERVAL_DAYS:
        status = Status.PASS
        detail = f"Inventory record last reviewed {age_days} day(s) ago (policy: {INVENTORY_REVIEW_INTERVAL_DAYS})."
    else:
        status = Status.FAIL
        detail = f"Inventory record last reviewed {age_days} day(s) ago, exceeding the {INVENTORY_REVIEW_INTERVAL_DAYS}-day policy interval."
    detail += as_of_label or ""
    return CheckResult(
        check_id="INV-04", name=_NAMES["INV-04"], status=status, detail=detail,
        evidence=json.dumps(record), control_refs=_CONTROL_REFS["INV-04"],
    )


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    facts = context.get("facts")
    if facts is None:
        return _stub_checks()

    inventory_record = context.get("inventory_record")
    record_given = "inventory_record" in context
    system_info = facts.get("system_info") or {}

    if (facts.get("os") or {}).get("platform") == "windows":
        inv03 = _check_inv03_windows(facts.get("programs") or [])
    else:
        inv03 = _check_inv03(facts.get("deb_packages") or [])

    return [
        _check_inv01(inventory_record, record_given=record_given),
        _check_inv02(system_info),
        inv03,
        _check_inv04(inventory_record, today=clock.reference_date(context),
                     as_of_label=clock.as_of_label(context), record_given=record_given),
    ]


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Inventoried property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
