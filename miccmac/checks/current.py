"""MICCMAC property: Current (C).

Intent: The device is kept in its most secure state: patched, updated, and free of expired cryptographic material.

Real detection logic reads osquery facts from context["facts"] (see
miccmac/connectors/ssh_osquery.py): facts["systemd_units"] and
facts["apt_update_stamp_mtime"] (CUR-01, patch cadence), facts["apt_sources"]
(CUR-02, third-party repo presence), facts["expired_certificates"] (CUR-04,
directly device-observable).

CUR-03 (firmware/BIOS currency) is different in kind from the others: even
with root access, a device can only report its *current* firmware version,
never whether that's the *latest available* one -- there is no local oracle
for that, only a vendor API/feed. So CUR-03 reads context["attestation"]
(via --attestation), following the same external-fact pattern as CTL-03 /
Claimed / Assessed, rather than pretending a device-local check could answer
"is this current".

On Windows targets (facts["os"]["platform"] == "windows", populated by
miccmac/connectors/ssh_osquery_windows.py), CUR-01/02 branch to Windows
equivalents: the Windows Update service (wuauserv) and last-successful-
install timestamp in place of apt-daily-upgrade.timer/update-success-stamp,
and installed third-party programs + package-manager presence in place of
apt sources. CUR-03 stays attestation-based and CUR-04 reuses the same
cross-platform expired_certificates fact key on both platforms.

When no connector was used at all (context has no "facts" key -- the
scaffold/default invocation), all four checks fall back to the original
NOT_IMPLEMENTED stub behavior, so the check results of `miccmac assess
<target>` with no flags are unchanged from the Alpha scaffold (the report
itself now adds the default CMMI lens, every level Unassessed).

CUR-01 counts the age of the last successful update against miccmac.clock's
reference time: the end of the --as-of day in UTC when one was given
(context["as_of"]), otherwise the current time. CUR-04 is different: its
expired-certificate list is computed on the device at collection time
(osquery's strftime('%s', 'now')), so --as-of does not move it.

Windows CUR-01 parses the install timestamp with _parse_iso_datetime, so
the 7-digit fractions that PowerShell's ToString('o') prints also parse on
Python 3.9 and 3.10, whose datetime.fromisoformat accepts only 3 or 6
digits and no "Z"; on 3.11 and later the result is what fromisoformat alone
gives. The saved facts keep the timestamp exactly as collected.

The missing-data markers (CheckResult.missing_data) cover CUR-03's
attestation entry not supplied (NOT_APPLICABLE), and the Windows CUR-01
install timestamp that cannot be read (ERROR). CUR-02's NOT_APPLICABLE (no
third-party software) has no marker: that check does not apply.
"""
from __future__ import annotations

import datetime
import re

from miccmac import clock
from miccmac.model import CheckResult, MissingData, PropertyResult, Status

KEY = "current"
LETTER = "C"
TITLE = "Current"

_CONTROL_REFS = {
    "CUR-01": ["NIST 800-53 SI-2", "CIS v8 7.3"],
    "CUR-02": ["NIST 800-53 SI-2", "CIS v8 7.4"],
    "CUR-03": ["NIST 800-53 SI-2", "CIS v8 7.3"],
    "CUR-04": ["NIST 800-53 SC-12", "CIS v8 3.10"],
}

# What valid data looks like, for the risk register's missing-data entries.
CUR03_EXPECTED = '{"current": true or false}'
CUR01_WINDOWS_EXPECTED = "an ISO 8601 timestamp of the last successful update install"


def _attestation_supplied(attestation: dict | None, attestation_given: bool | None) -> bool:
    """Whether --attestation was given (None: taken from whether there is one)."""
    return attestation is not None if attestation_given is None else bool(attestation_given)


_NAMES = {
    "CUR-01": "Operating-system patch level within policy",
    "CUR-02": "Third-party software updated within policy",
    "CUR-03": "Firmware / BIOS current",
    "CUR-04": "Certificates and cryptographic material valid and unexpired",
}

# Base URIs recognized as Ubuntu's own official archives (not "third-party").
_OFFICIAL_UBUNTU_URI_FRAGMENTS = ("archive.ubuntu.com", "security.ubuntu.com",
                                 "ports.ubuntu.com", "old-releases.ubuntu.com")
# How stale the apt update-success-stamp can be before CUR-01 considers
# patch cadence out of policy. Matches apt-daily-upgrade.timer's default
# roughly-daily cadence with headroom.
APT_UPDATE_FRESHNESS_DAYS = 7
# Same freshness window applied to Windows Update's last successful install.
WIN_UPDATE_FRESHNESS_DAYS = 30
# Publisher-string fragments recognized as Microsoft's own (not "third-party").
_MICROSOFT_PUBLISHER_FRAGMENTS = ("Microsoft",)
# An extended-format ISO 8601 timestamp: date, "T" or space, HH:MM:SS, an
# optional fraction of any length, then an optional "Z" or +HH:MM / -HH:MM.
# That covers what PowerShell's ToString('o') prints, with any DateTimeKind:
# 2026-11-12T00:00:00.0000000, ...0000000-05:00 and ...0000000Z.
_ISO_DATETIME_RE = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.([0-9]+))?"
    r"(Z|[+-][0-9]{2}:[0-9]{2})?"
)


def _normalize_iso_datetime(text: str) -> str:
    """The form of an extended ISO 8601 timestamp that Python 3.9's
    datetime.fromisoformat reads: the fraction cut or padded to exactly 6
    digits and a trailing "Z" written as +00:00. A string of any other form
    is returned unchanged, for fromisoformat to accept or reject as before.

    Python 3.11+ reads both forms to the same value: it also keeps only the
    first 6 fraction digits (padding shorter ones) and maps "Z" to UTC, so
    the normalization changes nothing there. A non-string is returned as it
    is, so fromisoformat raises the same TypeError it always did."""
    if not isinstance(text, str):
        return text
    match = _ISO_DATETIME_RE.fullmatch(text)
    if match is None:
        return text
    base, fraction, offset = match.groups()
    if fraction is not None:
        base += "." + (fraction + "000000")[:6]
    if offset == "Z":
        offset = "+00:00"
    return base + (offset or "")


def _parse_iso_datetime(text: str) -> datetime.datetime:
    """datetime.fromisoformat on the normalized timestamp (see
    _normalize_iso_datetime). Raises ValueError, as fromisoformat does. Used
    at parse time only: the facts keep the timestamp as collected."""
    return datetime.datetime.fromisoformat(_normalize_iso_datetime(text))


def _stub_result(check_id: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        name=_NAMES[check_id],
        status=Status.NOT_IMPLEMENTED,
        detail="Check not yet implemented.",
        control_refs=_CONTROL_REFS[check_id],
    )


def _stub_checks() -> list[CheckResult]:
    return [_stub_result(cid) for cid in ("CUR-01", "CUR-02", "CUR-03", "CUR-04")]


def _check_cur01(units: dict, apt_update_stamp_mtime: int | None, *,
                 now: datetime.datetime | None = None,
                 as_of_label: str | None = None) -> CheckResult:
    """``now`` is the aware UTC moment to count the update's age against
    (None: the real current time, through miccmac.clock). ``as_of_label``
    (e.g. " (as of 2026-11-23)") is appended to a detail that reports an age."""
    timer_active = units.get("apt-daily-upgrade.timer", {}).get("active_state") == "active"
    if not timer_active:
        return CheckResult(
            check_id="CUR-01", name=_NAMES["CUR-01"], status=Status.FAIL,
            detail="apt-daily-upgrade.timer is not active; OS patches are not applied on a schedule.",
            control_refs=_CONTROL_REFS["CUR-01"],
        )
    if apt_update_stamp_mtime is None:
        return CheckResult(
            check_id="CUR-01", name=_NAMES["CUR-01"], status=Status.PARTIAL,
            detail="apt-daily-upgrade.timer is active, but no successful apt update has been recorded yet.",
            control_refs=_CONTROL_REFS["CUR-01"],
        )
    if now is None:
        now = clock.reference_now(None)
    last_update = datetime.datetime.fromtimestamp(apt_update_stamp_mtime, tz=datetime.timezone.utc)
    age_days = (now - last_update).days
    if age_days <= APT_UPDATE_FRESHNESS_DAYS:
        status = Status.PASS
        detail = f"apt-daily-upgrade.timer active; last successful apt update {age_days} day(s) ago."
    else:
        status = Status.FAIL
        detail = (f"apt-daily-upgrade.timer active, but last successful apt update was {age_days} "
                 f"day(s) ago, exceeding the {APT_UPDATE_FRESHNESS_DAYS}-day policy.")
    detail += as_of_label or ""
    return CheckResult(
        check_id="CUR-01", name=_NAMES["CUR-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CUR-01"],
    )


def _check_cur02(units: dict, apt_sources: list) -> CheckResult:
    third_party = [uri for uri in apt_sources
                  if not any(frag in uri for frag in _OFFICIAL_UBUNTU_URI_FRAGMENTS)]
    if not third_party:
        return CheckResult(
            check_id="CUR-02", name=_NAMES["CUR-02"], status=Status.NOT_APPLICABLE,
            detail="No third-party apt repositories configured; no third-party software to have an update policy for.",
            control_refs=_CONTROL_REFS["CUR-02"],
        )
    timer_active = units.get("apt-daily-upgrade.timer", {}).get("active_state") == "active"
    if timer_active:
        status = Status.PARTIAL
        detail = (f"{len(third_party)} third-party apt source(s) configured, and apt-daily-upgrade.timer "
                 f"is active; whether third-party origins are actually in its update scope is not verified.")
    else:
        status = Status.FAIL
        detail = f"{len(third_party)} third-party apt source(s) configured, but apt-daily-upgrade.timer is not active."
    return CheckResult(
        check_id="CUR-02", name=_NAMES["CUR-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CUR-02"],
    )


def _check_cur01_windows(services: dict, last_update_installed_iso: str | None, *,
                         now: datetime.datetime | None = None,
                         as_of_label: str | None = None) -> CheckResult:
    """``now`` and ``as_of_label`` work as in _check_cur01."""
    service_running = services.get("wuauserv", {}).get("status") == "RUNNING"
    if not service_running:
        return CheckResult(
            check_id="CUR-01", name=_NAMES["CUR-01"], status=Status.FAIL,
            detail="Windows Update service (wuauserv) is not running; OS patches are not applied on a schedule.",
            control_refs=_CONTROL_REFS["CUR-01"],
        )
    if not last_update_installed_iso:
        return CheckResult(
            check_id="CUR-01", name=_NAMES["CUR-01"], status=Status.PARTIAL,
            detail="Windows Update service is running, but no successful update install has been recorded yet.",
            control_refs=_CONTROL_REFS["CUR-01"],
        )
    try:
        last_update = _parse_iso_datetime(last_update_installed_iso)
    except ValueError:
        return CheckResult(
            check_id="CUR-01", name=_NAMES["CUR-01"], status=Status.ERROR,
            detail=f"Last Windows Update install timestamp {last_update_installed_iso!r} is not a valid date.",
            control_refs=_CONTROL_REFS["CUR-01"],
            missing_data=MissingData("facts", "invalid-value", "last_update_installed_iso",
                                     CUR01_WINDOWS_EXPECTED),
        )
    if last_update.tzinfo is None:
        last_update = last_update.replace(tzinfo=datetime.timezone.utc)
    if now is None:
        now = clock.reference_now(None)
    age_days = (now - last_update).days
    if age_days <= WIN_UPDATE_FRESHNESS_DAYS:
        status = Status.PASS
        detail = f"Windows Update service active; last successful update installed {age_days} day(s) ago."
    else:
        status = Status.FAIL
        detail = (f"Windows Update service active, but last successful update was {age_days} "
                 f"day(s) ago, exceeding the {WIN_UPDATE_FRESHNESS_DAYS}-day policy.")
    detail += as_of_label or ""
    return CheckResult(
        check_id="CUR-01", name=_NAMES["CUR-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CUR-01"],
    )


def _check_cur02_windows(programs: list) -> CheckResult:
    third_party = [p for p in programs
                   if not any(frag in (p.get("publisher") or "") for frag in _MICROSOFT_PUBLISHER_FRAGMENTS)]
    if not third_party:
        return CheckResult(
            check_id="CUR-02", name=_NAMES["CUR-02"], status=Status.NOT_APPLICABLE,
            detail="No third-party programs installed; no third-party software to have an update policy for.",
            control_refs=_CONTROL_REFS["CUR-02"],
        )
    package_manager = next((p["name"] for p in programs if "Chocolatey" in p.get("name", "")), None)
    if package_manager:
        status = Status.PARTIAL
        detail = (f"{len(third_party)} third-party program(s) installed, and a package manager "
                 f"({package_manager!r}) is present; whether third-party software is actually kept "
                 f"current is not verified.")
    else:
        status = Status.FAIL
        detail = f"{len(third_party)} third-party program(s) installed, and no package manager (e.g. Chocolatey) was found to keep them updated."
    return CheckResult(
        check_id="CUR-02", name=_NAMES["CUR-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CUR-02"],
    )


def _check_cur03(attestation: dict | None, *, attestation_given: bool | None = None) -> CheckResult:
    if attestation is None or "firmware_currency" not in attestation:
        problem = "missing-field" if _attestation_supplied(attestation, attestation_given) else "not-supplied"
        return CheckResult(
            check_id="CUR-03", name=_NAMES["CUR-03"], status=Status.NOT_APPLICABLE,
            detail="No --attestation supplied for firmware_currency; a device can report its current "
                   "firmware version but never whether that is the latest available -- there is no "
                   "local oracle for that, only a vendor feed.",
            control_refs=_CONTROL_REFS["CUR-03"],
            missing_data=MissingData("attestation", problem, "firmware_currency", CUR03_EXPECTED),
        )
    firmware = attestation["firmware_currency"] or {}
    if firmware.get("current"):
        status, detail = Status.PASS, "Attestation confirms firmware/BIOS is current."
    else:
        status, detail = Status.FAIL, "Attestation states firmware/BIOS is NOT current."
    return CheckResult(
        check_id="CUR-03", name=_NAMES["CUR-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CUR-03"],
    )


def _check_cur04(expired_certificates: list) -> CheckResult:
    if expired_certificates:
        names = [c.get("common_name") or "(unnamed)" for c in expired_certificates[:5]]
        status = Status.FAIL
        detail = f"{len(expired_certificates)} expired certificate(s) found in the system trust store, e.g.: {', '.join(names)}."
    else:
        status = Status.PASS
        detail = "No expired certificates found in the system trust store."
    return CheckResult(
        check_id="CUR-04", name=_NAMES["CUR-04"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CUR-04"],
    )


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    facts = context.get("facts")
    if facts is None:
        return _stub_checks()

    expired_certificates = facts.get("expired_certificates") or []
    attestation = context.get("attestation")
    supplied = "attestation" in context
    now = clock.reference_now(context)
    label = clock.as_of_label(context)

    if (facts.get("os") or {}).get("platform") == "windows":
        services = facts.get("services") or {}
        programs = facts.get("programs") or []
        return [
            _check_cur01_windows(services, facts.get("last_update_installed_iso"),
                                 now=now, as_of_label=label),
            _check_cur02_windows(programs),
            _check_cur03(attestation, attestation_given=supplied),
            _check_cur04(expired_certificates),
        ]

    units = facts.get("systemd_units") or {}
    apt_update_stamp_mtime = facts.get("apt_update_stamp_mtime")
    apt_sources = facts.get("apt_sources") or []

    return [
        _check_cur01(units, apt_update_stamp_mtime, now=now, as_of_label=label),
        _check_cur02(units, apt_sources),
        _check_cur03(attestation, attestation_given=supplied),
        _check_cur04(expired_certificates),
    ]


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Current property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
