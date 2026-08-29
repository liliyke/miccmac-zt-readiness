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
NOT_IMPLEMENTED stub behavior so `miccmac assess <target>` with no flags is
unchanged from the Alpha scaffold.
"""
from __future__ import annotations

import datetime

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "current"
LETTER = "C"
TITLE = "Current"

_CONTROL_REFS = {
    "CUR-01": ["NIST 800-53 SI-2", "CIS v8 7.3"],
    "CUR-02": ["NIST 800-53 SI-2", "CIS v8 7.4"],
    "CUR-03": ["NIST 800-53 SI-2", "CIS v8 7.3"],
    "CUR-04": ["NIST 800-53 SC-12", "CIS v8 3.10"],
}

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


def _check_cur01(units: dict, apt_update_stamp_mtime: int | None) -> CheckResult:
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
    last_update = datetime.datetime.fromtimestamp(apt_update_stamp_mtime, tz=datetime.timezone.utc)
    age_days = (datetime.datetime.now(tz=datetime.timezone.utc) - last_update).days
    if age_days <= APT_UPDATE_FRESHNESS_DAYS:
        status = Status.PASS
        detail = f"apt-daily-upgrade.timer active; last successful apt update {age_days} day(s) ago."
    else:
        status = Status.FAIL
        detail = (f"apt-daily-upgrade.timer active, but last successful apt update was {age_days} "
                 f"day(s) ago, exceeding the {APT_UPDATE_FRESHNESS_DAYS}-day policy.")
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


def _check_cur01_windows(services: dict, last_update_installed_iso: str | None) -> CheckResult:
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
        last_update = datetime.datetime.fromisoformat(last_update_installed_iso)
    except ValueError:
        return CheckResult(
            check_id="CUR-01", name=_NAMES["CUR-01"], status=Status.ERROR,
            detail=f"Last Windows Update install timestamp {last_update_installed_iso!r} is not a valid date.",
            control_refs=_CONTROL_REFS["CUR-01"],
        )
    if last_update.tzinfo is None:
        last_update = last_update.replace(tzinfo=datetime.timezone.utc)
    age_days = (datetime.datetime.now(tz=datetime.timezone.utc) - last_update).days
    if age_days <= WIN_UPDATE_FRESHNESS_DAYS:
        status = Status.PASS
        detail = f"Windows Update service active; last successful update installed {age_days} day(s) ago."
    else:
        status = Status.FAIL
        detail = (f"Windows Update service active, but last successful update was {age_days} "
                 f"day(s) ago, exceeding the {WIN_UPDATE_FRESHNESS_DAYS}-day policy.")
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


def _check_cur03(attestation: dict | None) -> CheckResult:
    if attestation is None or "firmware_currency" not in attestation:
        return CheckResult(
            check_id="CUR-03", name=_NAMES["CUR-03"], status=Status.NOT_APPLICABLE,
            detail="No --attestation supplied for firmware_currency; a device can report its current "
                   "firmware version but never whether that is the latest available -- there is no "
                   "local oracle for that, only a vendor feed.",
            control_refs=_CONTROL_REFS["CUR-03"],
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

    if (facts.get("os") or {}).get("platform") == "windows":
        services = facts.get("services") or {}
        programs = facts.get("programs") or []
        return [
            _check_cur01_windows(services, facts.get("last_update_installed_iso")),
            _check_cur02_windows(programs),
            _check_cur03(attestation),
            _check_cur04(expired_certificates),
        ]

    units = facts.get("systemd_units") or {}
    apt_update_stamp_mtime = facts.get("apt_update_stamp_mtime")
    apt_sources = facts.get("apt_sources") or []

    return [
        _check_cur01(units, apt_update_stamp_mtime),
        _check_cur02(units, apt_sources),
        _check_cur03(attestation),
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
