"""MICCMAC property: Controlled (C).

Intent: Configuration and access to the device are centrally governed by enforced policy, not left to local discretion.

Real detection logic reads osquery facts from context["facts"] (see
miccmac/connectors/ssh_osquery.py): facts["deb_packages"] (config-mgmt /
hardening tool presence), facts["root_locked"] and facts["sudo_users"]
(least-privilege elevation). CTL-03 is NOT derivable from the device --
identity-aware / conditional-access policy is enforced by a cloud identity
provider (Azure AD, Okta, etc.), not something visible on the box itself --
so it reads context["attestation"] (via --attestation) instead, following
the same external-fact pattern as INV-01/INV-04's --inventory-record.

On Windows targets (facts["os"]["platform"] == "windows", populated by
miccmac/connectors/ssh_osquery_windows.py), CTL-01/02/04 branch to Windows
equivalents: installed MDM/config-mgmt clients (SCCM, Intune, or the same
cross-platform agents) in place of deb packages, built-in-Administrator-
account state + Administrators-group membership in place of root_locked/
sudo_users, and installed hardening tools in place of deb packages. CTL-03
stays attestation-based on both platforms.

When no connector was used at all (context has no "facts" key -- the
scaffold/default invocation), all four checks fall back to the original
NOT_IMPLEMENTED stub behavior so `miccmac assess <target>` with no flags is
unchanged from the Alpha scaffold.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "controlled"
LETTER = "C"
TITLE = "Controlled"

_CONTROL_REFS = {
    "CTL-01": ["NIST 800-53 CM-2", "CIS v8 4.1"],
    "CTL-02": ["NIST 800-53 AC-6", "CIS v8 5.4"],
    "CTL-03": ["NIST 800-207 Tenet 4", "NIST 800-53 AC-3", "CIS v8 6.7"],
    "CTL-04": ["NIST 800-53 CM-6", "CIS v8 4.2"],
}

_NAMES = {
    "CTL-01": "Device enrolled in central configuration management / MDM",
    "CTL-02": "Administrative privileges restricted (least privilege)",
    "CTL-03": "Access governed by identity-aware / conditional-access policy",
    "CTL-04": "Configuration baseline enforced and drift-monitored",
}

# Package-name substrings that indicate central configuration management /
# fleet enrollment on a Debian/Ubuntu host.
_CONFIG_MGMT_PACKAGES = ("puppet", "chef", "ansible", "salt-minion", "landscape-client")
# Package-name substrings that indicate a hardening-baseline tool is present.
_HARDENING_PACKAGES = ("usg", "openscap")
# Windows program-name substrings indicating central configuration
# management / fleet enrollment (SCCM/ConfigMgr, Intune, or the same
# cross-platform config-mgmt agents as the Linux list).
_CONFIG_MGMT_PROGRAMS_WIN = ("Configuration Manager Client", "Intune Management Extension",
                            "Chef", "Puppet", "Ansible")
# Windows program-name substrings indicating a hardening-baseline tool is present.
_HARDENING_PROGRAMS_WIN = ("Security Compliance", "Policy Analyzer", "LGPO")


def _stub_result(check_id: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        name=_NAMES[check_id],
        status=Status.NOT_IMPLEMENTED,
        detail="Check not yet implemented.",
        control_refs=_CONTROL_REFS[check_id],
    )


def _stub_checks() -> list[CheckResult]:
    return [_stub_result(cid) for cid in ("CTL-01", "CTL-02", "CTL-03", "CTL-04")]


def _package_installed(deb_packages: list, name_substrings: tuple) -> str | None:
    """Return the matching package name if any installed package's name
    contains one of name_substrings, else None."""
    for pkg in deb_packages:
        name = pkg.get("name", "")
        if any(sub in name for sub in name_substrings):
            return name
    return None


def _check_ctl01(deb_packages: list) -> CheckResult:
    match = _package_installed(deb_packages, _CONFIG_MGMT_PACKAGES)
    if match:
        status = Status.PASS
        detail = f"Central configuration management agent found installed: {match!r}."
    else:
        status = Status.FAIL
        detail = "No central configuration management / MDM agent (puppet, chef, ansible, salt-minion, landscape-client) found installed."
    return CheckResult(
        check_id="CTL-01", name=_NAMES["CTL-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CTL-01"],
    )


def _check_ctl02(root_locked: bool, sudo_users: list) -> CheckResult:
    if root_locked and sudo_users:
        status = Status.PASS
        detail = (f"root account is locked (no direct password login); privilege elevation is "
                  f"via sudo for {len(sudo_users)} named account(s): {', '.join(sudo_users)}.")
    elif root_locked:
        status = Status.PARTIAL
        detail = "root account is locked, but no accounts hold sudo -- there is no elevation path at all."
    else:
        status = Status.FAIL
        detail = "root account is NOT locked; direct root login is possible, bypassing named-account elevation."
    return CheckResult(
        check_id="CTL-02", name=_NAMES["CTL-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CTL-02"],
    )


def _check_ctl03(attestation: dict | None) -> CheckResult:
    if attestation is None or "identity_aware_access" not in attestation:
        return CheckResult(
            check_id="CTL-03", name=_NAMES["CTL-03"], status=Status.NOT_APPLICABLE,
            detail="No --attestation supplied for identity_aware_access; conditional-access "
                   "policy is enforced by a cloud identity provider and is not observable "
                   "from the device itself.",
            control_refs=_CONTROL_REFS["CTL-03"],
        )
    enabled = bool(attestation["identity_aware_access"].get("enabled")) \
        if isinstance(attestation["identity_aware_access"], dict) else bool(attestation["identity_aware_access"])
    if enabled:
        status, detail = Status.PASS, "Attestation confirms identity-aware / conditional-access policy is enforced."
    else:
        status, detail = Status.FAIL, "Attestation states identity-aware / conditional-access policy is NOT enforced."
    return CheckResult(
        check_id="CTL-03", name=_NAMES["CTL-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CTL-03"],
    )


def _check_ctl04(deb_packages: list) -> CheckResult:
    match = _package_installed(deb_packages, _HARDENING_PACKAGES)
    if match:
        status = Status.PASS
        detail = f"Hardening-baseline tool found installed: {match!r}."
    else:
        status = Status.FAIL
        detail = "No recognized hardening-baseline tool (usg, openscap-scanner) found installed."
    return CheckResult(
        check_id="CTL-04", name=_NAMES["CTL-04"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CTL-04"],
    )


def _program_installed(programs: list, name_substrings: tuple) -> str | None:
    for prog in programs:
        name = prog.get("name", "")
        if any(sub in name for sub in name_substrings):
            return name
    return None


def _check_ctl01_windows(programs: list) -> CheckResult:
    match = _program_installed(programs, _CONFIG_MGMT_PROGRAMS_WIN)
    if match:
        status = Status.PASS
        detail = f"Central configuration management / MDM client found installed: {match!r}."
    else:
        status = Status.FAIL
        detail = "No central configuration management / MDM client (SCCM, Intune, Chef, Puppet, Ansible) found installed."
    return CheckResult(
        check_id="CTL-01", name=_NAMES["CTL-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CTL-01"],
    )


def _check_ctl02_windows(builtin_admin_enabled: bool, local_admins: list) -> CheckResult:
    if not builtin_admin_enabled and local_admins:
        status = Status.PASS
        detail = (f"Built-in Administrator account is disabled; privilege elevation is via "
                  f"{len(local_admins)} named Administrators-group account(s): {', '.join(local_admins)}.")
    elif not builtin_admin_enabled:
        status = Status.PARTIAL
        detail = "Built-in Administrator account is disabled, but no named accounts hold Administrators-group membership -- there is no elevation path at all."
    else:
        status = Status.FAIL
        detail = "Built-in Administrator account is enabled, bypassing named-account elevation."
    return CheckResult(
        check_id="CTL-02", name=_NAMES["CTL-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CTL-02"],
    )


def _check_ctl04_windows(programs: list) -> CheckResult:
    match = _program_installed(programs, _HARDENING_PROGRAMS_WIN)
    if match:
        status = Status.PASS
        detail = f"Hardening-baseline tool found installed: {match!r}."
    else:
        status = Status.FAIL
        detail = "No recognized hardening-baseline tool (Microsoft Security Compliance Toolkit, LGPO) found installed."
    return CheckResult(
        check_id="CTL-04", name=_NAMES["CTL-04"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["CTL-04"],
    )


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    facts = context.get("facts")
    if facts is None:
        return _stub_checks()

    attestation = context.get("attestation")

    if (facts.get("os") or {}).get("platform") == "windows":
        programs = facts.get("programs") or []
        builtin_admin_enabled = bool(facts.get("builtin_admin_enabled"))
        local_admins = facts.get("local_admins") or []
        return [
            _check_ctl01_windows(programs),
            _check_ctl02_windows(builtin_admin_enabled, local_admins),
            _check_ctl03(attestation),
            _check_ctl04_windows(programs),
        ]

    deb_packages = facts.get("deb_packages") or []
    root_locked = bool(facts.get("root_locked"))
    sudo_users = facts.get("sudo_users") or []

    return [
        _check_ctl01(deb_packages),
        _check_ctl02(root_locked, sudo_users),
        _check_ctl03(attestation),
        _check_ctl04(deb_packages),
    ]


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Controlled property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
