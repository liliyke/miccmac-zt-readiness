"""MICCMAC property: Minimized (M).

Intent: The device's attack surface is reduced to the minimum required for its documented purpose.

Real detection logic reads osquery facts from context["facts"] (see
miccmac/connectors/ssh_osquery.py): facts["deb_packages"] and
facts["systemd_units"] (legacy/risky service and package presence),
facts["systemd_units"]["ufw.service"] and facts["listening_ports"]
(firewall + exposed ports), and facts["hardening_sysctls"] (a sample of
CIS-benchmark-relevant kernel parameters -- MIN-04's evidence that a
baseline was actually *applied*, distinct from CTL-04's "is a hardening
tool merely installed").

On Windows targets (facts["os"]["platform"] == "windows", populated by
miccmac/connectors/ssh_osquery_windows.py), all four checks branch to
Windows equivalents: legacy Windows services (Telnet/FTP/SNMP) in place of
legacy systemd units, legacy optional Windows features (SMBv1, Telnet
client) in place of legacy deb packages, Windows Defender Firewall profile
state in place of ufw, and a sample of CIS-benchmark-relevant registry
settings in place of kernel sysctls.

When no connector was used at all (context has no "facts" key -- the
scaffold/default invocation), all four checks fall back to the original
NOT_IMPLEMENTED stub behavior so `miccmac assess <target>` with no flags is
unchanged from the Alpha scaffold.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "minimized"
LETTER = "M"
TITLE = "Minimized"

_CONTROL_REFS = {
    "MIN-01": ["NIST 800-53 CM-7", "CIS v8 4.8"],
    "MIN-02": ["NIST 800-53 CM-7(1)", "CIS v8 2.3"],
    "MIN-03": ["NIST 800-53 SC-7", "CIS v8 4.5"],
    "MIN-04": ["NIST 800-53 CM-6", "CIS v8 4.1"],
}

_NAMES = {
    "MIN-01": "Unnecessary services and daemons disabled",
    "MIN-02": "Unused or unauthorized software removed",
    "MIN-03": "Host firewall enabled; unused network ports closed",
    "MIN-04": "Recognized hardening baseline (e.g. CIS Benchmark) applied",
}

# Legacy/insecure systemd unit ids that should not be active on a hardened host.
_LEGACY_UNITS = ("telnet.socket", "rsh.socket", "rpcbind.service", "tftpd-hpa.service", "nis.service")
# Exact package names for the same legacy/insecure services. Deliberately
# exact match, not substring: "nis" as a substring would false-positive on
# unrelated packages like "libunistring5" (caught via live VM testing).
_LEGACY_PACKAGES = ("telnetd", "inetutils-telnetd", "rsh-server", "rsh-client",
                    "nis", "xinetd", "tftpd-hpa", "rpcbind")
# Ports considered part of the expected minimal footprint (SSH for
# management, mDNS which ships enabled by default on Ubuntu Desktop).
_EXPECTED_PORTS = {"22", "5353"}
# name -> the CIS-hardened value expected for that sysctl.
_EXPECTED_SYSCTLS = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "1",
    "fs.suid_dumpable": "0",
    "net.ipv4.conf.all.rp_filter": "1",
}

# Windows service names considered legacy/insecure if running (MIN-01).
_LEGACY_SERVICES_WIN = ("Telnet", "TlntSvr", "FTPSVC", "SNMP")
# Ports considered part of the expected minimal footprint on Windows
# (RDP/WinRM for management, SSH since these targets run OpenSSH Server).
_EXPECTED_PORTS_WIN = {"22", "3389", "5985", "5986"}
# registry setting -> the CIS-hardened value expected (see
# ssh_osquery_windows.py's hardening_registry query).
_EXPECTED_REGISTRY_WIN = {
    "EnableLUA": "1",
    "SMB1": "0",
    "DisableRealtimeMonitoring": "0",
    "NoDriveTypeAutoRun": "255",
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
    return [_stub_result(cid) for cid in ("MIN-01", "MIN-02", "MIN-03", "MIN-04")]


def _check_min01(units: dict) -> CheckResult:
    active = [uid for uid in _LEGACY_UNITS if units.get(uid, {}).get("active_state") == "active"]
    if active:
        status = Status.FAIL
        detail = f"Legacy/insecure service(s) active: {', '.join(active)}."
    else:
        status = Status.PASS
        detail = "No legacy/insecure services (telnet, rsh, rpcbind, tftp, NIS) found active."
    return CheckResult(
        check_id="MIN-01", name=_NAMES["MIN-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-01"],
    )


def _check_min02(deb_packages: list) -> CheckResult:
    installed = [pkg["name"] for pkg in deb_packages if pkg.get("name") in _LEGACY_PACKAGES]
    if installed:
        status = Status.FAIL
        detail = f"Legacy/insecure package(s) installed: {', '.join(installed)}."
    else:
        status = Status.PASS
        detail = "No legacy/insecure packages (telnetd, rsh-server, nis, xinetd, tftpd-hpa, rpcbind) found installed."
    return CheckResult(
        check_id="MIN-02", name=_NAMES["MIN-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-02"],
    )


def _check_min03(units: dict, listening_ports: list) -> CheckResult:
    ufw_active = units.get("ufw.service", {}).get("active_state") == "active"
    unexpected_ports = sorted({p["port"] for p in listening_ports if p["port"] not in _EXPECTED_PORTS})

    if ufw_active and not unexpected_ports:
        status = Status.PASS
        detail = "Host firewall (ufw) is active; only the expected minimal ports are listening."
    elif ufw_active:
        status = Status.PARTIAL
        detail = f"Host firewall (ufw) is active, but unexpected port(s) are listening: {', '.join(unexpected_ports)}."
    else:
        status = Status.FAIL
        detail = "Host firewall (ufw) is not active."
    return CheckResult(
        check_id="MIN-03", name=_NAMES["MIN-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-03"],
    )


def _check_min04(hardening_sysctls: dict) -> CheckResult:
    matched = [name for name, expected in _EXPECTED_SYSCTLS.items()
              if hardening_sysctls.get(name) == expected]
    total = len(_EXPECTED_SYSCTLS)

    if len(matched) == total:
        status = Status.PASS
        detail = f"All {total} sampled hardening-baseline kernel parameters match their recommended values."
    elif matched:
        status = Status.PARTIAL
        unmatched = sorted(set(_EXPECTED_SYSCTLS) - set(matched))
        detail = (f"{len(matched)}/{total} sampled hardening-baseline kernel parameters match; "
                 f"not hardened: {', '.join(unmatched)}.")
    else:
        status = Status.FAIL
        detail = "None of the sampled hardening-baseline kernel parameters match their recommended values."
    return CheckResult(
        check_id="MIN-04", name=_NAMES["MIN-04"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-04"],
    )


def _check_min01_windows(services: dict) -> CheckResult:
    active = [name for name in _LEGACY_SERVICES_WIN if services.get(name, {}).get("status") == "RUNNING"]
    if active:
        status = Status.FAIL
        detail = f"Legacy/insecure service(s) running: {', '.join(active)}."
    else:
        status = Status.PASS
        detail = "No legacy/insecure services (Telnet, FTP, SNMP) found running."
    return CheckResult(
        check_id="MIN-01", name=_NAMES["MIN-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-01"],
    )


def _check_min02_windows(legacy_features_enabled: list) -> CheckResult:
    if legacy_features_enabled:
        status = Status.FAIL
        detail = f"Legacy/insecure optional feature(s) enabled: {', '.join(legacy_features_enabled)}."
    else:
        status = Status.PASS
        detail = "No legacy/insecure optional features (Telnet client/server, TFTP, SMBv1, FTP server) found enabled."
    return CheckResult(
        check_id="MIN-02", name=_NAMES["MIN-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-02"],
    )


def _check_min03_windows(firewall_all_profiles_enabled: bool, listening_ports: list) -> CheckResult:
    unexpected_ports = sorted({p["port"] for p in listening_ports if p["port"] not in _EXPECTED_PORTS_WIN})

    if firewall_all_profiles_enabled and not unexpected_ports:
        status = Status.PASS
        detail = "Windows Defender Firewall is enabled on all profiles; only the expected minimal ports are listening."
    elif firewall_all_profiles_enabled:
        status = Status.PARTIAL
        detail = f"Windows Defender Firewall is enabled on all profiles, but unexpected port(s) are listening: {', '.join(unexpected_ports)}."
    else:
        status = Status.FAIL
        detail = "Windows Defender Firewall is not enabled on all profiles."
    return CheckResult(
        check_id="MIN-03", name=_NAMES["MIN-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-03"],
    )


def _check_min04_windows(hardening_registry: dict) -> CheckResult:
    matched = [name for name, expected in _EXPECTED_REGISTRY_WIN.items()
              if hardening_registry.get(name) == expected]
    total = len(_EXPECTED_REGISTRY_WIN)

    if len(matched) == total:
        status = Status.PASS
        detail = f"All {total} sampled hardening-baseline registry settings match their recommended values."
    elif matched:
        status = Status.PARTIAL
        unmatched = sorted(set(_EXPECTED_REGISTRY_WIN) - set(matched))
        detail = (f"{len(matched)}/{total} sampled hardening-baseline registry settings match; "
                 f"not hardened: {', '.join(unmatched)}.")
    else:
        status = Status.FAIL
        detail = "None of the sampled hardening-baseline registry settings match their recommended values."
    return CheckResult(
        check_id="MIN-04", name=_NAMES["MIN-04"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MIN-04"],
    )


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    facts = context.get("facts")
    if facts is None:
        return _stub_checks()

    if (facts.get("os") or {}).get("platform") == "windows":
        services = facts.get("services") or {}
        listening_ports = facts.get("listening_ports") or []
        return [
            _check_min01_windows(services),
            _check_min02_windows(facts.get("legacy_features_enabled") or []),
            _check_min03_windows(bool(facts.get("firewall_all_profiles_enabled")), listening_ports),
            _check_min04_windows(facts.get("hardening_registry") or {}),
        ]

    units = facts.get("systemd_units") or {}
    deb_packages = facts.get("deb_packages") or []
    listening_ports = facts.get("listening_ports") or []
    hardening_sysctls = facts.get("hardening_sysctls") or {}

    return [
        _check_min01(units),
        _check_min02(deb_packages),
        _check_min03(units, listening_ports),
        _check_min04(hardening_sysctls),
    ]


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Minimized property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
