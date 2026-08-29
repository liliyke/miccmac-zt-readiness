"""MICCMAC property: Monitored (M).

Intent: The device's security-relevant activity is logged, retained, and continuously monitored so that compromise can be detected.

Real detection logic reads osquery facts from context["facts"] (see
miccmac/connectors/ssh_osquery.py) -- specifically facts["systemd_units"]
(active_state/sub_state/load_state for journald, rsyslog, syslog-ng,
osqueryd, auditd) and facts["rsyslog_forwarding_configured"] (whether
rsyslog's config declares a remote destination).

On Windows targets (facts["os"]["platform"] == "windows", populated by
miccmac/connectors/ssh_osquery_windows.py), the same four checks branch to
Windows-native equivalents: the Windows Event Log service in place of
journald/syslog, a known log-forwarding-agent service in place of rsyslog
remote-forwarding config, osqueryd unchanged, and Sysmon in place of
auditd for rich auth/privilege/process audit coverage.

When no connector was used at all (context has no "facts" key -- the
scaffold/default invocation), all four checks fall back to the original
NOT_IMPLEMENTED stub behavior so `miccmac assess <target>` with no flags is
unchanged from the Alpha scaffold.
"""
from __future__ import annotations

from miccmac.model import CheckResult, PropertyResult, Status

KEY = "monitored"
LETTER = "M"
TITLE = "Monitored"

_CONTROL_REFS = {
    "MON-01": ["NIST 800-53 AU-2", "CIS v8 8.2"],
    "MON-02": ["NIST 800-53 AU-6", "CIS v8 8.9"],
    "MON-03": ["NIST 800-53 SI-4", "CIS v8 13.7"],
    "MON-04": ["NIST 800-53 AU-2", "CIS v8 8.5"],
}

_NAMES = {
    "MON-01": "Endpoint security logging enabled",
    "MON-02": "Logs forwarded to a centralized SIEM / log platform",
    "MON-03": "EDR / endpoint telemetry agent installed and healthy",
    "MON-04": "Audit policy covers authentication, privilege, and process events",
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
    return [_stub_result(cid) for cid in ("MON-01", "MON-02", "MON-03", "MON-04")]


def _active(units: dict, unit_id: str) -> bool:
    return units.get(unit_id, {}).get("active_state") == "active"


def _check_mon01(units: dict) -> CheckResult:
    journald = _active(units, "systemd-journald.service")
    syslog = _active(units, "rsyslog.service") or _active(units, "syslog-ng.service")

    if journald and syslog:
        status = Status.PASS
        detail = "systemd-journald and a syslog daemon (rsyslog/syslog-ng) are both active."
    elif journald:
        status = Status.PARTIAL
        detail = "systemd-journald is active, but no traditional syslog daemon (rsyslog/syslog-ng) was found active."
    else:
        status = Status.FAIL
        detail = "systemd-journald is not active; no baseline logging service found."

    return CheckResult(
        check_id="MON-01", name=_NAMES["MON-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-01"],
    )


def _check_mon02(rsyslog_forwarding_configured: bool) -> CheckResult:
    if rsyslog_forwarding_configured:
        status = Status.PASS
        detail = "rsyslog configuration declares a remote forwarding destination (@/@@)."
    else:
        status = Status.FAIL
        detail = "No remote forwarding destination found in rsyslog configuration; logs are not leaving the device."

    return CheckResult(
        check_id="MON-02", name=_NAMES["MON-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-02"],
    )


def _check_mon03(units: dict) -> CheckResult:
    if _active(units, "osqueryd.service"):
        status = Status.PASS
        detail = "osqueryd (endpoint telemetry agent) is installed and active."
    else:
        status = Status.FAIL
        detail = "osqueryd is not active; no endpoint telemetry agent detected."

    return CheckResult(
        check_id="MON-03", name=_NAMES["MON-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-03"],
    )


def _check_mon04(units: dict) -> CheckResult:
    auditd = units.get("auditd.service", {})
    if auditd.get("active_state") == "active":
        # Confirms the daemon is running; does not yet verify specific rule
        # coverage (watches on auth/privilege/process events) -- a
        # deliberately simpler first pass, refinable later.
        status = Status.PASS
        detail = "auditd is active (specific rule coverage not yet verified by this check)."
    elif auditd.get("load_state") == "not-found":
        status = Status.FAIL
        detail = "auditd is not installed; authentication/privilege/process audit events are not being captured."
    else:
        status = Status.FAIL
        detail = "auditd is installed but not active."

    return CheckResult(
        check_id="MON-04", name=_NAMES["MON-04"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-04"],
    )


# Windows service names recognized as log-forwarding/SIEM agents (see
# ssh_osquery_windows.py's services query) -- the Windows counterpart to
# MON-02's "rsyslog forwards to somewhere" check.
_WIN_FORWARDING_SERVICES = ("SplunkForwarder", "winlogbeat", "nxlog", "DatadogAgent",
                            "MicrosoftMonitoringAgent", "AzureMonitorAgent")


def _win_running(services: dict, name: str) -> bool:
    return services.get(name, {}).get("status") == "RUNNING"


def _check_mon01_windows(services: dict) -> CheckResult:
    if _win_running(services, "EventLog"):
        status = Status.PASS
        detail = "Windows Event Log service is running."
    else:
        status = Status.FAIL
        detail = "Windows Event Log service is not running; no baseline logging service found."
    return CheckResult(
        check_id="MON-01", name=_NAMES["MON-01"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-01"],
    )


def _check_mon02_windows(services: dict) -> CheckResult:
    running = [name for name in _WIN_FORWARDING_SERVICES if _win_running(services, name)]
    if running:
        status = Status.PASS
        detail = f"Log-forwarding agent service running: {', '.join(running)}."
    else:
        status = Status.FAIL
        detail = "No recognized log-forwarding agent service found running; logs are not leaving the device."
    return CheckResult(
        check_id="MON-02", name=_NAMES["MON-02"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-02"],
    )


def _check_mon03_windows(services: dict) -> CheckResult:
    if _win_running(services, "osqueryd"):
        status = Status.PASS
        detail = "osqueryd (endpoint telemetry agent) is installed and running."
    else:
        status = Status.FAIL
        detail = "osqueryd is not running; no endpoint telemetry agent detected."
    return CheckResult(
        check_id="MON-03", name=_NAMES["MON-03"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-03"],
    )


def _check_mon04_windows(services: dict) -> CheckResult:
    sysmon_running = _win_running(services, "Sysmon") or _win_running(services, "Sysmon64")
    eventlog_running = _win_running(services, "EventLog")
    if sysmon_running:
        status = Status.PASS
        detail = "Sysmon is running, providing rich authentication/privilege/process audit coverage."
    elif eventlog_running:
        status = Status.PARTIAL
        detail = "Windows Event Log is running, but Sysmon is not -- native Security log auditing is not verified by this check."
    else:
        status = Status.FAIL
        detail = "Neither Sysmon nor the Windows Event Log service is running; authentication/privilege/process events are not being captured."
    return CheckResult(
        check_id="MON-04", name=_NAMES["MON-04"], status=status, detail=detail,
        control_refs=_CONTROL_REFS["MON-04"],
    )


def _run_checks(target: str, context: dict) -> list[CheckResult]:
    facts = context.get("facts")
    if facts is None:
        return _stub_checks()

    if (facts.get("os") or {}).get("platform") == "windows":
        services = facts.get("services") or {}
        return [
            _check_mon01_windows(services),
            _check_mon02_windows(services),
            _check_mon03_windows(services),
            _check_mon04_windows(services),
        ]

    units = facts.get("systemd_units") or {}
    rsyslog_forwarding_configured = bool(facts.get("rsyslog_forwarding_configured"))

    return [
        _check_mon01(units),
        _check_mon02(rsyslog_forwarding_configured),
        _check_mon03(units),
        _check_mon04(units),
    ]


def evaluate(target: str, context: dict) -> PropertyResult:
    """Entry point called by the engine for the Monitored property."""
    return PropertyResult(
        key=KEY,
        letter=LETTER,
        title=TITLE,
        checks=_run_checks(target, context),
    )
