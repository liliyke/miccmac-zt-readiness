"""Tests for extended facts: collect_facts(target, extended=True) on both SSH
connectors. paramiko is faked as in tests/test_ssh_osquery_connector.py and
tests/test_ssh_osquery_windows_connector.py: no real SSH connection or
network. Synthetic values only (IP 192.0.2.10, user "assessor", key
"keys/id_ed25519")."""
from __future__ import annotations

import json
import socket
import threading
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from miccmac.connectors.base import (EXTRA_ERROR_MAX_CHARS, ConnectorError, collect_extra_item,
                                     read_extra_command, short_error)
from miccmac.connectors.ssh_osquery import SSHOsqueryConnector
from miccmac.connectors.ssh_osquery_windows import SSHOsqueryWindowsConnector

TARGET = "192.0.2.10"

# The exact commands each connector sent before extended facts existed,
# captured from the code at that point. extended=False must keep sending
# exactly these, in this order.
BASELINE_LINUX_COMMANDS = [
    "osqueryi --json \"SELECT hostname, uuid, hardware_vendor, hardware_model, hardware_serial, cpu_brand, physical_memory FROM system_info;\"",
    "osqueryi --json \"SELECT name, version, platform, platform_like, codename FROM os_version;\"",
    "osqueryi --json \"SELECT name, version FROM deb_packages;\"",
    "osqueryi --json \"SELECT id, active_state, sub_state, load_state FROM systemd_units WHERE id IN ('systemd-journald.service', 'rsyslog.service', 'syslog-ng.service', 'osqueryd.service', 'auditd.service', 'ufw.service', 'apt-daily-upgrade.timer');\"",
    "osqueryi --json \"SELECT username, password_status FROM shadow WHERE username='root';\"",
    "osqueryi --json \"SELECT u.username FROM users u JOIN user_groups ug ON u.uid = ug.uid JOIN groups g ON ug.gid = g.gid WHERE g.groupname = 'sudo';\"",
    "osqueryi --json \"SELECT DISTINCT port, protocol, address FROM listening_ports WHERE protocol IN ('6', '17') AND port != '0' AND address NOT LIKE '127.%' AND address != '::1';\"",
    "osqueryi --json \"SELECT name, current_value FROM system_controls WHERE name IN ('kernel.dmesg_restrict', 'kernel.kptr_restrict', 'fs.suid_dumpable', 'net.ipv4.conf.all.rp_filter');\"",
    "osqueryi --json \"SELECT mtime FROM file WHERE path = '/var/lib/apt/periodic/update-success-stamp';\"",
    "osqueryi --json \"SELECT DISTINCT base_uri FROM apt_sources;\"",
    "osqueryi --json \"SELECT vendor, version, date FROM platform_info;\"",
    "osqueryi --json \"SELECT common_name, not_valid_after FROM certificates WHERE not_valid_after != '' AND not_valid_after < strftime('%s', 'now');\"",
    "grep -rhE '^[^#]*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; true",
]
BASELINE_WINDOWS_COMMANDS = [
    "osqueryi.exe --json \"SELECT hostname, uuid, hardware_vendor, hardware_model, hardware_serial, cpu_brand, physical_memory FROM system_info;\"",
    "osqueryi.exe --json \"SELECT name, version, platform, platform_like, codename FROM os_version;\"",
    "osqueryi.exe --json \"SELECT name, version, publisher FROM programs;\"",
    "osqueryi.exe --json \"SELECT name, status, start_type FROM services WHERE name IN ('EventLog', 'osqueryd', 'Sysmon', 'Sysmon64', 'mpssvc', 'wuauusv', 'wuauserv', 'Telnet', 'TlntSvr', 'FTPSVC', 'SNMP', 'SplunkForwarder', 'winlogbeat', 'nxlog', 'DatadogAgent', 'MicrosoftMonitoringAgent', 'AzureMonitorAgent');\"",
    "osqueryi.exe --json \"SELECT u.username FROM users u JOIN user_groups ug ON u.uid = ug.uid JOIN groups g ON ug.gid = g.gid WHERE g.groupname = 'Administrators';\"",
    "osqueryi.exe --json \"SELECT DISTINCT port, protocol, address FROM listening_ports WHERE protocol IN ('6', '17') AND port != '0' AND address NOT LIKE '127.%' AND address != '::1';\"",
    "osqueryi.exe --json \"SELECT common_name, not_valid_after FROM certificates WHERE not_valid_after != '' AND not_valid_after < strftime('%s', 'now');\"",
    "osqueryi.exe --json \"SELECT name, state FROM windows_optional_features WHERE name IN ('TelnetClient', 'TelnetServer', 'TFTP', 'SMB1Protocol', 'IIS-FTPServer');\"",
    "osqueryi.exe --json \"SELECT key, path, data FROM registry WHERE (key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' AND path LIKE '%EnableLUA') OR (key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' AND path LIKE '%SMB1') OR (key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection' AND path LIKE '%DisableRealtimeMonitoring') OR (key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' AND path LIKE '%NoDriveTypeAutoRun');\"",
    "powershell -NoProfile -NonInteractive -Command \"(Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue).Enabled\"",
    "powershell -NoProfile -NonInteractive -Command \"(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ','\"",
    "powershell -NoProfile -NonInteractive -Command \"(Get-CimInstance -ClassName Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn).ToString('o')\"",
]

# The extended items, as the specification gives them (runtime text).
_SHARED_EXTRA_SQL = [
    ("osquery_info", "SELECT version, build_platform, build_distro FROM osquery_info;"),
    ("os_version_full", "SELECT * FROM os_version;"),
    ("listening_ports_processes",
     "SELECT DISTINCT lp.port, lp.protocol, lp.address, p.name AS process FROM listening_ports lp "
     "LEFT JOIN processes p USING (pid) WHERE lp.protocol IN ('6', '17') AND lp.port != '0' "
     "AND lp.address NOT LIKE '127.%' AND lp.address != '::1';"),
    ("certificates_all", "SELECT common_name, not_valid_after, sha1 FROM certificates WHERE not_valid_after != '';"),
]
LINUX_EXTRA_SQL = _SHARED_EXTRA_SQL + [
    ("update_units", "SELECT id, active_state, sub_state, load_state FROM systemd_units WHERE id IN "
                     "('unattended-upgrades.service', 'apt-daily.timer', 'apt-daily-upgrade.timer');"),
]
LINUX_EXTRA_TEXT = [
    ("apt_periodic_config", "cat /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/10periodic 2>&1; true"),
    ("audit_rules", "cat /etc/audit/audit.rules /etc/audit/rules.d/*.rules 2>&1; true"),
]
WINDOWS_EXTRA_SQL = _SHARED_EXTRA_SQL + [
    ("update_services", "SELECT name, status, start_type FROM services WHERE name IN "
                        "('wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'BITS', 'DoSvc');"),
    ("update_policy_registry",
     r"SELECT key, path, name, type, data FROM registry WHERE key IN "
     r"('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', "
     r"'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU');"),
    ("update_orchestrator_tasks",
     r"SELECT name, path, enabled, state, last_run_time, next_run_time, last_run_code FROM "
     r"scheduled_tasks WHERE path LIKE '\Microsoft\Windows\UpdateOrchestrator\%';"),
    ("audit_registry",
     r"SELECT key, path, name, data FROM registry WHERE "
     r"(key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' "
     r"AND name = 'ProcessCreationIncludeCmdLine_Enabled') OR "
     r"(key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' "
     r"AND name = 'SCENoApplyLegacyAuditPolicy');"),
]
WINDOWS_EXTRA_OTHER = ["windows_update_results", "hotfixes", "audit_policy"]
LINUX_EXTRA_KEYS = [k for k, _ in LINUX_EXTRA_SQL] + [k for k, _ in LINUX_EXTRA_TEXT]
WINDOWS_EXTRA_KEYS = [k for k, _ in WINDOWS_EXTRA_SQL] + WINDOWS_EXTRA_OTHER


def _linux_osquery(sql: str) -> str:
    return "osqueryi --json " + json.dumps(sql)


def _windows_osquery(sql: str) -> str:
    return f'osqueryi.exe --json "{sql}"'


def _mock_channel_file(text: str, exit_status: int = 0):
    mock_file = MagicMock()
    mock_file.read.return_value = text.encode("utf-8")
    mock_file.channel.recv_exit_status.return_value = exit_status
    return mock_file


class _RealChannel:
    """A reply served by a real, unconnected paramiko.Channel, so reads and
    exit-status waits behave exactly as paramiko's do, timeouts included.
    output=None: the command never prints anything and never exits (a
    stalled osqueryi). Otherwise its output is delivered and its streams
    end; the exit status arrives only when exit_status is given."""

    def __init__(self, output=None, exit_status=None):
        self.output, self.exit_status = output, exit_status
        self.channel = None

    def open(self, timeout):
        channel = paramiko.Channel(1)
        channel.settimeout(timeout)  # what exec_command(command, timeout=...) does
        if self.output is not None:
            channel.in_buffer.feed(self.output.encode("utf-8"))
            channel.in_buffer.close()
            channel.in_stderr_buffer.close()
        if self.exit_status is not None:
            channel.exit_status = self.exit_status
            channel.status_event.set()
        channel.close = MagicMock(wraps=channel.close)
        self.channel = channel
        return channel.makefile("rb"), channel.makefile_stderr("rb")


def _make_client(rules=(), sent=None):
    """A fake paramiko.SSHClient. Every command is appended to `sent`. The
    reply comes from the first (substring, reply) rule matching the command;
    a reply is text (exit 0), (text, exit_status), an exception to raise, or
    a _RealChannel. Unmatched osqueryi queries return [] and other commands
    print nothing."""
    sent = [] if sent is None else sent
    client = MagicMock()

    def exec_command(command, timeout=None):
        sent.append(command)
        reply = next((r for needle, r in rules if needle in command), None)
        if reply is None:
            reply = "[]" if "osqueryi" in command else ""
        if isinstance(reply, BaseException):
            raise reply
        if isinstance(reply, _RealChannel):
            stdout, stderr = reply.open(timeout)
            return MagicMock(), stdout, stderr
        text, status = reply if isinstance(reply, tuple) else (reply, 0)
        stderr_text = text if status else ""
        return MagicMock(), _mock_channel_file(text, status), _mock_channel_file(stderr_text, status)

    client.exec_command.side_effect = exec_command
    return client, sent


# Replies for the main queries, so the facts are not all empty.
LINUX_MAIN_RULES = [
    ("codename FROM os_version", json.dumps([{"name": "Ubuntu", "version": "26.04", "platform": "ubuntu",
                                              "platform_like": "debian", "codename": "resolute"}])),
    ("FROM deb_packages", json.dumps([{"name": "bash", "version": "5.2"}])),
    ("update-success-stamp", json.dumps([{"mtime": "1795000000"}])),
    ("grep -rhE", "*.* @@logs.example.invalid:514\n"),
]
LINUX_EXTRA_RULES = [
    ("FROM osquery_info", json.dumps([{"version": "5.12.1", "build_platform": "ubuntu", "build_distro": "jammy"}])),
    ("SELECT * FROM os_version", json.dumps([{"name": "Ubuntu", "version": "26.04", "build": ""}])),
    ("FROM listening_ports lp", json.dumps([{"port": "22", "protocol": "6", "address": "0.0.0.0",
                                             "process": "sshd"}])),
    ("sha1 FROM certificates", json.dumps([{"common_name": "Synthetic Root", "not_valid_after": "1900000000",
                                            "sha1": "ab" * 20}])),
    ("unattended-upgrades.service", json.dumps([{"id": "apt-daily.timer", "active_state": "active",
                                                 "sub_state": "waiting", "load_state": "loaded"}])),
    ("10periodic", 'APT::Periodic::Update-Package-Lists "1";\n'),
    ("audit.rules", "cat: /etc/audit/audit.rules: Permission denied\n"),
]
WINDOWS_MAIN_RULES = [
    ("codename FROM os_version", json.dumps([{"name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200",
                                              "platform": "windows", "platform_like": "windows",
                                              "codename": None}])),
    ("FROM programs", json.dumps([{"name": "7-Zip", "version": "23.01", "publisher": "Igor Pavlov"}])),
    ("Get-LocalUser", "False"),
    ("Get-NetFirewallProfile", "True,True,True"),
    ("Sort-Object InstalledOn -Descending", "2026-11-12T00:00:00.0000000"),
]
WINDOWS_EXTRA_RULES = [
    ("FROM osquery_info", json.dumps([{"version": "5.12.1", "build_platform": "windows", "build_distro": "10"}])),
    ("SELECT * FROM os_version", json.dumps([{"name": "Microsoft Windows 11 Enterprise", "build": "26200"}])),
    ("'UsoSvc'", json.dumps([{"name": "UsoSvc", "status": "RUNNING", "start_type": "AUTO_START"}])),
    ("Microsoft.Update.AutoUpdate", json.dumps({"LastSearchSuccessDate": "2026-11-20T08:00:00.0000000",
                                                "LastInstallationSuccessDate": None})),
    ("Win32_QuickFixEngineering | Sort-Object HotFixID",
     json.dumps({"HotFixID": "KB0000001", "Description": "Update", "InstalledOn": "2026-11-12T00:00:00.0000000"})),
    ("auditpol", "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting\r\n"),
]


def _collect(connector_cls, module, rules, extended):
    client, sent = _make_client(rules)
    with patch(f"miccmac.connectors.{module}.paramiko.SSHClient", return_value=client):
        facts = connector_cls(ssh_user="assessor", ssh_key_path="keys/id_ed25519").collect_facts(
            TARGET, extended=extended)
    return facts, sent, client


def _linux(rules=(), extended=False):
    return _collect(SSHOsqueryConnector, "ssh_osquery", list(rules) + LINUX_MAIN_RULES, extended)


def _windows(rules=(), extended=False):
    return _collect(SSHOsqueryWindowsConnector, "ssh_osquery_windows", list(rules) + WINDOWS_MAIN_RULES, extended)


# ---------------------------------------------------------------- extended=False is unchanged

def test_linux_without_extended_sends_exactly_the_baseline_commands():
    facts, sent, client = _linux()
    assert sent == BASELINE_LINUX_COMMANDS
    assert "extra" not in facts
    client.close.assert_called_once()
    # The positional call used before extended facts existed still works.
    client2, sent2 = _make_client(LINUX_MAIN_RULES)
    with patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient", return_value=client2):
        assert SSHOsqueryConnector("assessor", "keys/id_ed25519").collect_facts(TARGET) == facts
    assert sent2 == BASELINE_LINUX_COMMANDS


def test_windows_without_extended_sends_exactly_the_baseline_commands():
    facts, sent, client = _windows()
    assert sent == BASELINE_WINDOWS_COMMANDS
    assert "extra" not in facts
    client.close.assert_called_once()


# ---------------------------------------------------------------- extended=True adds the extras after them

def test_linux_extended_adds_the_extra_items_after_the_baseline():
    facts, sent, client = _linux(LINUX_EXTRA_RULES, extended=True)
    expected = (BASELINE_LINUX_COMMANDS
                + [_linux_osquery(sql) for _, sql in LINUX_EXTRA_SQL]
                + [command for _, command in LINUX_EXTRA_TEXT])
    assert sent == expected
    client.close.assert_called_once()
    extra = facts["extra"]
    assert list(extra) == LINUX_EXTRA_KEYS
    assert all(item["ok"] is True for item in extra.values()), extra
    assert extra["osquery_info"]["data"] == [{"version": "5.12.1", "build_platform": "ubuntu",
                                              "build_distro": "jammy"}]
    assert extra["listening_ports_processes"]["data"][0]["process"] == "sshd"
    assert extra["apt_periodic_config"]["data"] == 'APT::Periodic::Update-Package-Lists "1";\n'
    # An unprivileged "Permission denied" is still a recorded answer.
    assert extra["audit_rules"] == {"ok": True, "data": "cat: /etc/audit/audit.rules: Permission denied\n"}


def test_windows_extended_adds_the_extra_items_after_the_baseline():
    facts, sent, client = _windows(WINDOWS_EXTRA_RULES, extended=True)
    n_base, n_sql = len(BASELINE_WINDOWS_COMMANDS), len(WINDOWS_EXTRA_SQL)
    assert sent[:n_base] == BASELINE_WINDOWS_COMMANDS
    assert sent[n_base:n_base + n_sql] == [_windows_osquery(sql) for _, sql in WINDOWS_EXTRA_SQL]
    update_results, hotfixes, audit_policy = sent[n_base + n_sql:]
    for command, needles in (
        (update_results, ["Microsoft.Update.AutoUpdate", "LastSearchSuccessDate",
                          "LastInstallationSuccessDate", "ToString('o')", "ConvertTo-Json -Compress"]),
        (hotfixes, ["Get-CimInstance -ClassName Win32_QuickFixEngineering", "HotFixID", "Description",
                    "InstalledOn", "ToString('o')", "ConvertTo-Json -Compress"]),
    ):
        assert command.startswith('powershell -NoProfile -NonInteractive -Command "')
        assert command.endswith('"') and command.count('"') == 2
        for needle in needles:
            assert needle in command
    assert audit_policy == "auditpol /get /category:* /r"
    client.close.assert_called_once()

    extra = facts["extra"]
    assert list(extra) == WINDOWS_EXTRA_KEYS
    assert all(item["ok"] is True for item in extra.values()), extra
    assert extra["windows_update_results"]["data"] == {
        "LastSearchSuccessDate": "2026-11-20T08:00:00.0000000", "LastInstallationSuccessDate": None}
    # PowerShell prints one object rather than a list when there is one hotfix.
    assert extra["hotfixes"]["data"] == [{"HotFixID": "KB0000001", "Description": "Update",
                                          "InstalledOn": "2026-11-12T00:00:00.0000000"}]
    assert extra["audit_policy"]["data"].startswith("Machine Name,Policy Target,Subcategory")
    assert extra["os_version_full"]["data"] == [{"name": "Microsoft Windows 11 Enterprise", "build": "26200"}]


def test_windows_hotfix_list_shapes():
    two = [{"HotFixID": "KB0000001"}, {"HotFixID": "KB0000002"}]
    facts, _, _ = _windows([("Sort-Object HotFixID", json.dumps(two))], extended=True)
    assert facts["extra"]["hotfixes"] == {"ok": True, "data": two}
    facts, _, _ = _windows([("Sort-Object HotFixID", "")], extended=True)
    assert facts["extra"]["hotfixes"] == {"ok": True, "data": []}


def test_main_facts_are_identical_with_and_without_extended():
    for collect, rules in ((_linux, LINUX_EXTRA_RULES), (_windows, WINDOWS_EXTRA_RULES)):
        plain, _, _ = collect(rules, extended=False)
        extended, _, _ = collect(rules, extended=True)
        assert set(extended) - set(plain) == {"extra"}
        without_extra = {k: v for k, v in extended.items() if k != "extra"}
        assert without_extra == plain
        assert list(without_extra) == list(plain)


# ---------------------------------------------------------------- every extra item is non-fatal

def test_linux_failing_extra_items_are_recorded_and_collection_returns():
    rules = [
        ("FROM osquery_info", ("osqueryi: table not found", 1)),        # non-zero exit
        ("SELECT * FROM os_version", "this is not json"),               # bad JSON
        ("FROM listening_ports lp", socket.timeout("timed out")),       # exception
        ("10periodic", ("cat: write error", 2)),                        # non-zero exit, text item
        ("audit.rules", RuntimeError("channel closed")),                # exception, text item
    ] + LINUX_EXTRA_RULES
    facts, sent, client = _linux(rules, extended=True)
    extra = facts["extra"]
    assert list(extra) == LINUX_EXTRA_KEYS
    assert extra["osquery_info"]["ok"] is False and "exit 1" in extra["osquery_info"]["error"]
    assert extra["os_version_full"]["ok"] is False and "non-JSON" in extra["os_version_full"]["error"]
    # socket.timeout is named "timeout" on Python 3.9 and "TimeoutError" from 3.10.
    assert extra["listening_ports_processes"]["ok"] is False
    assert extra["listening_ports_processes"]["error"] in ("timeout: timed out", "TimeoutError: timed out")
    assert extra["apt_periodic_config"]["ok"] is False
    assert "exit 2" in extra["apt_periodic_config"]["error"]
    assert extra["audit_rules"] == {"ok": False, "error": "RuntimeError: channel closed"}
    assert extra["certificates_all"]["ok"] is True and extra["update_units"]["ok"] is True
    for item in extra.values():
        assert set(item) in ({"ok", "data"}, {"ok", "error"})
    # Collection still returned the main facts, and every item was attempted.
    assert facts["os"]["platform"] == "ubuntu"
    assert facts["rsyslog_forwarding_configured"] is True
    assert len(sent) == len(BASELINE_LINUX_COMMANDS) + len(LINUX_EXTRA_KEYS)
    client.close.assert_called_once()


def test_windows_failing_extra_items_are_recorded_and_collection_returns():
    privilege = "Error 0x00000522 occurred:\r\nA required privilege is not held by the client.\r\n"
    rules = [
        ("FROM scheduled_tasks", ("", 1)),
        ("Microsoft.Update.AutoUpdate", ConnectionResetError("connection reset")),
        ("Sort-Object HotFixID", "{not json"),
        ("auditpol", (privilege, 1314)),
    ] + WINDOWS_EXTRA_RULES
    facts, sent, client = _windows(rules, extended=True)
    extra = facts["extra"]
    assert list(extra) == WINDOWS_EXTRA_KEYS
    assert extra["update_orchestrator_tasks"]["ok"] is False
    assert extra["windows_update_results"] == {"ok": False, "error": "ConnectionResetError: connection reset"}
    assert extra["hotfixes"]["ok"] is False and extra["hotfixes"]["error"].startswith("JSONDecodeError")
    # What auditpol printed is kept in the error, on one line.
    assert extra["audit_policy"] == {
        "ok": False,
        "error": "ConnectorError: command failed (exit 1314): Error 0x00000522 occurred: "
                 "A required privilege is not held by the client.",
    }
    assert extra["osquery_info"]["ok"] is True
    assert facts["os"]["platform"] == "windows"
    assert facts["last_update_installed_iso"] == "2026-11-12T00:00:00.0000000"
    assert len(sent) == len(BASELINE_WINDOWS_COMMANDS) + len(WINDOWS_EXTRA_KEYS)
    client.close.assert_called_once()


def test_windows_update_results_must_be_one_object():
    for output in ("", "[]", "42"):
        facts, _, _ = _windows([("Microsoft.Update.AutoUpdate", output)], extended=True)
        assert facts["extra"]["windows_update_results"]["ok"] is False


def test_a_failing_main_query_is_still_fatal_and_no_extra_is_attempted():
    client, sent = _make_client([("FROM deb_packages", ("osqueryi: error", 1))] + LINUX_MAIN_RULES)
    with patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient", return_value=client):
        with pytest.raises(ConnectorError, match="osqueryi failed"):
            SSHOsqueryConnector("assessor", "keys/id_ed25519").collect_facts(TARGET, extended=True)
    assert len(sent) == 3
    client.close.assert_called_once()


# ---------------------------------------------------------------- extended items are bounded by the channel timeout

SHORT_TIMEOUT = 0.3
# (connector, module, every other reply, an extended osquery item and its
# needle, an extended text item and its needle). Rules put before the
# replies win, since the first matching rule answers.
CONNECTORS = [
    (SSHOsqueryConnector, "ssh_osquery", LINUX_EXTRA_RULES + LINUX_MAIN_RULES,
     ("osquery_info", "FROM osquery_info"), ("apt_periodic_config", "10periodic")),
    (SSHOsqueryWindowsConnector, "ssh_osquery_windows", WINDOWS_EXTRA_RULES + WINDOWS_MAIN_RULES,
     ("osquery_info", "FROM osquery_info"), ("audit_policy", "auditpol")),
]


def _collect_within(seconds, connector_cls, module, rules):
    """collect_facts(extended=True) with a SHORT_TIMEOUT channel timeout, run
    in a thread so that a hang fails the test instead of stopping the suite."""
    client, sent = _make_client(rules)
    connector = connector_cls(ssh_user="assessor", ssh_key_path="keys/id_ed25519", timeout=SHORT_TIMEOUT)
    result = {}

    def run():
        try:
            result["facts"] = connector.collect_facts(TARGET, extended=True)
        except BaseException as exc:  # handed back to the test below
            result["error"] = exc

    with patch(f"miccmac.connectors.{module}.paramiko.SSHClient", return_value=client):
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(seconds)
    assert not thread.is_alive(), f"collection still running after {seconds} s: an extended item hung"
    if "error" in result:
        raise result["error"]
    return result["facts"], sent, client


@pytest.mark.parametrize("connector_cls, module, main_rules, osquery_item, text_item", CONNECTORS)
def test_a_stalled_extended_item_is_a_recorded_timeout_not_a_hang(connector_cls, module, main_rules,
                                                                   osquery_item, text_item):
    """CC-08: an osqueryi that never prints or exits. recv_exit_status() has
    no timeout, so a reader that waited for the exit status first would hang
    here forever; reading first lets the channel timeout end it."""
    (osquery_key, osquery_needle), (text_key, text_needle) = osquery_item, text_item
    stalled_query, stalled_text = _RealChannel(), _RealChannel()
    rules = [(osquery_needle, stalled_query), (text_needle, stalled_text)] + main_rules
    facts, sent, client = _collect_within(10, connector_cls, module, rules)
    expected = {"ok": False, "error": "ConnectorError: timed out: no output for 0.3 s"}
    assert facts["extra"][osquery_key] == expected
    assert facts["extra"][text_key] == expected
    for stalled in (stalled_query, stalled_text):
        stalled.channel.close.assert_called_once()  # the stalled channel is not left open
    # Every other item, and the main facts, were still collected.
    others = {k: v for k, v in facts["extra"].items() if k not in (osquery_key, text_key)}
    assert others and all(item["ok"] is True for item in others.values()), others
    assert facts["os"]["platform"] in ("ubuntu", "windows")
    baseline = BASELINE_LINUX_COMMANDS if module == "ssh_osquery" else BASELINE_WINDOWS_COMMANDS
    assert sent[:len(baseline)] == baseline
    assert len(sent) == len(baseline) + len(facts["extra"])
    client.close.assert_called_once()


@pytest.mark.parametrize("connector_cls, module, main_rules, osquery_item, text_item", CONNECTORS)
def test_an_extended_item_whose_exit_status_never_arrives_times_out(connector_cls, module, main_rules,
                                                                    osquery_item, text_item):
    """The output ends but no exit status follows: waited for at most the
    channel timeout, then recorded as a timeout."""
    (osquery_key, osquery_needle), (text_key, text_needle) = osquery_item, text_item
    rules = [(osquery_needle, _RealChannel(output="[]")),
             (text_needle, _RealChannel(output="some text\n"))] + main_rules
    facts, _, _ = _collect_within(10, connector_cls, module, rules)
    expected = {"ok": False, "error": "ConnectorError: timed out: no exit status 0.3 s after the output ended"}
    assert facts["extra"][osquery_key] == expected
    assert facts["extra"][text_key] == expected


@pytest.mark.parametrize("connector_cls, module, main_rules, osquery_item, text_item", CONNECTORS)
def test_extended_items_read_through_a_real_channel(connector_cls, module, main_rules, osquery_item, text_item):
    (osquery_key, osquery_needle), (text_key, text_needle) = osquery_item, text_item
    rows = [{"version": "5.12.1", "build_platform": "synthetic"}]
    rules = [(osquery_needle, _RealChannel(output=json.dumps(rows), exit_status=0)),
             (text_needle, _RealChannel(output="denied\n", exit_status=1))] + main_rules
    facts, _, _ = _collect_within(10, connector_cls, module, rules)
    assert facts["extra"][osquery_key] == {"ok": True, "data": rows}
    assert facts["extra"][text_key] == {"ok": False, "error": "ConnectorError: command failed (exit 1): denied"}


def test_read_extra_command_reads_before_waiting_for_the_exit_status():
    calls = []
    stdout, stderr = MagicMock(), MagicMock()
    stdout.read.side_effect = lambda: calls.append("stdout") or b"out"
    stderr.read.side_effect = lambda: calls.append("stderr") or b"err"
    stdout.channel.exit_status_ready.side_effect = lambda: calls.append("ready?") or True
    stdout.channel.recv_exit_status.side_effect = lambda: calls.append("exit status") or 3
    assert read_extra_command(stdout, stderr, 5.0) == (3, "out", "err")
    assert calls == ["stdout", "stderr", "ready?", "exit status"]
    stdout.channel.close.assert_not_called()


def test_the_main_queries_keep_their_reader():
    """The bound applies to extended items only: the main queries still use
    _run_osquery, unchanged (BASELINE_*_COMMANDS pin what they send)."""
    from miccmac.connectors import ssh_osquery, ssh_osquery_windows

    for module in (ssh_osquery, ssh_osquery_windows):
        connector_cls = (module.SSHOsqueryConnector if module is ssh_osquery
                         else module.SSHOsqueryWindowsConnector)
        client = MagicMock()
        client.exec_command.side_effect = lambda command, timeout=None: (
            MagicMock(), _mock_channel_file("[]"), _mock_channel_file(""))
        connector = connector_cls("assessor", "keys/id_ed25519")
        with patch(f"{module.__name__}.read_extra_command") as reader:
            assert connector._run_osquery(client, "SELECT 1;") == []
        reader.assert_not_called()


# ---------------------------------------------------------------- read-only, quoting, helpers

def test_extra_commands_are_read_only_and_quoted_for_the_windows_command_line():
    from miccmac.connectors import ssh_osquery, ssh_osquery_windows

    linux = list(ssh_osquery.EXTRA_QUERIES.values()) + list(ssh_osquery.EXTRA_TEXT_COMMANDS.values())
    windows = list(ssh_osquery_windows.EXTRA_QUERIES.values()) + [
        ssh_osquery_windows.WINDOWS_UPDATE_RESULTS_COMMAND, ssh_osquery_windows.HOTFIXES_COMMAND,
        ssh_osquery_windows.AUDIT_POLICY_COMMAND]
    for command in linux + windows:
        lowered = command.lower()
        for word in ("sudo", "runas", "set-", "remove-", "rm ", "insert ", "update ", "delete ",
                     " > /", "tee "):
            assert word not in lowered, (word, command)
    for query in ssh_osquery_windows.EXTRA_QUERIES.values():
        assert '"' not in query
    assert dict(_SHARED_EXTRA_SQL + LINUX_EXTRA_SQL) == ssh_osquery.EXTRA_QUERIES
    assert dict(LINUX_EXTRA_TEXT) == ssh_osquery.EXTRA_TEXT_COMMANDS
    assert dict(WINDOWS_EXTRA_SQL) == ssh_osquery_windows.EXTRA_QUERIES


def test_collect_extra_item_and_short_error():
    assert collect_extra_item(lambda a, b: a + b, 1, 2) == {"ok": True, "data": 3}

    def boom():
        raise ValueError("bad\n  value\twith   spaces")

    assert collect_extra_item(boom) == {"ok": False, "error": "ValueError: bad value with spaces"}
    assert short_error(KeyError()) == "KeyError"
    long_message = short_error(RuntimeError("x" * 2000))
    assert len(long_message) == EXTRA_ERROR_MAX_CHARS and long_message.endswith("...")
