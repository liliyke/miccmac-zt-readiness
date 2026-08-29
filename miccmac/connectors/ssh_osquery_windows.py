"""SSH + osquery connector: runs osqueryi.exe over SSH against a remote
Windows target and returns its facts, in the Windows-flavored counterpart to
miccmac/connectors/ssh_osquery.py's Linux facts. Same realistic pattern: the
tool runs on the assessor's machine, not on every target.

Requires paramiko (see requirements.txt), the target's OpenSSH Server
optional feature enabled and reachable (see D:\\VMs\\autoinstall-windows for
how the test VM gets it set up), and osqueryi.exe installed on the target.

Fact-key design: tables that are genuinely cross-platform in osquery
(system_info, listening_ports, certificates) reuse the EXACT SAME fact keys
as the Linux connector, so check bodies that already handle those keys
generically need no Windows-specific branch. Tables/data that differ by OS
(services vs systemd units, installed programs vs deb packages, registry-
based hardening vs sysctls) get their own Windows-specific keys, consumed by
each check module's platform branch.
"""
from __future__ import annotations

import json
from typing import List

import paramiko

from miccmac.connectors.base import ConnectorError

# osqueryi.exe's Windows query surface for the facts this connector collects.
QUERIES = {
    "system_info": "SELECT hostname, uuid, hardware_vendor, hardware_model, "
                    "hardware_serial, cpu_brand, physical_memory FROM system_info;",
    "os_version": "SELECT name, version, platform, platform_like, codename "
                   "FROM os_version;",
    # Installed Win32 programs (from the registry Uninstall keys) -- the
    # Windows counterpart to deb_packages.
    "programs": "SELECT name, version, publisher FROM programs;",
    # Service state for Monitored (M): Windows Event Log service (MON-01),
    # osqueryd itself as the endpoint telemetry agent (MON-03). Sysmon
    # (MON-04, process/auth-relevant event coverage) is checked separately
    # since it's a third-party service whose exact name varies by install.
    "services": "SELECT name, status, start_type FROM services "
                "WHERE name IN ('EventLog', 'osqueryd', 'Sysmon', 'Sysmon64', "
                "'mpssvc', 'wuauusv', 'wuauserv', 'Telnet', 'TlntSvr', 'FTPSVC', 'SNMP', "
                "'SplunkForwarder', 'winlogbeat', 'nxlog', 'DatadogAgent', "
                "'MicrosoftMonitoringAgent', 'AzureMonitorAgent');",
    # Controlled (C): local Administrators-group membership -- the Windows
    # counterpart to sudo_users, used the same way (elevation should be via
    # named accounts in this group, not blanket use of the built-in account).
    "local_admins": "SELECT u.username FROM users u "
                     "JOIN user_groups ug ON u.uid = ug.uid "
                     "JOIN groups g ON ug.gid = g.gid "
                     "WHERE g.groupname = 'Administrators';",
    # Minimized (M): real, network-reachable TCP/UDP listeners only. Same
    # table and same loopback-exclusion logic as the Linux connector --
    # listening_ports is one of the genuinely cross-platform osquery tables.
    "listening_ports": "SELECT DISTINCT port, protocol, address FROM listening_ports "
                        "WHERE protocol IN ('6', '17') AND port != '0' "
                        "AND address NOT LIKE '127.%' AND address != '::1';",
    # Current (C, CUR-04): system trust-store certificates and their expiry.
    # certificates is cross-platform in osquery -- queries the Windows cert
    # store here, same as it queries /etc/ssl on Linux.
    "certificates": "SELECT common_name, not_valid_after FROM certificates "
                     "WHERE not_valid_after != '' AND not_valid_after < strftime('%s', 'now');",
    # Minimized (M, MIN-04): a small sample of CIS-benchmark-relevant
    # registry hardening settings -- the Windows counterpart to
    # hardening_sysctls. Deliberately simple/non-exhaustive, same discipline
    # as the Linux sysctl sample.
    # Minimized (M, MIN-02): legacy/insecure optional Windows features
    # installed -- the Windows counterpart to legacy Debian packages, since
    # these ship as optional components rather than Programs-list entries.
    "legacy_features": "SELECT name, state FROM windows_optional_features "
                        "WHERE name IN ('TelnetClient', 'TelnetServer', 'TFTP', "
                        "'SMB1Protocol', 'IIS-FTPServer');",
    "hardening_registry": (
        "SELECT key, path, data FROM registry WHERE "
        "(key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "AND path LIKE '%EnableLUA') OR "
        "(key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
        "AND path LIKE '%SMB1') OR "
        "(key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection' "
        "AND path LIKE '%DisableRealtimeMonitoring') OR "
        "(key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' "
        "AND path LIKE '%NoDriveTypeAutoRun');"
    ),
}

# osquery's SQL surface doesn't expose "is the built-in Administrator account
# enabled/disabled" or "are all Windows Firewall profiles on" as a table, so
# these two facts are collected via plain PowerShell commands instead --
# same kind of one-off gap RSYSLOG_FORWARDING_CHECK_COMMAND fills on Linux.
BUILTIN_ADMIN_ENABLED_COMMAND = (
    "powershell -NoProfile -NonInteractive -Command "
    "\"(Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue).Enabled\""
)
FIREWALL_PROFILES_COMMAND = (
    "powershell -NoProfile -NonInteractive -Command "
    "\"(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ','\""
)
# Last time Windows Update successfully installed an update, ISO 8601. Feeds
# CUR-01 the same way apt_update_stamp_mtime does on Linux.
LAST_UPDATE_COMMAND = (
    "powershell -NoProfile -NonInteractive -Command "
    "\"(Get-CimInstance -ClassName Win32_QuickFixEngineering | "
    "Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn)"
    ".ToString('o')\""
)


class SSHOsqueryWindowsConnector:
    def __init__(
        self,
        ssh_user: str,
        ssh_key_path: str,
        port: int = 22,
        timeout: float = 20.0,
    ):
        self.ssh_user = ssh_user
        self.ssh_key_path = ssh_key_path
        self.port = port
        self.timeout = timeout

    def _run_osquery(self, client: paramiko.SSHClient, query: str) -> List[dict]:
        command = f'osqueryi.exe --json "{query}"'
        stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if exit_status != 0:
            raise ConnectorError(f"osqueryi.exe failed (exit {exit_status}): {err.strip()}")
        try:
            return json.loads(out) if out.strip() else []
        except json.JSONDecodeError as exc:
            raise ConnectorError(f"osqueryi.exe returned non-JSON output: {exc}") from exc

    def _run_raw(self, client: paramiko.SSHClient, command: str) -> str:
        """Run a plain PowerShell command and return its stdout, stripped.
        Does not raise on a non-zero exit -- some of these commands (e.g. a
        missing built-in account) exit non-zero on an empty/normal result."""
        stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
        stdout.channel.recv_exit_status()
        return stdout.read().decode("utf-8", errors="replace").strip()

    def collect_facts(self, target: str) -> dict:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=target,
                port=self.port,
                username=self.ssh_user,
                key_filename=self.ssh_key_path,
                timeout=self.timeout,
            )
        except (paramiko.SSHException, OSError) as exc:
            raise ConnectorError(f"could not SSH to {target}: {exc}") from exc

        try:
            results = {}
            for key, query in QUERIES.items():
                results[key] = self._run_osquery(client, query)
            builtin_admin_raw = self._run_raw(client, BUILTIN_ADMIN_ENABLED_COMMAND)
            firewall_raw = self._run_raw(client, FIREWALL_PROFILES_COMMAND)
            last_update_raw = self._run_raw(client, LAST_UPDATE_COMMAND)
        finally:
            client.close()

        os_rows = results["os_version"]
        os_facts = {
            "platform": os_rows[0]["platform"] if os_rows else None,
            "name": os_rows[0]["name"] if os_rows else None,
            "version": os_rows[0]["version"] if os_rows else None,
            "codename": os_rows[0].get("codename") if os_rows else None,
        }
        system_info = results["system_info"][0] if results["system_info"] else {}
        services = {row["name"]: row for row in results["services"]}

        hardening_registry = {}
        for row in results["hardening_registry"]:
            setting = row["path"].rsplit("\\", 1)[-1]
            hardening_registry[setting] = row.get("data")

        firewall_values = [v.strip() for v in firewall_raw.split(",") if v.strip()]
        all_profiles_enabled = bool(firewall_values) and all(v == "True" for v in firewall_values)

        legacy_features_enabled = [
            row["name"] for row in results["legacy_features"] if row.get("state") == "Enabled"
        ]

        return {
            "os": os_facts,
            "system_info": system_info,
            "programs": results["programs"],
            "services": services,
            "local_admins": [row["username"] for row in results["local_admins"]],
            "builtin_admin_enabled": builtin_admin_raw.strip() == "True",
            "firewall_all_profiles_enabled": all_profiles_enabled,
            "listening_ports": results["listening_ports"],
            "legacy_features_enabled": legacy_features_enabled,
            "hardening_registry": hardening_registry,
            "last_update_installed_iso": last_update_raw or None,
            "expired_certificates": results["certificates"],
        }
