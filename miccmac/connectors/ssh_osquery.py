"""SSH + osquery connector: runs osqueryi over SSH against a remote Linux
target and returns its facts. This is the realistic pattern for assessing a
fleet device -- the tool runs on the assessor's machine, not on every target.

Requires paramiko (see requirements.txt) and osqueryi installed on the
target (see D:\\VMs\\autoinstall\\user-data's late-commands for how the test
VM gets it).
"""
from __future__ import annotations

import json
from typing import List, Optional

import paramiko

from miccmac.connectors.base import ConnectorError

# The fixed set of osquery queries this connector collects. Kept minimal and
# explicit rather than "select * from everything" so it's obvious exactly
# what data check bodies can rely on.
QUERIES = {
    "system_info": "SELECT hostname, uuid, hardware_vendor, hardware_model, "
                    "hardware_serial, cpu_brand, physical_memory FROM system_info;",
    "os_version": "SELECT name, version, platform, platform_like, codename "
                   "FROM os_version;",
    "deb_packages": "SELECT name, version FROM deb_packages;",
    # Service state for the Monitored (M) checks: journald/rsyslog/syslog-ng
    # (MON-01), osqueryd as the endpoint telemetry agent (MON-03), auditd
    # (MON-04). One query, filtered to only the units checks care about.
    "systemd_units": "SELECT id, active_state, sub_state, load_state FROM systemd_units "
                      "WHERE id IN ('systemd-journald.service', 'rsyslog.service', "
                      "'syslog-ng.service', 'osqueryd.service', 'auditd.service');",
    # Controlled (C): whether direct root login is possible. Readable without
    # root -- password_status reflects /etc/shadow's lock state, not the hash
    # itself, and osqueryi (run as an unprivileged user here) can read it.
    "shadow_root": "SELECT username, password_status FROM shadow WHERE username='root';",
    # Controlled (C): who can elevate via sudo -- least-privilege pairs with
    # a locked root account (above): elevation should be possible via sudo,
    # by named accounts, not via direct root login.
    "sudo_users": "SELECT u.username FROM users u "
                   "JOIN user_groups ug ON u.uid = ug.uid "
                   "JOIN groups g ON ug.gid = g.gid "
                   "WHERE g.groupname = 'sudo';",
}

# osquery's SQL surface exposes file *metadata* (the `file` table) but not
# file *content* -- there is no stock table for "does this config file
# contain X". MON-02 (log forwarding) needs to read rsyslog's config for a
# remote destination, so this one fact is collected via a plain shell
# command instead of osqueryi. It's still local read-only fact collection,
# just outside osquery's table set for this one gap.
RSYSLOG_FORWARDING_CHECK_COMMAND = (
    "grep -rhE '^[^#]*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; true"
)


class SSHOsqueryConnector:
    def __init__(
        self,
        ssh_user: str,
        ssh_key_path: str,
        port: int = 22,
        timeout: float = 15.0,
    ):
        self.ssh_user = ssh_user
        self.ssh_key_path = ssh_key_path
        self.port = port
        self.timeout = timeout

    def _run_osquery(self, client: paramiko.SSHClient, query: str) -> List[dict]:
        command = f"osqueryi --json {json.dumps(query)}"
        stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if exit_status != 0:
            raise ConnectorError(f"osqueryi failed (exit {exit_status}): {err.strip()}")
        try:
            return json.loads(out) if out.strip() else []
        except json.JSONDecodeError as exc:
            raise ConnectorError(f"osqueryi returned non-JSON output: {exc}") from exc

    def _run_raw(self, client: paramiko.SSHClient, command: str) -> str:
        """Run a plain shell command and return its stdout. Does not raise on
        a non-zero exit -- used only for commands like grep where "no match"
        (exit 1) is a normal, meaningful result, not a failure."""
        stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
        stdout.channel.recv_exit_status()
        return stdout.read().decode("utf-8", errors="replace")

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
            rsyslog_forwarding_raw = self._run_raw(client, RSYSLOG_FORWARDING_CHECK_COMMAND)
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
        systemd_units = {row["id"]: row for row in results["systemd_units"]}
        shadow_root_rows = results["shadow_root"]
        root_locked = bool(shadow_root_rows) and shadow_root_rows[0].get("password_status") == "locked"

        return {
            "os": os_facts,
            "system_info": system_info,
            "deb_packages": results["deb_packages"],
            "systemd_units": systemd_units,
            "rsyslog_forwarding_configured": bool(rsyslog_forwarding_raw.strip()),
            "root_locked": root_locked,
            "sudo_users": [row["username"] for row in results["sudo_users"]],
        }
