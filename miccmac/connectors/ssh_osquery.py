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
    # 'ufw.service' added for Minimized (MIN-03): host firewall enabled.
    # 'apt-daily-upgrade.timer' added for Current (CUR-01): the mechanism
    # that actually applies OS/security patches on a schedule.
    "systemd_units": "SELECT id, active_state, sub_state, load_state FROM systemd_units "
                      "WHERE id IN ('systemd-journald.service', 'rsyslog.service', "
                      "'syslog-ng.service', 'osqueryd.service', 'auditd.service', "
                      "'ufw.service', 'apt-daily-upgrade.timer');",
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
    # Minimized (M): real, network-reachable TCP/UDP listeners only.
    # listening_ports also returns non-IP (raw/netlink) socket rows with
    # port/protocol '0' (noise, excluded by port != '0'), and loopback-bound
    # services (127.0.0.0/8, ::1 -- e.g. systemd-resolved's stub on
    # 127.0.0.53, cupsd, chronyd) that aren't reachable from the network and
    # so aren't real attack surface for MIN-03 (excluded explicitly, since
    # SQLite's LIKE has no CIDR match).
    "listening_ports": "SELECT DISTINCT port, protocol, address FROM listening_ports "
                        "WHERE protocol IN ('6', '17') AND port != '0' "
                        "AND address NOT LIKE '127.%' AND address != '::1';",
    # Minimized (M, MIN-04): a small sample of CIS-benchmark-relevant kernel
    # hardening parameters. Not exhaustive -- a deliberately simple first
    # pass at "is a recognized hardening baseline actually applied", as
    # opposed to CTL-04's "is a hardening tool merely installed".
    "hardening_sysctls": "SELECT name, current_value FROM system_controls WHERE name IN "
                          "('kernel.dmesg_restrict', 'kernel.kptr_restrict', "
                          "'fs.suid_dumpable', 'net.ipv4.conf.all.rp_filter');",
    # Current (C, CUR-01): when apt last successfully completed an update
    # cycle. mtime is file metadata -- within osquery's normal SQL surface,
    # no raw command needed (unlike MON-02's rsyslog-content gap).
    "apt_update_stamp": "SELECT mtime FROM file "
                         "WHERE path = '/var/lib/apt/periodic/update-success-stamp';",
    # Current (C, CUR-02): configured apt repositories, to distinguish
    # official Ubuntu archives from third-party sources.
    "apt_sources": "SELECT DISTINCT base_uri FROM apt_sources;",
    # Current (C, CUR-03): BIOS/firmware vendor and version. Like
    # system_info's hardware_serial (see INV-02), this is typically empty
    # when osqueryi runs unprivileged -- DMI data requires root.
    "platform_info": "SELECT vendor, version, date FROM platform_info;",
    # Current (C, CUR-04): system trust-store certificates and their expiry.
    # Directly device-observable, unlike CUR-03.
    "certificates": "SELECT common_name, not_valid_after FROM certificates "
                     "WHERE not_valid_after != '' AND not_valid_after < strftime('%s', 'now');",
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

        hardening_sysctls = {row["name"]: row["current_value"] for row in results["hardening_sysctls"]}
        apt_stamp_rows = results["apt_update_stamp"]
        apt_update_stamp_mtime = int(apt_stamp_rows[0]["mtime"]) if apt_stamp_rows else None
        platform_info = results["platform_info"][0] if results["platform_info"] else {}

        return {
            "os": os_facts,
            "system_info": system_info,
            "deb_packages": results["deb_packages"],
            "systemd_units": systemd_units,
            "rsyslog_forwarding_configured": bool(rsyslog_forwarding_raw.strip()),
            "root_locked": root_locked,
            "sudo_users": [row["username"] for row in results["sudo_users"]],
            "listening_ports": results["listening_ports"],
            "hardening_sysctls": hardening_sysctls,
            "apt_update_stamp_mtime": apt_update_stamp_mtime,
            "apt_sources": [row["base_uri"] for row in results["apt_sources"]],
            "platform_info": platform_info,
            "expired_certificates": results["certificates"],
        }
