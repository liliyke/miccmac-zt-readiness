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
}


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

        return {
            "os": os_facts,
            "system_info": system_info,
            "deb_packages": results["deb_packages"],
        }
