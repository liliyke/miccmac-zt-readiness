"""Unit tests for miccmac.connectors.ssh_osquery_windows. paramiko is
mocked -- no real SSH connection or network dependency. The one real
end-to-end test against a live VM is opt-in (see tests/test_integration_vm.py
for the Linux precedent; a Windows equivalent can follow the same pattern)."""
import json
from unittest.mock import MagicMock, patch

import pytest

from miccmac.connectors.base import ConnectorError
from miccmac.connectors.ssh_osquery_windows import SSHOsqueryWindowsConnector


def _mock_channel_file(text: str, exit_status: int = 0):
    mock_file = MagicMock()
    mock_file.read.return_value = text.encode("utf-8")
    mock_file.channel.recv_exit_status.return_value = exit_status
    return mock_file


_DEFAULT_RESPONSES = {
    "system_info": [], "os_version": [], "programs": [], "services": [],
    "groupname = 'Administrators'": [], "listening_ports": [], "certificates": [],
    "windows_optional_features": [], "FROM registry": [],
}


def _make_client(query_responses: dict, exit_status: int = 0, stderr_text: str = "",
                 builtin_admin_output: str = "False", firewall_output: str = "True,True,True",
                 last_update_output: str = ""):
    """query_responses: dict of SQL substring -> JSON-encodable rows list,
    merged over _DEFAULT_RESPONSES. Raw (non-osqueryi) PowerShell commands are
    distinguished by distinctive substrings and answered from the *_output
    kwargs, never treated as a query failure."""
    responses = {**_DEFAULT_RESPONSES, **query_responses}
    client = MagicMock()

    def exec_command(command, timeout=None):
        if "osqueryi" not in command:
            if "Get-LocalUser" in command:
                text = builtin_admin_output
            elif "Get-NetFirewallProfile" in command:
                text = firewall_output
            elif "Win32_QuickFixEngineering" in command:
                text = last_update_output
            else:
                text = ""
            stdout = _mock_channel_file(text, 0)
            stderr = _mock_channel_file("")
            return MagicMock(), stdout, stderr
        matched = next((rows for q, rows in responses.items() if q in command), [])
        stdout = _mock_channel_file(json.dumps(matched), exit_status)
        stderr = _mock_channel_file(stderr_text)
        return MagicMock(), stdout, stderr

    client.exec_command.side_effect = exec_command
    return client


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_collect_facts_shapes_os_and_system_info(mock_ssh_client_cls):
    responses = {
        "os_version": [{"name": "Microsoft Windows 11 Enterprise", "version": "10.0.26200",
                        "platform": "windows", "platform_like": "windows", "codename": None}],
        "system_info": [{"hostname": "miccmac-win11", "uuid": "abc", "hardware_vendor": "VMware, Inc.",
                         "hardware_model": "VMware Virtual Platform", "hardware_serial": "VMware-2",
                         "cpu_brand": "Intel", "physical_memory": "8589934592"}],
        "programs": [{"name": "7-Zip", "version": "23.01", "publisher": "Igor Pavlov"},
                    {"name": "Microsoft Edge", "version": "120.0", "publisher": "Microsoft Corporation"}],
        "services": [{"name": "EventLog", "status": "RUNNING", "start_type": "AUTO_START"},
                    {"name": "osqueryd", "status": "RUNNING", "start_type": "AUTO_START"}],
        "groupname = 'Administrators'": [{"username": "miccmac"}],
        "certificates": [],
    }
    mock_client = _make_client(responses, builtin_admin_output="False",
                               firewall_output="True,True,True",
                               last_update_output="2026-08-01T00:00:00")
    mock_ssh_client_cls.return_value = mock_client

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.6")

    assert facts["os"]["platform"] == "windows"
    assert facts["system_info"]["hardware_vendor"] == "VMware, Inc."
    assert len(facts["programs"]) == 2
    assert facts["services"]["osqueryd"]["status"] == "RUNNING"
    assert facts["local_admins"] == ["miccmac"]
    assert facts["builtin_admin_enabled"] is False
    assert facts["firewall_all_profiles_enabled"] is True
    assert facts["last_update_installed_iso"] == "2026-08-01T00:00:00"
    assert facts["expired_certificates"] == []
    mock_client.connect.assert_called_once()
    mock_client.close.assert_called_once()


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_builtin_admin_enabled_true_when_powershell_reports_true(mock_ssh_client_cls):
    mock_ssh_client_cls.return_value = _make_client({}, builtin_admin_output="True")

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.6")

    assert facts["builtin_admin_enabled"] is True


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_firewall_not_all_enabled_when_one_profile_off(mock_ssh_client_cls):
    mock_ssh_client_cls.return_value = _make_client({}, firewall_output="True,True,False")

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.6")

    assert facts["firewall_all_profiles_enabled"] is False


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_last_update_installed_iso_none_when_empty(mock_ssh_client_cls):
    mock_ssh_client_cls.return_value = _make_client({}, last_update_output="")

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.6")

    assert facts["last_update_installed_iso"] is None


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_legacy_features_enabled_filters_to_enabled_only(mock_ssh_client_cls):
    # osquery's real windows_optional_features.state is numeric: "1" enabled,
    # "2" disabled (DISM's FeatureState enum), not the word "Enabled"/"Disabled".
    responses = {
        "windows_optional_features": [{"name": "TelnetClient", "state": "1"},
                                      {"name": "SMB1Protocol", "state": "2"}],
    }
    mock_ssh_client_cls.return_value = _make_client(responses)

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.6")

    assert facts["legacy_features_enabled"] == ["TelnetClient"]


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_hardening_registry_keyed_by_setting_name(mock_ssh_client_cls):
    responses = {
        "FROM registry": [
            {"key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
             "path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA",
             "data": "1"},
        ],
    }
    mock_ssh_client_cls.return_value = _make_client(responses)

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.6")

    assert facts["hardening_registry"] == {"EnableLUA": "1"}


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_nonzero_exit_status_raises_connectorerror(mock_ssh_client_cls):
    mock_client = _make_client({"os_version": []}, exit_status=1, stderr_text="command not found")
    mock_ssh_client_cls.return_value = mock_client

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    with pytest.raises(ConnectorError, match="osqueryi.exe failed"):
        connector.collect_facts("10.0.0.6")


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_non_json_output_raises_connectorerror(mock_ssh_client_cls):
    client = MagicMock()
    stdout = _mock_channel_file("not json at all")
    stderr = _mock_channel_file("")
    client.exec_command.return_value = (MagicMock(), stdout, stderr)
    mock_ssh_client_cls.return_value = client

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    with pytest.raises(ConnectorError, match="non-JSON"):
        connector.collect_facts("10.0.0.6")


@patch("miccmac.connectors.ssh_osquery_windows.paramiko.SSHClient")
def test_connect_failure_raises_connectorerror(mock_ssh_client_cls):
    import paramiko as real_paramiko
    client = MagicMock()
    client.connect.side_effect = real_paramiko.SSHException("auth failed")
    mock_ssh_client_cls.return_value = client

    connector = SSHOsqueryWindowsConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    with pytest.raises(ConnectorError, match="could not SSH"):
        connector.collect_facts("10.0.0.6")
