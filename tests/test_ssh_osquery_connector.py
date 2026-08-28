"""Unit tests for miccmac.connectors.ssh_osquery. paramiko is mocked -- no
real SSH connection or network dependency. The one real end-to-end test
against a live VM is tests/test_integration_vm.py, explicitly opt-in."""
import json
from unittest.mock import MagicMock, patch

import pytest

from miccmac.connectors.base import ConnectorError
from miccmac.connectors.ssh_osquery import SSHOsqueryConnector


def _mock_channel_file(text: str, exit_status: int = 0):
    mock_file = MagicMock()
    mock_file.read.return_value = text.encode("utf-8")
    mock_file.channel.recv_exit_status.return_value = exit_status
    return mock_file


_DEFAULT_RESPONSES = {
    "system_info": [], "os_version": [], "deb_packages": [], "systemd_units": [],
    "shadow": [], "sudo": [], "listening_ports": [], "system_controls": [],
}


def _make_client(query_responses: dict, exit_status: int = 0, stderr_text: str = "",
                 rsyslog_forwarding_output: str = ""):
    """query_responses: dict of SQL substring -> JSON-encodable rows list,
    merged over _DEFAULT_RESPONSES so tests only need to specify what they
    care about. Any command not matching an osqueryi query substring (i.e.
    the raw rsyslog-forwarding grep) returns rsyslog_forwarding_output as
    plain text, exit 0, never treated as a query-failure."""
    responses = {**_DEFAULT_RESPONSES, **query_responses}
    client = MagicMock()

    def exec_command(command, timeout=None):
        if "osqueryi" not in command:
            stdout = _mock_channel_file(rsyslog_forwarding_output, 0)
            stderr = _mock_channel_file("")
            return MagicMock(), stdout, stderr
        matched = next((rows for q, rows in responses.items() if q in command), [])
        stdout = _mock_channel_file(json.dumps(matched), exit_status)
        stderr = _mock_channel_file(stderr_text)
        return MagicMock(), stdout, stderr

    client.exec_command.side_effect = exec_command
    return client


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_collect_facts_shapes_os_and_system_info(mock_ssh_client_cls):
    responses = {
        "os_version": [{"name": "Ubuntu", "version": "26.04", "platform": "ubuntu",
                        "platform_like": "debian", "codename": "resolute"}],
        "system_info": [{"hostname": "miccmac-ubuntu", "uuid": "abc", "hardware_vendor": "VMware, Inc.",
                         "hardware_model": "VMware Virtual Platform", "hardware_serial": "VMware-1",
                         "cpu_brand": "Intel", "physical_memory": "4294967296"}],
        "deb_packages": [{"name": "bash", "version": "5.2"}, {"name": "curl", "version": "8.5"}],
        "systemd_units": [{"id": "osqueryd.service", "active_state": "active",
                          "sub_state": "running", "load_state": "loaded"}],
        "shadow": [{"username": "root", "password_status": "locked"}],
        "sudo": [{"username": "miccmac"}],
    }
    mock_client = _make_client(responses)
    mock_ssh_client_cls.return_value = mock_client

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["os"]["platform"] == "ubuntu"
    assert facts["os"]["codename"] == "resolute"
    assert facts["system_info"]["hardware_vendor"] == "VMware, Inc."
    assert len(facts["deb_packages"]) == 2
    assert facts["systemd_units"]["osqueryd.service"]["active_state"] == "active"
    assert facts["rsyslog_forwarding_configured"] is False
    assert facts["root_locked"] is True
    assert facts["sudo_users"] == ["miccmac"]
    mock_client.connect.assert_called_once()
    mock_client.close.assert_called_once()


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_collect_facts_handles_empty_os_version(mock_ssh_client_cls):
    responses = {"os_version": [], "system_info": [], "deb_packages": [], "systemd_units": []}
    mock_ssh_client_cls.return_value = _make_client(responses)

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["os"] == {"platform": None, "name": None, "version": None, "codename": None}
    assert facts["system_info"] == {}
    assert facts["deb_packages"] == []
    assert facts["systemd_units"] == {}
    assert facts["root_locked"] is False
    assert facts["sudo_users"] == []


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_root_locked_false_when_shadow_status_is_not_locked(mock_ssh_client_cls):
    responses = {"shadow": [{"username": "root", "password_status": "empty"}]}
    mock_ssh_client_cls.return_value = _make_client(responses)

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["root_locked"] is False


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_sudo_users_lists_multiple_accounts(mock_ssh_client_cls):
    responses = {"sudo": [{"username": "alice"}, {"username": "bob"}]}
    mock_ssh_client_cls.return_value = _make_client(responses)

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["sudo_users"] == ["alice", "bob"]


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_listening_ports_and_hardening_sysctls_shaped(mock_ssh_client_cls):
    responses = {
        "listening_ports": [{"port": "22", "protocol": "6", "address": "0.0.0.0"}],
        "system_controls": [{"name": "kernel.dmesg_restrict", "current_value": "1"}],
    }
    mock_ssh_client_cls.return_value = _make_client(responses)

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["listening_ports"] == [{"port": "22", "protocol": "6", "address": "0.0.0.0"}]
    assert facts["hardening_sysctls"] == {"kernel.dmesg_restrict": "1"}


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_rsyslog_forwarding_configured_true_when_grep_matches(mock_ssh_client_cls):
    responses = {"os_version": [], "system_info": [], "deb_packages": [], "systemd_units": []}
    mock_client = _make_client(responses, rsyslog_forwarding_output="*.* @@siem.example.com:514\n")
    mock_ssh_client_cls.return_value = mock_client

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["rsyslog_forwarding_configured"] is True


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_rsyslog_forwarding_configured_false_when_grep_finds_nothing(mock_ssh_client_cls):
    responses = {"os_version": [], "system_info": [], "deb_packages": [], "systemd_units": []}
    mock_client = _make_client(responses, rsyslog_forwarding_output="")
    mock_ssh_client_cls.return_value = mock_client

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["rsyslog_forwarding_configured"] is False


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_nonzero_exit_status_raises_connectorerror(mock_ssh_client_cls):
    mock_client = _make_client({"os_version": []}, exit_status=1, stderr_text="command not found")
    mock_ssh_client_cls.return_value = mock_client

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    with pytest.raises(ConnectorError, match="osqueryi failed"):
        connector.collect_facts("10.0.0.5")


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_non_json_output_raises_connectorerror(mock_ssh_client_cls):
    client = MagicMock()
    stdout = _mock_channel_file("not json at all")
    stderr = _mock_channel_file("")
    client.exec_command.return_value = (MagicMock(), stdout, stderr)
    mock_ssh_client_cls.return_value = client

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    with pytest.raises(ConnectorError, match="non-JSON"):
        connector.collect_facts("10.0.0.5")


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_connect_failure_raises_connectorerror(mock_ssh_client_cls):
    import paramiko as real_paramiko
    client = MagicMock()
    client.connect.side_effect = real_paramiko.SSHException("auth failed")
    mock_ssh_client_cls.return_value = client

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    with pytest.raises(ConnectorError, match="could not SSH"):
        connector.collect_facts("10.0.0.5")
