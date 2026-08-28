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


def _make_client(query_responses: dict, exit_status: int = 0, stderr_text: str = ""):
    """query_responses: dict of SQL substring -> JSON-encodable rows list."""
    client = MagicMock()

    def exec_command(command, timeout=None):
        matched = next((rows for q, rows in query_responses.items() if q in command), [])
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
    }
    mock_client = _make_client(responses)
    mock_ssh_client_cls.return_value = mock_client

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["os"]["platform"] == "ubuntu"
    assert facts["os"]["codename"] == "resolute"
    assert facts["system_info"]["hardware_vendor"] == "VMware, Inc."
    assert len(facts["deb_packages"]) == 2
    mock_client.connect.assert_called_once()
    mock_client.close.assert_called_once()


@patch("miccmac.connectors.ssh_osquery.paramiko.SSHClient")
def test_collect_facts_handles_empty_os_version(mock_ssh_client_cls):
    responses = {"os_version": [], "system_info": [], "deb_packages": []}
    mock_ssh_client_cls.return_value = _make_client(responses)

    connector = SSHOsqueryConnector(ssh_user="miccmac", ssh_key_path="/fake/key")
    facts = connector.collect_facts("10.0.0.5")

    assert facts["os"] == {"platform": None, "name": None, "version": None, "codename": None}
    assert facts["system_info"] == {}
    assert facts["deb_packages"] == []


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
