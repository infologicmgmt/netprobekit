"""
Filename: tests/test_cli.py
Author: Michael Moscovitch
Assistant: Jules
Date: 2026/01/10
Copyright (c) 2026 Michael Moscovitch
Description: Unit tests for the CLI
"""
from click.testing import CliRunner
from netprobe.cli import cli
from unittest.mock import patch

@patch('netprobe.cli.NetProbeApp')
def test_show_config(MockNetProbeApp):
    """Test the show-config command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.show_config.return_value = '{"server": {"host": "127.0.0.1"}}'

    runner = CliRunner()
    result = runner.invoke(cli, ["show-config"], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert '{"server": {"host": "127.0.0.1"}}' in result.output
    mock_app_instance.show_config.assert_called_once()


def test_cli_no_api_key(monkeypatch):
    """Test that the CLI exits gracefully if the API key is not set."""
    monkeypatch.delenv("NETPROBE_API_KEY", raising=False)
    runner = CliRunner()
    result = runner.invoke(cli, ["show-config"])
    assert result.exit_code == 1
    assert "API key not found" in result.output


@patch('netprobe.cli.NetProbeApp')
def test_add_node(MockNetProbeApp):
    """Test the add command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.add_node.return_value = "Node 1.1.1.1 added successfully"

    runner = CliRunner()
    result = runner.invoke(cli, ["add", "--target", "1.1.1.1", "--org-id", "1"], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert "Node 1.1.1.1 added successfully" in result.output
    mock_app_instance.add_node.assert_called_once_with("1.1.1.1", 'v2c', 'public', 1)


@patch('netprobe.cli.NetProbeApp')
def test_delete_node(MockNetProbeApp):
    """Test the delete command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.delete_node.return_value = "Node 123 deleted successfully"

    runner = CliRunner()
    result = runner.invoke(cli, ["delete", "--target", "123"], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert "Node 123 deleted successfully" in result.output
    mock_app_instance.delete_node.assert_called_once_with("123")


@patch('netprobe.cli.NetProbeApp')
def test_scan(MockNetProbeApp):
    """Test the scan command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.scan.return_value = "Scan for 192.168.1.0/24 initiated successfully"

    runner = CliRunner()
    result = runner.invoke(cli, [
        "scan",
        "--target", "192.168.1.0/24",
        "--site-id", "1",
        "--snmp-profile-id", "2",
        "--scan-profile-id", "3",
        "--org-id", "4"
    ], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert "Scan for 192.168.1.0/24 initiated successfully" in result.output
    mock_app_instance.scan.assert_called_once_with("192.168.1.0/24", 1, 2, 3, 4)


@patch('netprobe.cli.NetProbeApp')
def test_config(MockNetProbeApp):
    """Test the config command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.manage_config.return_value = "Set agent.server_url = http://new-server"

    runner = CliRunner()
    result = runner.invoke(cli, ["config", "--set", "agent.server_url=http://new-server"], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert "Set agent.server_url = http://new-server" in result.output
    mock_app_instance.manage_config.assert_called_once_with("agent.server_url=http://new-server")


@patch('netprobe.cli.NetProbeApp')
def test_switchport_report(MockNetProbeApp):
    """Test the switchport report command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.report_switchport.return_value = "Switch port report generated as switchport_report.csv"

    runner = CliRunner()
    result = runner.invoke(cli, ["report", "switchport", "--format", "csv"], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert "Switch port report generated as switchport_report.csv" in result.output
    mock_app_instance.report_switchport.assert_called_once_with("csv")


@patch('netprobe.cli.NetProbeApp')
def test_init(MockNetProbeApp):
    """Test the init command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.init_db.return_value = "Database initialized successfully."

    runner = CliRunner()
    result = runner.invoke(cli, ["init"], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert "Database initialized successfully." in result.output
    mock_app_instance.init_db.assert_called_once()


@patch('netprobe.cli.NetProbeApp')
def test_version(MockNetProbeApp):
    """Test the version command."""
    mock_app_instance = MockNetProbeApp.return_value
    mock_app_instance.get_version.return_value = "0.1.0"

    runner = CliRunner()
    result = runner.invoke(cli, ["version"], env={"NETPROBE_API_KEY": "test-key"})

    assert result.exit_code == 0
    assert "0.1.0" in result.output
    mock_app_instance.get_version.assert_called_once()
