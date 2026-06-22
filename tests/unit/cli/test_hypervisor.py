# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from openstack_hypervisor.cli.hypervisor import hypervisor


@pytest.fixture
def mock_snap():
    """Create a mock Snap instance."""
    snap = MagicMock()
    snap.paths.common = "/var/snap/test/common"
    snap.paths.data = "/var/snap/test/data"
    snap.paths.snap = "/snap/test/current"
    snap.name = "test-snap"
    return snap


@pytest.fixture
def mock_ovs_cli():
    """Create a mock OVSCli instance."""
    return MagicMock()


class TestDPDKReadyCommand:
    """Tests for the dpdk-ready CLI command."""

    @patch("openstack_hypervisor.hooks.is_connected")
    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._dpdk_config_is_ready")
    def test_dpdk_ready_success(
        self,
        mock_dpdk_ready,
        mock_get_context,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
        mock_connected,
    ):
        """Test dpdk-ready command returns 0 when ready."""
        mock_dpdk_ready.return_value = True
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/some/path"

        runner = CliRunner()
        result = runner.invoke(hypervisor, ["dpdk-ready"])

        assert result.exit_code == 0
        assert "DPDK configuration is ready" in result.output

    @patch("openstack_hypervisor.hooks.is_connected")
    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._dpdk_config_is_ready")
    def test_dpdk_ready_not_ready(
        self,
        mock_dpdk_ready,
        mock_get_context,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
        mock_connected,
    ):
        """Test dpdk-ready command returns 1 when not ready."""
        mock_dpdk_ready.return_value = False
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/some/path"

        runner = CliRunner()
        result = runner.invoke(hypervisor, ["dpdk-ready"])

        assert result.exit_code == 1
        assert "NOT ready" in result.output

    @patch("openstack_hypervisor.hooks.is_connected")
    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switchd_ctl_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._dpdk_config_is_ready")
    def test_dpdk_ready_uses_correct_socket(
        self,
        mock_dpdk_ready,
        mock_get_context,
        mock_switchd_ctl_socket,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
        mock_connected,
    ):
        """Test dpdk-ready command uses ovs_switch_socket."""
        mock_dpdk_ready.return_value = True
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/custom/socket/path"
        mock_switchd_ctl_socket.return_value = "unix:/custom/ctl/socket/path"

        runner = CliRunner()
        runner.invoke(hypervisor, ["dpdk-ready"])

        # Verify OVSCli was created with the socket from ovs_switch_socket
        mock_ovs_cli_class.assert_called_once_with(
            "unix:/custom/socket/path", "unix:/custom/ctl/socket/path"
        )


class TestSetupBridgeCommand:
    @patch("openstack_hypervisor.hooks.is_connected")
    @patch("openstack_hypervisor.cli.hypervisor._set_ovs_managed_by")
    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switchd_ctl_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._configure_ovn_external_networking")
    def test_setup_bridge_defaults_to_fresh_sb_reads(
        self,
        mock_setup_bridge,
        mock_get_context,
        mock_switchd_ctl_socket,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
        mock_set_ovs_managed_by,
        mock_connected,
    ):
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/custom/socket/path"
        mock_switchd_ctl_socket.return_value = "unix:/custom/ctl/socket/path"

        runner = CliRunner()
        result = runner.invoke(hypervisor, ["setup-bridge"])

        assert result.exit_code == 0
        mock_set_ovs_managed_by.assert_called_once_with(mock_snap_class.return_value)
        mock_setup_bridge.assert_called_once_with(
            mock_snap_class.return_value,
            mock_ovs_cli_class.return_value,
            {"network": {}},
            allow_stale_sb_read=False,
        )

    @patch("openstack_hypervisor.hooks.is_connected")
    @patch("openstack_hypervisor.cli.hypervisor.click.echo")
    @patch("openstack_hypervisor.cli.hypervisor._set_ovs_managed_by")
    @patch("openstack_hypervisor.cli.hypervisor.Snap")
    @patch("openstack_hypervisor.cli.hypervisor.OVSCli")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switch_socket")
    @patch("openstack_hypervisor.cli.hypervisor.ovs_switchd_ctl_socket")
    @patch("openstack_hypervisor.cli.hypervisor._get_configure_context")
    @patch("openstack_hypervisor.cli.hypervisor._configure_ovn_external_networking")
    def test_setup_bridge_allows_stale_sb_reads_with_flag(
        self,
        mock_setup_bridge,
        mock_get_context,
        mock_switchd_ctl_socket,
        mock_socket,
        mock_ovs_cli_class,
        mock_snap_class,
        mock_set_ovs_managed_by,
        mock_echo,
        mock_connected,
    ):
        mock_get_context.return_value = {"network": {}}
        mock_socket.return_value = "unix:/custom/socket/path"
        mock_switchd_ctl_socket.return_value = "unix:/custom/ctl/socket/path"

        runner = CliRunner()
        result = runner.invoke(hypervisor, ["setup-bridge", "--allow-stale-sb-read"])

        assert result.exit_code == 0
        mock_set_ovs_managed_by.assert_called_once_with(mock_snap_class.return_value)
        mock_setup_bridge.assert_called_once_with(
            mock_snap_class.return_value,
            mock_ovs_cli_class.return_value,
            {"network": {}},
            allow_stale_sb_read=True,
        )
        mock_echo.assert_any_call(
            "Warning: allowing stale OVN Southbound reads may misjudge bridge rename safety."
        )
