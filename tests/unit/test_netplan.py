# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import io
from unittest import mock

import mock_netplan_configs
import yaml

from openstack_hypervisor import netplan


def test_get_netplan_config(check_output):
    check_output.return_value = bytes(
        """
fake-config:
    some-key: some-value
""",
        "utf-8",
    )

    output = netplan.get_netplan_config()
    expected_output = {
        "fake-config": {
            "some-key": "some-value",
        }
    }

    assert expected_output == output
    check_output.assert_called_once_with(["netplan", "get"])


@mock.patch.object(netplan, "get_netplan_config")
def test_remove_interface_from_bridge(mock_get_netplan_config, check_call):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE)
    )

    changes_made = netplan.remove_interface_from_bridge("br0", "eth1")
    assert changes_made

    check_call.assert_called_once_with(["netplan", "set", "bridges.br0.interfaces=NULL"])


@mock.patch.object(netplan, "get_netplan_config")
def test_remove_interface_from_bridge_having_multiple_ports(
    mock_get_netplan_config,
    check_call,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE_MULTIPLE_PORTS)
    )

    changes_made = netplan.remove_interface_from_bridge("br0", "eth1")
    assert changes_made

    check_call.assert_called_once_with(["netplan", "set", "bridges.br0.interfaces=[eth2]"])


@mock.patch.object(netplan, "get_netplan_config")
def test_remove_inexistent_interface_from_bridge(
    mock_get_netplan_config,
    check_call,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE_MULTIPLE_PORTS)
    )

    assert not netplan.remove_interface_from_bridge("br0", "eth0")
    assert not netplan.remove_interface_from_bridge("br5", "eth1")

    check_call.assert_not_called()


@mock.patch("os.path.exists")
def test_remove_bond(mock_exists, check_call):
    mock_exists.return_value = True

    netplan.remove_bond("bond-name")

    check_call.assert_has_calls(
        [
            mock.call(["netplan", "set", "bonds.bond-name=NULL"]),
            mock.call(["ip", "link", "delete", "dev", "bond-name"]),
        ]
    )
    mock_exists.assert_called_once_with("/proc/net/bonding/bond-name")


def test_remove_ethernet(check_call):
    netplan.remove_ethernet("iface-name")

    check_call.assert_called_once_with(["netplan", "set", "ethernets.iface-name=NULL"])


def test_netplan_apply(check_call):
    netplan.apply_netplan()

    check_call.assert_called_once_with(["netplan", "apply"])
