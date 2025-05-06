# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock, patch

import pytest

from openstack_hypervisor.cli.interfaces import filter_candidate_nics

INTERFACES = [
    {
        "ifname": "eth0",
        "slave_kind": None,
        "kind": "eth",
        "ipaddr": [{"address": "192.168.1.1"}],
    },
    {
        "ifname": "eth1",
        "slave_kind": "bond",
        "kind": "eth",
        "ipaddr": [{"address": "192.168.1.2"}],
    },
    {
        "ifname": "eth2",
        "slave_kind": None,
        "kind": "eth",
        "ipaddr": [],
    },
    {
        "ifname": "vlan0",
        "slave_kind": None,
        "kind": "vlan",
        "ipaddr": [{"address": "fe80::1"}],  # link local
    },
    {
        "ifname": "bond0",
        "slave_kind": None,
        "kind": "bond",
        "ipaddr": [{"address": "192.168.1.3"}],
    },
    {
        "ifname": "bond1",
        "slave_kind": None,
        "kind": "bond",
        "ipaddr": [],
    },
]


@pytest.fixture
def mock_interfaces():
    nics = []
    for interface in INTERFACES:
        iface = MagicMock()
        iface.__getitem__.side_effect = interface.__getitem__
        iface.ipaddr.summary.return_value = interface["ipaddr"]
        nics.append(iface)

    return nics


@patch(
    "openstack_hypervisor.cli.interfaces.load_virtual_interfaces",
    return_value=["vlan0", "bond0", "bond1"],
)
def test_filter_candidate_nics(mock_load_virtual_interfaces, mock_interfaces):
    result = filter_candidate_nics(mock_interfaces)
    assert result == ["eth0", "eth2", "vlan0", "bond0", "bond1"]
