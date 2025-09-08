# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

# Mock Netplan configuration used for testing purposes.


MOCK_NETPLAN_OVS_BRIDGE = """
network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: "00:16:3e:cf:59:cd"
      addresses:
      - "1.2.3.4/24"
      nameservers:
        addresses:
        - 1.2.3.5
        search:
        - maas
      gateway4: 1.2.3.1
      set-name: "eth0"
      mtu: 1500
    eth1:
      match:
        macaddress: "00:16:3e:c0:43:a8"
      set-name: "eth1"
      mtu: 1500
    eth2:
      match:
        macaddress: "00:16:3e:6b:59:13"
      set-name: "eth2"
      mtu: 1500
  bridges:
    br0:
      macaddress: "00:16:3e:c0:43:a8"
      mtu: 1500
      interfaces:
      - eth1
      parameters:
        forward-delay: "15"
        stp: false
      openvswitch: {}
"""


MOCK_NETPLAN_OVS_BRIDGE_WITH_BOND = """
network:
  version: 2
  ethernets:
    eth1:
      match:
        macaddress: "00:16:3e:c0:43:a8"
      set-name: "eth1"
      mtu: 1500
    eth2:
      match:
        macaddress: "00:16:3e:6b:59:13"
      set-name: "eth2"
      mtu: 1500
  bridges:
    br0:
      macaddress: "00:16:3e:c0:43:a8"
      mtu: 1500
      interfaces:
      - bond0
      parameters:
        forward-delay: "15"
        stp: false
      openvswitch: {}
  bonds:
    bond0:
      macaddress: "00:16:3e:c0:43:a8"
      mtu: 1500
      parameters:
        mode: 802.3ad
        lacp-rate: slow
      interfaces:
      - eth1
      - eth2
"""


MOCK_NETPLAN_OVS_WITH_BOND_NO_BRIDGE = """
network:
  version: 2
  ethernets:
    eth1:
      match:
        macaddress: "00:16:3e:c0:43:a8"
      set-name: "eth1"
      mtu: 1500
    eth2:
      match:
        macaddress: "00:16:3e:6b:59:13"
      set-name: "eth2"
      mtu: 1500
  bonds:
    bond0:
      macaddress: "00:16:3e:c0:43:a8"
      mtu: 1500
      parameters:
        mode: 802.3ad
        lacp-rate: slow
      interfaces:
      - eth1
      - eth2
"""

MOCK_NETPLAN_OVS_NO_BRIDGE = """
network:
  version: 2
  ethernets:
    eth1:
      match:
        macaddress: "00:16:3e:c0:43:a8"
      set-name: "eth1"
      mtu: 1500
    eth2:
      match:
        macaddress: "00:16:3e:6b:59:13"
      set-name: "eth2"
      mtu: 1500
  bonds:
    bond0:
      macaddress: "00:16:3e:c0:43:a8"
      mtu: 1500
      parameters:
        mode: 802.3ad
        lacp-rate: slow
      interfaces:
      - eth1
      - eth2
"""


MOCK_NETPLAN_OVS_BRIDGE_MULTIPLE_PORTS = """
network:
  version: 2
  ethernets:
    eth1:
      match:
        macaddress: "00:16:3e:c0:43:a8"
      set-name: "eth1"
      mtu: 1500
    eth2:
      match:
        macaddress: "00:16:3e:6b:59:13"
      set-name: "eth2"
      mtu: 1500
  bridges:
    br0:
      macaddress: "00:16:3e:c0:43:a8"
      mtu: 1500
      interfaces:
      - eth1
      - eth2
      parameters:
        forward-delay: "15"
        stp: false
      openvswitch: {}
"""
