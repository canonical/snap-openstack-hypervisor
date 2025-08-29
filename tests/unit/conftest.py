# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from snaphelpers import Snap, SnapConfig, SnapServices

libvirt_mock = MagicMock()
libvirt_mock.VIR_DOMAIN_RUNNING = 1
libvirt_mock.VIR_DOMAIN_SHUTDOWN = 5
sys.modules["libvirt"] = libvirt_mock


@pytest.fixture
def snap_env(tmpdir: Path):
    """Environment variables defined in the snap.

    This is primarily used to setup the snaphelpers bit.
    """
    yield {
        "SNAP": tmpdir / "snap/mysnap/2",
        "SNAP_COMMON": tmpdir / "var/snap/mysnap/common",
        "SNAP_DATA": tmpdir / "var/snap/mysnap/2",
        "SNAP_INSTANCE_NAME": "",
        "SNAP_NAME": "mysnap",
        "SNAP_REVISION": "2",
        "SNAP_USER_COMMON": "",
        "SNAP_USER_DATA": "",
        "SNAP_VERSION": "1.2.3",
        "SNAP_REAL_HOME": tmpdir / "home/ubuntu",
    }


@pytest.fixture
def snap(snap_env):
    snap = Snap(environ=snap_env)
    snap.config = MagicMock(SnapConfig)
    snap.services = MagicMock(SnapServices)
    yield snap


@pytest.fixture
def os_makedirs():
    with patch("os.makedirs") as p:
        yield p


@pytest.fixture
def check_call():
    with patch("subprocess.check_call") as p:
        yield p


@pytest.fixture
def check_output():
    with patch("subprocess.check_output") as p:
        yield p


@pytest.fixture
def link_lookup():
    with patch("pyroute2.IPRoute.link_lookup") as p:
        yield p


@pytest.fixture
def split():
    yield "1.2.3.4/24"


@pytest.fixture
def addr():
    with patch("pyroute2.IPRoute.addr") as p:
        yield p


@pytest.fixture
def link():
    with patch("pyroute2.IPRoute.link") as p:
        yield p


@pytest.fixture
def ip_interface():
    with patch("ipaddress.ip_interface") as p:
        yield p


@pytest.fixture
def sleep():
    with patch("time.sleep") as p:
        yield p


@pytest.fixture
def libvirt():
    yield libvirt_mock


def mock_vm(name, xml, active):
    vm = MagicMock()
    vm.name = name
    vm.isActive.return_value = active

    def shutdown():
        vm.isActive.return_value = False

    vm.destroy.side_effect = shutdown
    vm.XMLDesc.return_value = xml
    return vm


@pytest.fixture
def vms():
    with open("tests/unit/virsh_openstack.xml", "r") as f:
        os_xml = f.read()
    with open("tests/unit/virsh_non_openstack.xml", "r") as f:
        non_os_xml = f.read()

    vms = {
        "vm1": mock_vm("vm1", os_xml, True),
        "vm2": mock_vm("vm2", non_os_xml, True),
        "vm3": mock_vm("vm3", os_xml, False),
    }
    yield vms


@pytest.fixture()
def ifaddresses():
    ifaddresses = {
        "eth1": {
            17: [{"addr": "00:16:3e:07:ba:1e", "broadcast": "ff:ff:ff:ff:ff:ff"}],
            2: [
                {
                    "addr": "10.177.200.93",
                    "netmask": "255.255.255.0",
                    "broadcast": "10.177.200.255",
                }
            ],
            10: [
                {
                    "addr": "fe80::216:3eff:fe07:ba1e%enp5s0",
                    "netmask": "ffff:ffff:ffff:ffff::/64",
                }
            ],
        },
        "bond1": {
            17: [{"addr": "00:16:3e:07:ba:1e", "broadcast": "ff:ff:ff:ff:ff:ff"}],
            10: [
                {
                    "addr": "fe80::216:3eff:fe07:ba1e%bond1",
                    "netmask": "ffff:ffff:ffff:ffff::/64",
                }
            ],
        },
    }
    with patch("openstack_hypervisor.hooks.ifaddresses") as p:
        p.side_effect = lambda nic: ifaddresses.get(nic)
        yield p


@pytest.fixture()
def get_pci_address():
    with patch("openstack_hypervisor.cli.interfaces.get_pci_address") as p:
        p.side_effect = lambda iface: "pci-addr-%s" % iface
        yield p
