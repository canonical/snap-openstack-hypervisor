# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import pytest

from openstack_hypervisor import manage_guests


class TestManageGuests:
    """Contains tests for openstack_hypervisor.manage_guests."""

    def test_openstack_guest(self):
        with open("tests/unit/virsh_openstack.xml", "r") as f:
            assert manage_guests.openstack_guest(f.read())
        with open("tests/unit/virsh_non_openstack.xml", "r") as f:
            assert not manage_guests.openstack_guest(f.read())

    def test_running_guests(self, mocker, libvirt, vms):
        assert manage_guests.running_guests(list(vms.values())) == [vms["vm1"], vms["vm2"]]

    def test_delete_openstack_guests(self, mocker, libvirt, sleep, vms):
        conn_mock = mocker.Mock()
        libvirt.open.return_value = conn_mock
        conn_mock.listAllDomains.return_value = list(vms.values())
        manage_guests.delete_openstack_guests()
        assert not vms["vm1"].isActive()
        # vm2 is not an openstack vm so should not have been shutdown
        assert vms["vm2"].isActive()
        assert not vms["vm3"].isActive()

    def test_delete_openstack_guests_timeout(self, mocker, libvirt, sleep, vms):
        conn_mock = mocker.Mock()
        libvirt.open.return_value = conn_mock
        conn_mock.listAllDomains.return_value = list(vms.values())
        # Stop VM1 responding to shutdown requests
        vms["vm1"].destroy.side_effect = lambda: None
        with pytest.raises(TimeoutError):
            manage_guests.delete_openstack_guests()
