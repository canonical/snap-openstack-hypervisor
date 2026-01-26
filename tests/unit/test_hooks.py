# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import io
import json
import random
import textwrap
from unittest import mock

import mock_netplan_configs
import pytest
import yaml
from snaphelpers._conf import UnknownConfigKey

from openstack_hypervisor import hooks
from openstack_hypervisor.cli import pci_devices


class TestHooks:
    """Contains tests for openstack_hypervisor.hooks."""

    def test_install_hook(self, mocker, snap):
        """Tests the install hook."""
        mocker.patch.object(hooks, "_secure_copy")
        hooks.install(snap)

    def test_get_local_ip_by_default_route(self, mocker, ifaddresses):
        """Test get local ip by default route."""
        gateways = mocker.patch("openstack_hypervisor.hooks.gateways")
        gateways.return_value = {"default": {2: ("10.177.200.1", "eth1")}}
        assert hooks._get_local_ip_by_default_route() == "10.177.200.93"

    def test_get_local_ip_by_default_route_no_default(self, mocker, ifaddresses):
        """Test netifaces returns no default route."""
        gateways = mocker.patch("openstack_hypervisor.hooks.gateways")
        fallback = mocker.patch("openstack_hypervisor.hooks._get_default_gw_iface_fallback")
        gateways.return_value = {"default": {}}
        fallback.return_value = "eth1"
        assert hooks._get_local_ip_by_default_route() == "10.177.200.93"

    def test__get_default_gw_iface_fallback(self):
        """Test default gateway iface fallback returns iface."""
        proc_net_route = textwrap.dedent("""\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0003	0	0	0	00000000	0	0	0
        ens10f3	000A010A	00000000	0001	0	0	0	00FEFFFF	0	0	0
        ens10f2	000A010A	00000000	0001	0	0	0	00FEFFFF	0	0	0
        ens10f0	000A010A	00000000	0001	0	0	0	00FEFFFF	0	0	0
        ens4f0	0018010A	00000000	0001	0	0	0	00FCFFFF	0	0	0
        ens10f1	0080F50A	00000000	0001	0	0	0	00F8FFFF	0	0	0""")
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() == "ens10f0"

    def test__get_default_gw_iface_fallback_no_0_dest(self):
        """Test route has 000 mask but no 000 dest, then returns None."""
        proc_net_route = textwrap.dedent("""
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000001	020A010A	0003	0	0	0	00000000	0	0	0
        """)
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() is None

    def test__get_default_gw_iface_fallback_no_0_mask(self):
        """Test route has a 000 dest but no 000 mask, then returns None."""
        proc_net_route = textwrap.dedent("""
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0003	0	0	0	0000000F	0	0	0
        """)
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() is None

    def test__get_default_gw_iface_fallback_not_up(self):
        """Tests route is a gateway but not up, then returns None."""
        proc_net_route = textwrap.dedent("""
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0002	0	0	0	00000000	0	0	0
        """)
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() is None

    def test__get_default_gw_iface_fallback_up_but_not_gateway(self):
        """Tests route is up but not a gateway, then returns None."""
        proc_net_route = textwrap.dedent("""
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0001	0	0	0	00000000	0	0	0
        """)
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() is None

    def test_get_template(self, mocker, snap):
        """Tests retrieving the template."""
        mock_fs_loader = mocker.patch.object(hooks, "FileSystemLoader")
        mocker.patch.object(hooks, "Environment")
        hooks._get_template(snap, "foo.bar")
        mock_fs_loader.assert_called_once_with(searchpath=str(snap.paths.snap / "templates"))

    def test_configure_hook(
        self, mocker, snap, check_call, link_lookup, split, addr, link, ip_interface
    ):
        """Tests the configure hook."""
        mock_template = mocker.Mock()
        mocker.patch.object(hooks, "_secure_copy")
        mocker.patch.object(hooks, "_process_dpdk_ports")
        mocker.patch.object(hooks, "_get_template", return_value=mock_template)
        mocker.patch.object(hooks, "OVSCli", spec=hooks.OVSCli)
        mock_write_text = mocker.patch.object(hooks.Path, "write_text")
        mock_chmod = mocker.patch.object(hooks.Path, "chmod")
        mocker.patch(
            "openstack_hypervisor.hooks.get_cpu_pinning_from_socket", return_value=("0-3", "4-7")
        )
        hooks.configure(snap)
        mock_template.render.assert_called()
        mock_write_text.assert_called()
        mock_chmod.assert_called()

    def test_configure_hook_exception(self, mocker, snap, os_makedirs, check_call):
        """Tests the configure hook raising an exception while writing file."""
        mock_template = mocker.Mock()
        mocker.patch.object(hooks, "_get_template", return_value=mock_template)
        mocker.patch.object(hooks.Path, "write_text")
        mocker.patch.object(hooks.Path, "chmod")
        mocker.patch(
            "openstack_hypervisor.hooks.get_cpu_pinning_from_socket", return_value=("0-3", "4-7")
        )
        with pytest.raises(FileNotFoundError):
            hooks.configure(snap)

    def test_services(self):
        """Test getting a list of managed services."""
        assert hooks.services() == [
            "ceilometer-compute-agent",
            "libvirtd",
            "masakari-instancemonitor",
            "neutron-ovn-metadata-agent",
            "neutron-sriov-nic-agent",
            "nova-api-metadata",
            "nova-compute",
            "virtlogd",
        ]

    def test_section_complete(self):
        assert hooks._section_complete("identity", {"identity": {"password": "foo"}})
        assert hooks._section_complete(
            "identity", {"identity": {"username": "user", "password": "foo"}}
        )
        assert not hooks._section_complete(
            "identity", {"identity": {"username": "user", "password": ""}}
        )
        assert not hooks._section_complete("identity", {"identity": {"password": ""}})
        assert not hooks._section_complete("identity", {"rabbitmq": {"url": "rabbit://sss"}})

    def test_check_config_present(self):
        assert hooks._check_config_present("identity.password", {"identity": {"password": "foo"}})
        assert hooks._check_config_present("identity", {"identity": {"password": "foo"}})
        assert not hooks._check_config_present(
            "identity.password", {"rabbitmq": {"url": "rabbit://sss"}}
        )

    def test_services_not_ready(self, snap):
        config = {}
        assert hooks._services_not_ready(config) == [
            "ceilometer-compute-agent",
            "masakari-instancemonitor",
            "neutron-ovn-metadata-agent",
            "nova-api-metadata",
            "nova-compute",
        ]
        config["identity"] = {"username": "user", "password": "pass"}
        assert hooks._services_not_ready(config) == [
            "ceilometer-compute-agent",
            "masakari-instancemonitor",
            "neutron-ovn-metadata-agent",
            "nova-api-metadata",
            "nova-compute",
        ]
        config["rabbitmq"] = {"url": "rabbit://localhost:5672"}
        config["node"] = {"fqdn": "myhost.maas"}
        assert hooks._services_not_ready(config) == [
            "neutron-ovn-metadata-agent",
            "nova-api-metadata",
        ]
        config["network"] = {
            "external-bridge-address": "10.0.0.10",
            "ovn_cert": "cert",
            "ovn_key": "key",
            "ovn_cacert": "cacert",
        }
        assert hooks._services_not_ready(config) == ["neutron-ovn-metadata-agent"]
        config["credentials"] = {"ovn_metadata_proxy_shared_secret": "secret"}
        assert hooks._services_not_ready(config) == []

    def test_services_not_enabled_by_config(self, snap):
        config = {}
        assert hooks._services_not_enabled_by_config(config) == [
            "ceilometer-compute-agent",
            "masakari-instancemonitor",
        ]
        config["telemetry"] = {"enable": True}
        config["masakari"] = {"enable": True}
        assert hooks._services_not_enabled_by_config(config) == []

    def test_add_interface_to_bridge(self, ovs_cli):
        ovs_cli.list_bridge_interfaces.return_value = ["int1", "int2"]
        hooks._add_interface_to_bridge(ovs_cli, "br1", "int3")
        ovs_cli.add_port.assert_called_once_with(
            "br1",
            "int3",
            external_ids={"microstack-function": "ext-port"},
        )

    def test_add_interface_to_bridge_noop(self, ovs_cli):
        ovs_cli.list_bridge_interfaces.return_value = ["int1", "int2"]
        hooks._add_interface_to_bridge(ovs_cli, "br1", "int2")
        assert not ovs_cli.add_port.called

    def test_del_interface_from_bridge(self, ovs_cli):
        ovs_cli.list_bridge_interfaces.return_value = ["int1", "int2"]
        hooks._del_interface_from_bridge(ovs_cli, "br1", "int2")
        ovs_cli.del_port.assert_called_once_with("br1", "int2")

    def test_del_interface_from_bridge_noop(self, ovs_cli):
        ovs_cli.list_bridge_interfaces.return_value = ["int1", "int2"]
        hooks._del_interface_from_bridge(ovs_cli, "br1", "int3")
        assert not ovs_cli.del_port.called

    def test_get_external_ports_on_bridge(self, ovs_cli):
        port_data = {
            "data": [
                [
                    ["uuid", "efd95c01-d658-4847-8506-664eec95e653"],
                    ["set", []],
                    0,
                    False,
                    ["set", []],
                    0,
                    ["set", []],
                    ["map", [["microk8s-function", "external-nic"]]],
                    False,
                    ["uuid", "92f62f7c-53f2-4362-bbd5-9b46b8f88632"],
                    ["set", []],
                    ["set", []],
                    "enp6s0",
                    ["map", []],
                    False,
                    ["set", []],
                    ["map", []],
                    ["map", []],
                    ["map", []],
                    ["map", []],
                    ["set", []],
                    ["set", []],
                    ["set", []],
                ]
            ],
            "headings": [
                "_uuid",
                "bond_active_slave",
                "bond_downdelay",
                "bond_fake_iface",
                "bond_mode",
                "bond_updelay",
                "cvlans",
                "external_ids",
                "fake_bridge",
                "interfaces",
                "lacp",
                "mac",
                "name",
                "other_config",
                "protected",
                "qos",
                "rstp_statistics",
                "rstp_status",
                "statistics",
                "status",
                "tag",
                "trunks",
                "vlan_mode",
            ],
        }
        ovs_cli.find.return_value = port_data
        ovs_cli.list_bridge_interfaces.return_value = ["enp6s0"]
        assert hooks._get_external_ports_on_bridge(ovs_cli, "br-ex") == ["enp6s0"]
        ovs_cli.list_bridge_interfaces.return_value = []
        assert hooks._get_external_ports_on_bridge(ovs_cli, "br-ex") == []

    def test_ensure_single_nic_on_bridge(self, ovs_cli, mocker):
        mock_get_external_ports_on_bridge = mocker.patch.object(
            hooks, "_get_external_ports_on_bridge"
        )
        mock_add_interface_to_bridge = mocker.patch.object(hooks, "_add_interface_to_bridge")
        mock_del_interface_from_bridge = mocker.patch.object(hooks, "_del_interface_from_bridge")
        mock_get_external_ports_on_bridge.return_value = ["eth0", "eth1"]
        hooks._ensure_single_nic_on_bridge(ovs_cli, "br-ex", "eth1")
        assert not mock_add_interface_to_bridge.called
        mock_del_interface_from_bridge.assert_called_once_with(ovs_cli, "br-ex", "eth0")

        mock_get_external_ports_on_bridge.reset_mock()
        mock_add_interface_to_bridge.reset_mock()
        mock_del_interface_from_bridge.reset_mock()
        mock_get_external_ports_on_bridge.return_value = []
        hooks._ensure_single_nic_on_bridge(ovs_cli, "br-ex", "eth1")
        mock_add_interface_to_bridge.assert_called_once_with(ovs_cli, "br-ex", "eth1")
        assert not mock_del_interface_from_bridge.called

    def test_del_external_nics_from_bridge(self, ovs_cli, mocker):
        mock_get_external_ports_on_bridge = mocker.patch.object(
            hooks, "_get_external_ports_on_bridge"
        )
        mock_del_interface_from_bridge = mocker.patch.object(hooks, "_del_interface_from_bridge")
        mock_get_external_ports_on_bridge.return_value = ["eth0", "eth1"]
        hooks._del_external_nics_from_bridge(ovs_cli, "br-ex")
        expect = [mock.call(ovs_cli, "br-ex", "eth0"), mock.call(ovs_cli, "br-ex", "eth1")]
        mock_del_interface_from_bridge.assert_has_calls(expect)

    def test_set_secret(self, mocker):
        conn_mock = mocker.Mock()
        secret_mock = mocker.Mock()
        conn_mock.secretDefineXML.return_value = secret_mock
        hooks._set_secret(conn_mock, "uuid1", "c2VjcmV0Cg==")
        conn_mock.secretDefineXML.assert_called_once()
        secret_mock.setValue.assert_called_once_with(b"secret\n")

    def test_ensure_secret_new_secret(self, mocker):
        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        mock_set_secret = mocker.patch.object(hooks, "_set_secret")
        conn_mock.listSecrets.return_value = []
        hooks._ensure_secret("uuid1", "secret")
        mock_set_secret.assert_called_once_with(conn_mock, "uuid1", "secret")

    def test_ensure_secret_secret_exists(self, mocker):
        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        secret_mock = mocker.Mock()
        secret_mock.value.return_value = b"c2VjcmV0"
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        mock_set_secret = mocker.patch.object(hooks, "_set_secret")
        conn_mock.listSecrets.return_value = ["uuid1"]
        conn_mock.secretLookupByUUIDString.return_value = secret_mock
        hooks._ensure_secret("uuid1", "secret")
        assert not mock_set_secret.called

    def test_ensure_secret_secret_wrong_value(self, mocker):
        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        secret_mock = mocker.Mock()
        secret_mock.value.return_value = b"wrong"
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        mock_set_secret = mocker.patch.object(hooks, "_set_secret")
        conn_mock.listSecrets.return_value = ["uuid1"]
        conn_mock.secretLookupByUUIDString.return_value = secret_mock
        hooks._ensure_secret("uuid1", "secret")
        mock_set_secret.assert_called_once_with(conn_mock, "uuid1", "secret")

    def test_ensure_secret_secret_missing_value(self, mocker):
        class FakeError(Exception):
            def get_error_code(self):
                return 42

        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        mock_libvirt.libvirtError = FakeError
        mock_libvirt.VIR_ERR_NO_SECRET = 42
        secret_mock = mocker.Mock()
        secret_mock.value.side_effect = FakeError()
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        mock_set_secret = mocker.patch.object(hooks, "_set_secret")
        conn_mock.listSecrets.return_value = ["uuid1"]
        conn_mock.secretLookupByUUIDString.return_value = secret_mock
        hooks._ensure_secret("uuid1", "secret")
        mock_set_secret.assert_called_once_with(conn_mock, "uuid1", "secret")

    def test_detect_compute_flavors_no_rights(self, mocker, snap):
        mocker.patch("pathlib.Path.read_text", mock.Mock(side_effect=PermissionError))
        hooks._detect_compute_flavors(snap)
        snap.config.set.assert_not_called()

    def test_detect_compute_flavors_with_no_flavors_set(self, mocker, snap):
        mocker.patch("pathlib.Path.read_text", mock.Mock(return_value="Y"))
        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        conn_mock.getDomainCapabilities.return_value = """<domainCapabilities>
        <features>
          <sev supported='yes'/>
        </features>
        </domainCapabilities>
        """

        snap.config.get.side_effect = UnknownConfigKey("compute.flavors")
        hooks._detect_compute_flavors(snap)
        snap.config.set.assert_called_once_with({"compute.flavors": "sev"})

    def test_detect_compute_flavors_with_flavors_set(self, mocker, snap):
        mocker.patch("pathlib.Path.read_text", mock.Mock(return_value="Y"))
        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        conn_mock.getDomainCapabilities.return_value = """<domainCapabilities>
        <features>
          <sev supported='yes'/>
        </features>
        </domainCapabilities>
        """

        snap.config.get.return_value = "flavor1"
        hooks._detect_compute_flavors(snap)
        snap.config.set.assert_called_once_with({"compute.flavors": "flavor1,sev"})

    def test_detect_compute_flavors_with_sev_flavor_already_set(self, mocker, snap):
        mock_os_path_exists = mocker.patch("os.path.exists")
        mock_os_path_exists.return_value = True
        mocker.patch("builtins.open", mock.mock_open(read_data="Y"))
        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        conn_mock.getDomainCapabilities.return_value = """<domainCapabilities>
        <features>
          <sev supported='yes'/>
        </features>
        </domainCapabilities>
        """

        snap.config.get.return_value = "sev"
        hooks._detect_compute_flavors(snap)
        snap.config.set.assert_not_called()

    def test_detect_compute_flavors_with_libvirt_sev_capability_no(self, mocker, snap):
        mock_os_path_exists = mocker.patch("os.path.exists")
        mock_os_path_exists.return_value = True
        mocker.patch("builtins.open", mock.mock_open(read_data="Y"))
        conn_mock = mocker.Mock()
        mock_libvirt = mocker.Mock()
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt
        mock_libvirt.open.return_value = conn_mock
        conn_mock.getDomainCapabilities.return_value = """<domainCapabilities>
        <features>
          <sev supported='no'/>
        </features>
        </domainCapabilities>
        """

        snap.config.get.side_effect = UnknownConfigKey("compute.flavors")
        hooks._detect_compute_flavors(snap)
        snap.config.set.assert_not_called()

    def test_detect_compute_flavors_with_sev_file_value_n(self, mocker, snap):
        mock_os_path_exists = mocker.patch("os.path.exists")
        mock_os_path_exists.return_value = True
        mocker.patch("builtins.open", mock.mock_open(read_data="N"))
        mock_libvirt = mocker.Mock()
        mock_get_libvirt = mocker.patch.object(hooks, "_get_libvirt")
        mock_get_libvirt.return_value = mock_libvirt

        mock_get_libvirt.assert_not_called()

    def test_detect_compute_flavors_with_sev_file_not_exists(self, mocker, snap):
        mock_os_path_exists = mocker.patch("os.path.exists")
        mock_os_path_exists.return_value = False
        mock_builtins_open = mocker.patch("builtins.open", mock.mock_open(read_data="N"))
        mock_builtins_open.assert_not_called()

    def _get_mock_nic(
        self,
        name,
        configured=False,
        up=False,
        connected=True,
        sriov_available=False,
        sriov_totalvfs=0,
        sriov_numvfs=0,
        hw_offload_available=False,
        pci_address="",
        product_id="8086",
        vendor_id="1563",
        pf_pci_address="",
        pci_physnet="",
        pci_whitelisted=True,
    ):
        if not pci_address:
            pci_address = "0000:%s:%s.0" % (
                hex(random.randint(0, 0xFF)).strip("0x"),
                hex(random.randint(0, 0xFF)).strip("0x"),
            )
        return pci_devices.InterfaceOutput(
            name=name,
            configured=configured,
            up=up,
            connected=connected,
            sriov_available=sriov_available,
            sriov_totalvfs=sriov_totalvfs,
            sriov_numvfs=sriov_numvfs,
            hw_offload_available=hw_offload_available,
            pci_address=pci_address,
            product_id=product_id,
            vendor_id=vendor_id,
            pf_pci_address=pf_pci_address,
            pci_physnet=pci_physnet,
            pci_whitelisted=pci_whitelisted,
            class_name="mock class name",
            vendor_name="mock vendor name",
            product_name="mock product name",
            subsystem_vendor_name="mock subsystem vendor name",
            subsystem_product_name="mock subsystem product name",
        )

    @mock.patch.object(pci_devices, "get_nics")
    def test_set_sriov_context(self, mock_get_nics, snap):
        sriov_pf_specs = dict(
            sriov_available=True,
            sriov_numvfs=32,
            sriov_totalvfs=32,
        )
        nic_list = [
            # Not whitelisted
            self._get_mock_nic("eno0", pci_whitelisted=False, **sriov_pf_specs),
            # SR-IOV not available
            self._get_mock_nic("eno1", pci_whitelisted=True, pci_physnet="physnet1"),
            # No physnet
            self._get_mock_nic("eno2", pci_whitelisted=True, **sriov_pf_specs),
            # HW offload available, should be skipped.
            self._get_mock_nic(
                "eno3",
                pci_whitelisted=True,
                pci_physnet="physnet1",
                hw_offload_available=True,
                **sriov_pf_specs,
            ),
            # PF whitelisted
            self._get_mock_nic(
                "eno4",
                pci_whitelisted=True,
                pci_physnet="physnet1",
                hw_offload_available=False,
                **sriov_pf_specs,
            ),
            # Contains whitelisted VF
            self._get_mock_nic(
                "eno5",
                pci_whitelisted=False,
                hw_offload_available=False,
                pci_address="0000:1b:00.0",
                **sriov_pf_specs,
            ),
            # Whitelisted VF
            self._get_mock_nic(
                "eno5v0",
                pci_whitelisted=True,
                pci_physnet="physnet2",
                hw_offload_available=False,
                pf_pci_address="0000:1b:00.0",
            ),
            # VF not whitelisted
            self._get_mock_nic(
                "eno5v1",
                pci_whitelisted=False,
                hw_offload_available=False,
                pf_pci_address="0000:1b:00.0",
            ),
            # Contains whitelisted VF, hw offload available
            self._get_mock_nic(
                "eno5",
                pci_whitelisted=False,
                hw_offload_available=True,
                pci_address="0000:1c:00.0",
                **sriov_pf_specs,
            ),
            # Whitelisted VF
            self._get_mock_nic(
                "eno5v0",
                pci_whitelisted=True,
                pci_physnet="physnet1",
                hw_offload_available=True,
                pf_pci_address="0000:1c:00.0",
            ),
        ]
        mock_get_nics.return_value = mock.Mock(root=nic_list)

        context = {}
        hooks._set_sriov_context(snap, context)
        expected_bridge_mappings = "physnet1:eno4,physnet2:eno5"

        assert sorted(expected_bridge_mappings.split(",")) == sorted(
            context["network"]["sriov_nic_physical_device_mappings"].split(",")
        )
        assert context["network"]["hw_offloading"]


@pytest.mark.parametrize(
    "cpu_shared_set,allocated_cores,should_include",
    [
        ("0-3", "4-7", True),
        ("", "", False),
    ],
)
def test_nova_conf_cpu_pinning_injection(
    mocker, snap, cpu_shared_set, allocated_cores, should_include, check_call, check_output
):
    mocker.patch(
        "openstack_hypervisor.hooks.get_cpu_pinning_from_socket",
        return_value=(cpu_shared_set, allocated_cores),
    )
    mocker.patch("openstack_hypervisor.hooks._secure_copy")
    mock_template = mock.Mock()
    mocker.patch("openstack_hypervisor.hooks._get_template", return_value=mock_template)
    mocker.patch("openstack_hypervisor.hooks.Path.write_text")
    mocker.patch("openstack_hypervisor.hooks.Path.chmod")
    for fn in [
        "_configure_ovs",
        "_configure_ovn_base",
        "_configure_ovn_external_networking",
        "_configure_kvm",
        "_configure_monitoring_services",
        "_configure_ceph",
        "_configure_masakari_services",
        "_configure_sriov_agent_service",
        "_process_dpdk_ports",
        "_set_sriov_context",
        "_set_pci_context",
    ]:
        mocker.patch(f"openstack_hypervisor.hooks.{fn}")

    class ConfigOptionsDict(dict):
        def as_dict(self):
            return dict(self)

    config_dict = {
        k: {}
        for k in [
            "compute",
            "network",
            "identity",
            "logging",
            "node",
            "rabbitmq",
            "credentials",
            "telemetry",
            "monitoring",
            "ca",
            "masakari",
            "sev",
        ]
    }
    mocker.patch.object(snap.config, "get_options", return_value=ConfigOptionsDict(config_dict))
    mocker.patch.object(snap.config, "get", return_value="dummy")

    import openstack_hypervisor.hooks as hooks

    hooks.configure(snap)

    context = mock_template.render.call_args_list[0][0][0]
    if should_include:
        assert context["compute"]["allocated_cores"] == allocated_cores
        assert context["compute"]["cpu_shared_set"] == cpu_shared_set
    else:
        assert context["compute"]["allocated_cores"] == ""
        assert context["compute"]["cpu_shared_set"] == ""


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
def test_process_dpdk_netplan_config(mock_get_netplan_config, get_pci_address):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE)
    )

    dpdk_mappings = {"ports": {}, "bonds": {}}
    dpdk_ifaces = ["eth1", "eth2"]

    netplan_changes_required = hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)

    # eth2 will be skipped since it's not connected to a bridge.
    exp_mappings = {
        "ports": {
            "eth1": {
                "pci_address": "pci-addr-eth1",
                "mtu": 1500,
                "bridge": "br0",
                "bond": None,
                "dpdk_port_name": "dpdk-eth1",
            },
        },
        "bonds": {},
    }
    assert exp_mappings == dpdk_mappings
    assert netplan_changes_required


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
def test_process_dpdk_netplan_config_bond(mock_get_netplan_config, get_pci_address):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE_WITH_BOND)
    )

    dpdk_mappings = {"ports": {}, "bonds": {}}
    dpdk_ifaces = ["eth1", "eth2"]

    netplan_changes_required = hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)

    exp_mappings = {
        "ports": {
            "eth1": {
                "pci_address": "pci-addr-eth1",
                "mtu": 1500,
                "bridge": None,
                "bond": "bond0",
                "dpdk_port_name": "dpdk-eth1",
            },
            "eth2": {
                "pci_address": "pci-addr-eth2",
                "mtu": 1500,
                "bridge": None,
                "bond": "bond0",
                "dpdk_port_name": "dpdk-eth2",
            },
        },
        "bonds": {
            "bond0": {
                "ports": ["eth1", "eth2"],
                "bridge": "br0",
                "bond_mode": "balance-tcp",
                "lacp_mode": "active",
                "lacp_time": "slow",
                "mtu": 1500,
            }
        },
    }
    assert exp_mappings == dpdk_mappings
    assert netplan_changes_required


@pytest.mark.parametrize(
    "netplan_config",
    [
        mock_netplan_configs.MOCK_NETPLAN_OVS_NO_BRIDGE,
        mock_netplan_configs.MOCK_NETPLAN_OVS_WITH_BOND_NO_BRIDGE,
    ],
    ids=["without_bond", "with_bond"],
)
@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
def test_process_dpdk_netplan_config_no_bridge(
    mock_get_netplan_config, get_pci_address, netplan_config
):
    mock_get_netplan_config.return_value = yaml.safe_load(io.StringIO(netplan_config))

    dpdk_mappings = {"ports": {}, "bonds": {}}
    dpdk_ifaces = ["eth1", "eth2"]

    netplan_changes_required = hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)

    # No bridge defined.
    exp_mappings = {"ports": {}, "bonds": {}}
    assert exp_mappings == dpdk_mappings
    assert not netplan_changes_required


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
def test_process_dpdk_netplan_already_processed(mock_get_netplan_config, get_pci_address):
    mock_get_netplan_config.return_value = {}

    dpdk_mappings = {
        "ports": {
            "eth1": {
                "pci_address": "pci-addr-eth1",
                "mtu": 1500,
                "bridge": None,
                "bond": "bond0",
                "dpdk_port_name": "dpdk-eth1",
            },
            "eth2": {
                "pci_address": "pci-addr-eth2",
                "mtu": 1500,
                "bridge": None,
                "bond": "bond0",
                "dpdk_port_name": "dpdk-eth2",
            },
        },
        "bonds": {
            "bond0": {
                "ports": ["eth1", "eth2"],
                "bridge": "br0",
                "bond_mode": "balance-tcp",
                "lacp_mode": "active",
                "lacp_time": "slow",
                "mtu": 1500,
            }
        },
    }
    dpdk_mappings_copy = dict(dpdk_mappings)
    dpdk_ifaces = ["eth1", "eth2"]

    netplan_changes_required = hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)

    assert dpdk_mappings_copy == dpdk_mappings
    assert not netplan_changes_required


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
@mock.patch("openstack_hypervisor.netplan.remove_interface_from_bridge")
@mock.patch("openstack_hypervisor.netplan.remove_bond")
@mock.patch("openstack_hypervisor.netplan.remove_ethernet")
@mock.patch("openstack_hypervisor.netplan.apply_netplan")
def test_update_netplan_dpdk_ports_with_bond(
    mock_apply_netplan,
    mock_remove_ethernet,
    mock_remove_bond,
    mock_remove_interface_from_bridge,
    mock_get_netplan_config,
    ovs_cli,
    get_pci_address,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE_WITH_BOND)
    )

    dpdk_mappings = {"ports": {}, "bonds": {}}
    dpdk_ifaces = ["eth1", "eth2"]

    hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)
    hooks._update_netplan_dpdk_ports(ovs_cli, dpdk_mappings)

    mock_remove_interface_from_bridge.assert_called_once_with("br0", "bond0")
    ovs_cli.del_port.assert_called_once_with("br0", "bond0")
    mock_remove_bond.assert_called_once_with("bond0")
    mock_remove_ethernet.assert_has_calls([mock.call(iface) for iface in ["eth1", "eth2"]])

    mock_apply_netplan.assert_called_once_with()


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
@mock.patch("openstack_hypervisor.netplan.remove_interface_from_bridge")
@mock.patch("openstack_hypervisor.netplan.remove_bond")
@mock.patch("openstack_hypervisor.netplan.remove_ethernet")
@mock.patch("openstack_hypervisor.netplan.apply_netplan")
def test_update_netplan_dpdk_ports_without_bond(
    mock_apply_netplan,
    mock_remove_ethernet,
    mock_remove_bond,
    mock_remove_interface_from_bridge,
    mock_get_netplan_config,
    ovs_cli,
    get_pci_address,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE)
    )

    dpdk_mappings = {"ports": {}, "bonds": {}}
    dpdk_ifaces = ["eth1", "eth2"]

    hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)
    hooks._update_netplan_dpdk_ports(ovs_cli, dpdk_mappings)

    mock_remove_interface_from_bridge.assert_called_once_with("br0", "eth1")
    ovs_cli.del_port.assert_called_once_with("br0", "eth1")
    mock_remove_ethernet.assert_called_once_with("eth1")

    mock_apply_netplan.assert_called_once_with()


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
@mock.patch("openstack_hypervisor.netplan.remove_interface_from_bridge")
@mock.patch("openstack_hypervisor.netplan.remove_bond")
@mock.patch("openstack_hypervisor.netplan.remove_ethernet")
@mock.patch("openstack_hypervisor.netplan.apply_netplan")
def test_update_netplan_reapply_not_required(
    mock_apply_netplan,
    mock_remove_ethernet,
    mock_remove_bond,
    mock_remove_interface_from_bridge,
    mock_get_netplan_config,
    ovs_cli,
    get_pci_address,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE_WITH_BOND)
    )

    dpdk_mappings = {"ports": {}, "bonds": {}}
    # The netplan configuration doesn't contain this interface, as such it
    # shouldn't be modified or reapplied.
    dpdk_ifaces = ["fake-iface"]

    hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)
    hooks._update_netplan_dpdk_ports(ovs_cli, dpdk_mappings)

    mock_remove_interface_from_bridge.assert_not_called()
    ovs_cli.del_port.assert_not_called()
    mock_remove_ethernet.assert_not_called()
    mock_apply_netplan.assert_not_called()


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
@mock.patch("openstack_hypervisor.pci.ensure_driver_override")
def test_create_dpdk_ports_and_bonds(
    mock_ensure_driver_override,
    mock_get_netplan_config,
    ovs_cli,
    get_pci_address,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE_WITH_BOND)
    )

    dpdk_mappings = {"ports": {}, "bonds": {}}
    dpdk_ifaces = ["eth1", "eth2"]

    hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)
    hooks._create_dpdk_ports_and_bonds(ovs_cli, dpdk_mappings, "mock-driver")

    mock_ensure_driver_override.assert_has_calls(
        [mock.call("pci-addr-eth1", "mock-driver"), mock.call("pci-addr-eth2", "mock-driver")]
    )
    ovs_cli.add_bridge.assert_called_with("br0", "netdev")
    ovs_cli.add_bond.assert_called_once()
    # _add_dpdk_bond creates the bond and then configures each DPDK port
    assert ovs_cli.add_port.call_count == 2


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
@mock.patch("openstack_hypervisor.pci.ensure_driver_override")
def test_create_dpdk_ports(
    mock_ensure_driver_override,
    mock_get_netplan_config,
    ovs_cli,
    get_pci_address,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE)
    )

    dpdk_mappings = {"ports": {}, "bonds": {}}
    dpdk_ifaces = ["eth1", "eth2"]

    hooks._process_dpdk_netplan_config(dpdk_mappings, dpdk_ifaces)
    hooks._create_dpdk_ports_and_bonds(ovs_cli, dpdk_mappings, "mock-driver")

    mock_ensure_driver_override.assert_called_once_with("pci-addr-eth1", "mock-driver")
    ovs_cli.add_bridge.assert_called_once_with("br0", "netdev")
    # _add_dpdk_port is called with ovs_cli, and then it calls ovs_cli.add_port
    ovs_cli.add_port.assert_called_once_with(
        "br0",
        "dpdk-eth1",
        port_type="dpdk",
        options={"dpdk-devargs": "pci-addr-eth1"},
        mtu=1500,
    )
    ovs_cli.add_bond.assert_not_called()


def test_add_dpdk_port(ovs_cli):
    hooks._add_dpdk_port(
        ovs_cli,
        bridge_name="bridge-name",
        dpdk_port_name="dpdk-port-name",
        pci_address="pci-address",
        mtu=9000,
    )

    ovs_cli.add_port.assert_called_once_with(
        "bridge-name",
        "dpdk-port-name",
        port_type="dpdk",
        options={"dpdk-devargs": "pci-address"},
        mtu=9000,
    )


def test_add_dpdk_bond(ovs_cli):
    hooks._add_dpdk_bond(
        ovs_cli,
        bridge_name="bridge-name",
        bond_name="bond-name",
        dpdk_ports=[
            {
                "name": "dpdk-eth0",
                "pci_address": "pci-address-eth0",
            },
            {
                "name": "dpdk-eth1",
                "pci_address": "pci-address-eth1",
            },
        ],
        mtu=9000,
        bond_mode="balance-tcp",
        lacp_mode="active",
        lacp_time="fast",
    )

    ovs_cli.add_bond.assert_called_once_with(
        "bridge-name",
        "bond-name",
        ["dpdk-eth0", "dpdk-eth1"],
        bond_mode="balance-tcp",
        lacp_mode="active",
        lacp_time="fast",
    )
    assert ovs_cli.add_port.call_count == 2


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
@mock.patch.object(hooks, "_update_netplan_dpdk_ports")
@mock.patch.object(hooks, "_create_dpdk_ports_and_bonds")
def test_process_dpdk_ports(
    mock_create_dpdk_ports,
    mock_update_netplan,
    mock_get_netplan_config,
    get_pci_address,
    ovs_cli,
    snap,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE)
    )

    context = {
        "network": {
            "ovs_dpdk_enabled": True,
            "ovs_dpdk_ports": "eth1,eth2",
        }
    }

    hooks._process_dpdk_ports(snap, ovs_cli, context)

    # eth2 will be skipped since it's not connected to a bridge.
    exp_mappings = {
        "ports": {
            "eth1": {
                "pci_address": "pci-addr-eth1",
                "mtu": 1500,
                "bridge": "br0",
                "bond": None,
                "dpdk_port_name": "dpdk-eth1",
            },
        },
        "bonds": {},
    }
    snap.config.set.assert_called_once_with(
        {"internal.dpdk-port-mappings": json.dumps(exp_mappings)}
    )

    mock_update_netplan.assert_called_once_with(ovs_cli, exp_mappings)
    mock_create_dpdk_ports.assert_called_once_with(ovs_cli, exp_mappings, "vfio-pci")


@mock.patch("openstack_hypervisor.netplan.get_netplan_config")
@mock.patch.object(hooks, "_update_netplan_dpdk_ports")
@mock.patch.object(hooks, "_create_dpdk_ports_and_bonds")
def test_process_dpdk_ports_skipped(
    mock_create_dpdk_ports,
    mock_update_netplan,
    mock_get_netplan_config,
    get_pci_address,
    ovs_cli,
    snap,
):
    mock_get_netplan_config.return_value = yaml.safe_load(
        io.StringIO(mock_netplan_configs.MOCK_NETPLAN_OVS_BRIDGE)
    )

    context = {
        "network": {
            "ovs_dpdk_enabled": False,
            "ovs_dpdk_ports": "eth1,eth2",
        }
    }
    hooks._process_dpdk_ports(snap, ovs_cli, context)

    context = {
        "network": {
            "ovs_dpdk_enabled": True,
            "ovs_dpdk_ports": "",
        }
    }
    hooks._process_dpdk_ports(snap, ovs_cli, context)
    mock_update_netplan.assert_not_called()
    mock_create_dpdk_ports.assert_not_called()
    snap.config.set.assert_not_called()
