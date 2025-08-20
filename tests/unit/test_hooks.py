# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import random
import textwrap
from unittest import mock

import pytest
from snaphelpers._conf import UnknownConfigKey

from openstack_hypervisor import hooks
from openstack_hypervisor.cli import interfaces


class TestHooks:
    """Contains tests for openstack_hypervisor.hooks."""

    def test_install_hook(self, snap):
        """Tests the install hook."""
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
        proc_net_route = textwrap.dedent(
            """\
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0003	0	0	0	00000000	0	0	0
        ens10f3	000A010A	00000000	0001	0	0	0	00FEFFFF	0	0	0
        ens10f2	000A010A	00000000	0001	0	0	0	00FEFFFF	0	0	0
        ens10f0	000A010A	00000000	0001	0	0	0	00FEFFFF	0	0	0
        ens4f0	0018010A	00000000	0001	0	0	0	00FCFFFF	0	0	0
        ens10f1	0080F50A	00000000	0001	0	0	0	00F8FFFF	0	0	0"""
        )
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() == "ens10f0"

    def test__get_default_gw_iface_fallback_no_0_dest(self):
        """Test route has 000 mask but no 000 dest, then returns None."""
        proc_net_route = textwrap.dedent(
            """
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000001	020A010A	0003	0	0	0	00000000	0	0	0
        """
        )
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() is None

    def test__get_default_gw_iface_fallback_no_0_mask(self):
        """Test route has a 000 dest but no 000 mask, then returns None."""
        proc_net_route = textwrap.dedent(
            """
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0003	0	0	0	0000000F	0	0	0
        """
        )
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() is None

    def test__get_default_gw_iface_fallback_not_up(self):
        """Tests route is a gateway but not up, then returns None."""
        proc_net_route = textwrap.dedent(
            """
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0002	0	0	0	00000000	0	0	0
        """
        )
        with mock.patch("builtins.open", mock.mock_open(read_data=proc_net_route)):
            assert hooks._get_default_gw_iface_fallback() is None

    def test__get_default_gw_iface_fallback_up_but_not_gateway(self):
        """Tests route is up but not a gateway, then returns None."""
        proc_net_route = textwrap.dedent(
            """
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        ens10f0	00000000	020A010A	0001	0	0	0	00000000	0	0	0
        """
        )
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
        mocker.patch.object(hooks, "_get_template", return_value=mock_template)
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

    def test_list_bridge_ifaces(self, check_output):
        check_output.return_value = b"int1\nint2\n"
        assert hooks._list_bridge_ifaces("br1") == ["int1", "int2"]
        check_output.assert_called_once_with(["ovs-vsctl", "--retry", "list-ifaces", "br1"])

    def test_add_interface_to_bridge(self, check_call, check_output):
        check_output.return_value = b"int1\nint2\n"
        hooks._add_interface_to_bridge("br1", "int3")
        check_call.assert_called_once_with(
            [
                "ovs-vsctl",
                "--retry",
                "add-port",
                "br1",
                "int3",
                "--",
                "set",
                "Port",
                "int3",
                "external-ids:microstack-function=ext-port",
            ]
        )

    def test_add_interface_to_bridge_noop(self, check_call, check_output):
        check_output.return_value = b"int1\nint2\n"
        hooks._add_interface_to_bridge("br1", "int2")
        assert not check_call.called

    def test_del_interface_from_bridge(self, check_call, check_output):
        check_output.return_value = b"int1\nint2\n"
        hooks._del_interface_from_bridge("br1", "int2")
        check_call.assert_called_once_with(["ovs-vsctl", "--retry", "del-port", "br1", "int2"])

    def test_del_interface_from_bridge_noop(self, check_call, check_output):
        check_output.return_value = b"int1\nint2\n"
        hooks._del_interface_from_bridge("br1", "int3")
        assert not check_call.called

    def test_get_external_ports_on_bridge(self, check_output, mocker):
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

        check_output.return_value = str.encode(json.dumps(port_data))
        mock_list_ifaces = mocker.patch.object(hooks, "_list_bridge_ifaces")
        mock_list_ifaces.return_value = ["enp6s0"]
        assert hooks._get_external_ports_on_bridge("br-ex") == ["enp6s0"]
        mock_list_ifaces.return_value = []
        assert hooks._get_external_ports_on_bridge("br-ex") == []

    def test_ensure_single_nic_on_bridge(self, mocker):
        mock_get_external_ports_on_bridge = mocker.patch.object(
            hooks, "_get_external_ports_on_bridge"
        )
        mock_add_interface_to_bridge = mocker.patch.object(hooks, "_add_interface_to_bridge")
        mock_del_interface_from_bridge = mocker.patch.object(hooks, "_del_interface_from_bridge")
        mock_get_external_ports_on_bridge.return_value = ["eth0", "eth1"]
        hooks._ensure_single_nic_on_bridge("br-ex", "eth1")
        assert not mock_add_interface_to_bridge.called
        mock_del_interface_from_bridge.assert_called_once_with("br-ex", "eth0")

        mock_get_external_ports_on_bridge.reset_mock()
        mock_add_interface_to_bridge.reset_mock()
        mock_del_interface_from_bridge.reset_mock()
        mock_get_external_ports_on_bridge.return_value = []
        hooks._ensure_single_nic_on_bridge("br-ex", "eth1")
        mock_add_interface_to_bridge.assert_called_once_with("br-ex", "eth1")
        assert not mock_del_interface_from_bridge.called

    def test_del_external_nics_from_bridge(self, mocker):
        mock_get_external_ports_on_bridge = mocker.patch.object(
            hooks, "_get_external_ports_on_bridge"
        )
        mock_del_interface_from_bridge = mocker.patch.object(hooks, "_del_interface_from_bridge")
        mock_get_external_ports_on_bridge.return_value = ["eth0", "eth1"]
        hooks._del_external_nics_from_bridge("br-ex")
        expect = [mock.call("br-ex", "eth0"), mock.call("br-ex", "eth1")]
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
        return interfaces.InterfaceOutput(
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

    @mock.patch.object(interfaces, "get_nics")
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

    @mock.patch("subprocess.check_output")
    def test_ovs_vsctl_list_table(self, mock_check_output):
        mock_data = """
{"data":[[["map",[["dpdk-init","try"],["dpdk-socket-mem","4096"]]]]],"headings":["other_config"]}
"""
        mock_check_output.return_value = mock_data.encode("utf-8")

        out = hooks._ovs_vsctl_list_table("mock-table", "mock-record", ["mock-column"])

        mock_check_output.assert_called_once_with(
            [
                "ovs-vsctl",
                "--retry",
                "--format",
                "json",
                "--if-exists",
                "--columns=mock-column",
                "list",
                "mock-table",
                "mock-record",
            ]
        )

        exp_out = {
            "other_config": {
                "dpdk-init": "try",
                "dpdk-socket-mem": "4096",
            }
        }
        assert exp_out == out

    @mock.patch("subprocess.check_call")
    def test_ovs_vsctl_set(self, mock_check_call):
        hooks._ovs_vsctl_set(
            "mock-table", "mock-record", "mock-column", {"key1": "val1", "key2": "val2"}
        )

        mock_check_call.assert_called_once_with(
            [
                "ovs-vsctl",
                "--retry",
                "set",
                "mock-table",
                "mock-record",
                "mock-column:key1=val1",
                "mock-column:key2=val2",
            ]
        )

    @mock.patch.object(hooks, "_ovs_vsctl_list_table")
    @mock.patch.object(hooks, "_ovs_vsctl_set")
    def test_ovs_vsctl_set_check(self, mock_vsctl_set, mock_list_table):
        mock_current_settings = {
            "dpdk-init": "try",
            "dpdk-socket-mem": "4096",
        }
        mock_updates = {
            "hw-offload": True,
        }
        mock_applied_settings = dict(mock_current_settings)
        mock_applied_settings.update(mock_updates)

        mock_list_table.side_effect = [
            {"other_config": mock_current_settings},
            {"other_config": mock_applied_settings},
        ]

        config_changed = hooks._ovs_vsctl_set_check(
            "mock-table", "mock-record", "other_config", mock_updates
        )
        assert config_changed

        config_changed = hooks._ovs_vsctl_set_check(
            "mock-table", "mock-record", "other_config", mock_updates
        )
        assert not config_changed

        mock_vsctl_set.assert_called_once_with(
            "mock-table", "mock-record", "other_config", mock_updates
        )


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
    mock_template = mock.Mock()
    mocker.patch("openstack_hypervisor.hooks._get_template", return_value=mock_template)
    mocker.patch("openstack_hypervisor.hooks.Path.write_text")
    mocker.patch("openstack_hypervisor.hooks.Path.chmod")
    for fn in [
        "_configure_ovn_base",
        "_configure_ovn_external_networking",
        "_configure_kvm",
        "_configure_monitoring_services",
        "_configure_ceph",
        "_configure_masakari_services",
        "_configure_sriov_agent_service",
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
