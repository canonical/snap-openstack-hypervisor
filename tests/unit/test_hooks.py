# SPDX-FileCopyrightText: 2022 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import io
import json
import random
import textwrap
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

import mock_netplan_configs
import pytest
import yaml
from snaphelpers._conf import UnknownConfigKey

from openstack_hypervisor import hooks
from openstack_hypervisor.cli import pci_devices
from openstack_hypervisor.hooks import OwnedPath


def service_mock(*, enabled: bool, active: bool):
    """Return a service mock with an explicit snapd state."""
    service = mock.Mock()
    service.enabled = enabled
    service.active = active
    return service


class TestOwnedPath:
    """Tests for the OwnedPath class."""

    def test_owned_path_stores_owner_and_group(self):
        """Test that OwnedPath stores owner and group attributes."""
        path = OwnedPath("some/path", owner="testuser", group="testgroup")
        assert path._owner == "testuser"
        assert path._group == "testgroup"
        assert str(path) == "some/path"

    def test_owned_path_with_only_owner(self):
        """Test OwnedPath with only owner specified."""
        path = OwnedPath("some/path", owner="testuser")
        assert path._owner == "testuser"
        assert path._group is None

    def test_owned_path_with_only_group(self):
        """Test OwnedPath with only group specified."""
        path = OwnedPath("some/path", group="testgroup")
        assert path._owner is None
        assert path._group == "testgroup"

    def test_owned_path_with_no_ownership(self):
        """Test OwnedPath without owner or group specified."""
        path = OwnedPath("some/path")
        assert path._owner is None
        assert path._group is None

    def test_owned_path_is_path_subclass(self):
        """Test that OwnedPath is a subclass of Path."""
        path = OwnedPath("some/path", owner="user", group="group")
        assert isinstance(path, Path)


class TestHooks:
    """Contains tests for openstack_hypervisor.hooks."""

    @pytest.mark.parametrize(
        ("machine", "expected"),
        [
            ("x86_64", "/snap/microovn/current/lib/x86_64-linux-gnu/dpdk/pmds-26.0"),
            ("aarch64", "/snap/microovn/current/lib/aarch64-linux-gnu/dpdk/pmds-26.0"),
        ],
    )
    def test_get_dpdk_pmd_dir_uses_microovn_runtime(self, mocker, machine, expected):
        mocker.patch.object(hooks.platform, "machine", return_value=machine)
        glob = mocker.patch.object(hooks.glob, "glob", return_value=[expected])

        assert hooks._get_dpdk_pmd_dir() == expected
        glob.assert_called_once_with(f"/snap/microovn/current/lib/{machine}-linux-gnu/dpdk/pmds-*")

    def test_set_nova_metadata_proxy_context_parses_url(self):
        """Nova metadata ingress URL is expanded for HAProxy rendering."""
        context = {"network": {"nova_metadata_proxy_url": "http://internal/nova-metadata"}}

        hooks._set_nova_metadata_proxy_context(context)

        assert context["network"]["nova_metadata_proxy_scheme"] == "http"
        assert context["network"]["nova_metadata_proxy_host"] == "internal"
        assert context["network"]["nova_metadata_proxy_server_host"] == "internal"
        assert context["network"]["nova_metadata_proxy_port"] == 80
        assert context["network"]["nova_metadata_proxy_host_header"] == "internal"
        assert context["network"]["nova_metadata_proxy_path"] == "/nova-metadata"
        assert context["network"]["nova_metadata_proxy_ssl"] is False

    def test_set_nova_metadata_proxy_context_defaults_https_port(self):
        """HTTPS metadata ingress uses the default HTTPS upstream port."""
        context = {"network": {"nova_metadata_proxy_url": "https://internal/nova-metadata/"}}

        hooks._set_nova_metadata_proxy_context(context)

        assert context["network"]["nova_metadata_proxy_port"] == 443
        assert context["network"]["nova_metadata_proxy_path"] == "/nova-metadata"
        assert context["network"]["nova_metadata_proxy_ssl"] is True

    def test_set_nova_metadata_proxy_context_keeps_non_default_host_port(self):
        """Host header preserves an explicit non-default upstream port."""
        context = {"network": {"nova_metadata_proxy_url": "https://internal:8443/nova-metadata/"}}

        hooks._set_nova_metadata_proxy_context(context)

        assert context["network"]["nova_metadata_proxy_host_header"] == "internal:8443"
        assert context["network"]["nova_metadata_proxy_port"] == 8443

    def test_set_nova_metadata_proxy_context_rejects_userinfo(self):
        """Nova metadata ingress URLs must not contain userinfo."""
        context = {
            "network": {"nova_metadata_proxy_url": "https://user:pass@internal/nova-metadata/"}
        }

        with pytest.raises(ValueError, match="must not include userinfo"):
            hooks._set_nova_metadata_proxy_context(context)

    def test_install_hook(self, mocker, snap, shutil_chown):
        """Tests the install hook."""
        mocker.patch.object(hooks, "_secure_copy")
        hooks.install(snap)

    def test_mkdirs_calls_chown_for_owned_paths(self, mocker, snap):
        """Test that _mkdirs calls shutil.chown for OwnedPath directories."""
        mock_chown = mocker.patch("shutil.chown")
        mocker.patch("os.makedirs")

        # Patch DATA_DIRS and COMMON_DIRS to test OwnedPath behavior
        test_owned_path = OwnedPath("test/owned", owner="testuser", group="testgroup")
        test_regular_path = Path("test/regular")
        mocker.patch.object(hooks, "DATA_DIRS", [test_owned_path, test_regular_path])
        mocker.patch.object(hooks, "COMMON_DIRS", [])

        hooks._mkdirs(snap)

        # chown should be called only for OwnedPath with owner/group
        mock_chown.assert_called_once()
        call_args = mock_chown.call_args
        assert call_args.kwargs["user"] == "testuser"
        assert call_args.kwargs["group"] == "testgroup"

    def test_mkdirs_skips_chown_for_regular_paths(self, mocker, snap):
        """Test that _mkdirs does not call shutil.chown for regular Path objects."""
        mock_chown = mocker.patch("shutil.chown")
        mocker.patch("os.makedirs")

        test_regular_path = Path("test/regular")
        mocker.patch.object(hooks, "DATA_DIRS", [test_regular_path])
        mocker.patch.object(hooks, "COMMON_DIRS", [])

        hooks._mkdirs(snap)

        mock_chown.assert_not_called()

    def test_mkdirs_skips_chown_for_owned_path_without_ownership(self, mocker, snap):
        """Test that _mkdirs skips chown for OwnedPath without owner/group."""
        mock_chown = mocker.patch("shutil.chown")
        mocker.patch("os.makedirs")

        test_owned_path = OwnedPath("test/owned")  # No owner or group
        mocker.patch.object(hooks, "DATA_DIRS", [test_owned_path])
        mocker.patch.object(hooks, "COMMON_DIRS", [])

        hooks._mkdirs(snap)

        mock_chown.assert_not_called()

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

    def test_configure_hook(self, mocker, snap, check_call, shutil_chown):
        """Tests the configure hook."""
        mock_template = mocker.Mock()
        mocker.patch.object(hooks, "_secure_copy")
        mocker.patch.object(hooks, "_configure_webdav_apache")
        mocker.patch.object(hooks, "_process_dpdk_ports")
        mocker.patch.object(hooks, "_is_multipathd_available", return_value=False)
        mocker.patch.object(hooks, "_ensure_services_started")
        mocker.patch.object(hooks, "_ensure_services_stopped")
        mocker.patch.object(hooks, "_restart_services")
        mocker.patch.object(hooks, "_get_template", return_value=mock_template)
        mocker.patch.object(hooks, "OVSCli", spec=hooks.OVSCli)
        mock_write_text = mocker.patch.object(hooks.Path, "write_text")
        mock_chmod = mocker.patch.object(hooks.Path, "chmod")
        mocker.patch(
            "openstack_hypervisor.hooks.get_cpu_pinning_from_socket",
            return_value=("0-3", "4-7"),
        )
        hooks.configure(snap)
        mock_template.render.assert_called()
        mock_write_text.assert_called()
        mock_chmod.assert_called()

    def test_configure_hook_exception(self, mocker, snap, os_makedirs, check_call, shutil_chown):
        """Tests the configure hook raising an exception while writing file."""
        mock_template = mocker.Mock()
        mocker.patch.object(hooks, "_is_multipathd_available", return_value=False)
        mocker.patch.object(hooks, "_ensure_services_stopped")
        mocker.patch.object(hooks, "_get_template", return_value=mock_template)
        mocker.patch.object(hooks.Path, "write_text")
        mocker.patch.object(hooks.Path, "chmod")
        mocker.patch(
            "openstack_hypervisor.hooks.get_cpu_pinning_from_socket",
            return_value=("0-3", "4-7"),
        )
        with pytest.raises(FileNotFoundError):
            hooks.configure(snap)

    def test_services(self):
        """Test getting a list of managed services."""
        assert hooks.services() == [
            "ceilometer-compute-agent",
            "file-transfer",
            "libvirtd",
            "masakari-instancemonitor",
            "neutron-ovn-agent",
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
            "file-transfer",
            "masakari-instancemonitor",
            "neutron-ovn-agent",
            "nova-api-metadata",
            "nova-compute",
        ]
        config["identity"] = {"username": "user", "password": "pass"}
        assert hooks._services_not_ready(config) == [
            "ceilometer-compute-agent",
            "file-transfer",
            "masakari-instancemonitor",
            "neutron-ovn-agent",
            "nova-api-metadata",
            "nova-compute",
        ]
        config["rabbitmq"] = {"url": "rabbit://localhost:5672"}
        config["node"] = {"fqdn": "myhost.maas"}
        assert hooks._services_not_ready(config) == [
            "file-transfer",
            "neutron-ovn-agent",
            "nova-api-metadata",
        ]
        config["network"] = {
            "external-bridge-address": "10.0.0.10",
            "ovn_cert": "cert",
            "ovn_key": "key",
            "ovn_cacert": "cacert",
        }
        assert hooks._services_not_ready(config) == [
            "file-transfer",
            "neutron-ovn-agent",
            "nova-api-metadata",
        ]
        config["network"]["nova_metadata_proxy_url"] = "http://internal/nova-metadata"
        assert hooks._services_not_ready(config) == [
            "file-transfer",
            "neutron-ovn-agent",
            "nova-api-metadata",
        ]
        config["credentials"] = {"ovn_metadata_proxy_shared_secret": "secret"}
        assert hooks._services_not_ready(config) == [
            "file-transfer",
            "neutron-ovn-agent",
        ]
        config["network"].update(
            {
                "ovn_nb_connection": "ssl:10.0.0.10:6641",
                "ovn_sb_connection": "ssl:10.0.0.10:6642",
            }
        )
        assert hooks._services_not_ready(config) == ["file-transfer"]
        config["compute"] = {
            "cacert": "cacert",
            "cert": "cert",
            "key": "key",
        }
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
    "cpu_shared_set,allocated_cores",
    [
        ("0-3", "4-7"),
        ("", ""),
    ],
)
def test_nova_conf_cpu_pinning_injection(
    mocker,
    snap,
    cpu_shared_set,
    allocated_cores,
    check_call,
    check_output,
    shutil_chown,
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
    mocker.patch("openstack_hypervisor.hooks._is_multipathd_available")
    for fn in [
        "_configure_ovs",
        "_configure_ovn_base_external_ovs",
        "_configure_webdav_apache",
        "_configure_kvm",
        "_configure_monitoring_services",
        "_configure_ceph",
        "_configure_masakari_services",
        "_configure_sriov_agent_service",
        "_ensure_services_stopped",
        "_restart_services",
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
    config_dict["compute"]["cpu-pinning-profile"] = ""
    mocker.patch.object(snap.config, "get_options", return_value=ConfigOptionsDict(config_dict))

    import openstack_hypervisor.hooks as hooks

    hooks.configure(snap)

    context = mock_template.render.call_args_list[0][0][0]
    assert context["compute"]["allocated_cores"] == allocated_cores
    assert context["compute"]["cpu_shared_set"] == cpu_shared_set


def test_get_configure_context_cpu_pinning_profile_percent_path(mocker, snap):
    profile = {"dedicated_percentage": 40, "requested_cores_percentage": 50}
    epa_allocated_cores = "2-9"
    split_shared_set = "2-4"
    split_allocated_cores = "5-9"

    mock_get_percent = mocker.patch(
        "openstack_hypervisor.hooks.get_cpu_pinning_percent_from_socket",
        return_value=epa_allocated_cores,
    )
    mock_split = mocker.patch(
        "openstack_hypervisor.hooks._split_dedicated_cores_by_profile",
        return_value=(split_shared_set, split_allocated_cores),
    )
    mock_legacy_get = mocker.patch("openstack_hypervisor.hooks.get_cpu_pinning_from_socket")

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
            "internal",
        ]
    }
    config_dict["compute"]["cpu-pinning-profile"] = profile
    mocker.patch.object(snap.config, "get_options", return_value=ConfigOptionsDict(config_dict))
    mocker.patch("openstack_hypervisor.hooks._is_multipathd_available", return_value=False)
    mocker.patch(
        "openstack_hypervisor.hooks.ovs_switch_socket",
        return_value="unix:/var/snap/openstack-hypervisor/common/run/openvswitch/db.sock",
    )

    import openstack_hypervisor.hooks as hooks

    context = hooks._get_configure_context(snap)

    mock_get_percent.assert_called_once_with(
        service_name=snap.name,
        socket_path=hooks.socket_path(snap),
        requested_cores_percentage=profile["requested_cores_percentage"],
    )
    mock_split.assert_called_once_with(epa_allocated_cores, profile["dedicated_percentage"])
    mock_legacy_get.assert_not_called()
    assert context["compute"]["allocated_cores"] == split_allocated_cores
    assert context["compute"]["cpu_shared_set"] == split_shared_set


def _minimal_config_options():
    class ConfigOptionsDict(dict):
        def as_dict(self):
            return dict(self)

    return ConfigOptionsDict(
        {
            section: {}
            for section in [
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
                "internal",
            ]
        }
    )


def _prepare_minimal_configure_context(mocker, snap):
    mocker.patch.object(snap.config, "get_options", return_value=_minimal_config_options())
    mocker.patch.object(hooks, "_is_multipathd_available", return_value=False)
    mocker.patch.object(hooks, "get_cpu_pinning_from_socket", return_value=("", ""))
    mocker.patch.object(hooks, "_set_sriov_context")
    mocker.patch.object(hooks, "_set_pci_context")


def _prepare_configure_reconciliation(mocker, snap):
    config_options = _minimal_config_options()
    config_options["network"] = {
        "ovn_key": "key",
        "ovn_cert": "cert",
        "ovn_cacert": "cacert",
    }
    config_options["credentials"] = {"ovn_metadata_proxy_shared_secret": "secret"}
    config_options["node"] = {"fqdn": "compute-0.internal"}
    mocker.patch.object(snap.config, "get_options", return_value=config_options)

    mocker.patch.object(hooks, "setup_logging")
    mocker.patch.object(hooks, "_mkdirs")
    mocker.patch.object(hooks, "_update_default_config")
    mocker.patch.object(hooks, "_setup_secrets")
    mocker.patch.object(hooks, "_detect_compute_flavors")
    mocker.patch.object(hooks, "_is_multipathd_available", return_value=False)
    mocker.patch.object(hooks, "get_cpu_pinning_from_socket", return_value=("", ""))
    mocker.patch.object(hooks, "_set_sriov_context")
    mocker.patch.object(hooks, "_set_pci_context")
    mocker.patch.object(hooks, "OVSCli")
    mocker.patch.object(hooks, "_microovn_ovs_ready", return_value=False)
    mocker.patch.object(hooks, "ovs_switchd_ctl_socket", return_value=None)

    agent_config = Path("etc/neutron/neutron_ovn_agent.ini")
    mocker.patch.object(
        hooks,
        "TEMPLATES",
        {
            agent_config: {
                "template": "neutron_ovn_agent.ini.j2",
                "services": ["neutron-ovn-agent"],
            }
        },
    )
    mocker.patch.object(hooks, "TLS_TEMPLATES", {})
    mocker.patch.object(
        hooks,
        "_get_template",
        return_value=hooks.Template(
            "{{ network.ovn_nb_connection | default('') }}|"
            "{{ network.ovn_sb_connection | default('') }}\n"
        ),
    )

    for name in [
        "_configure_tls",
        "_configure_webdav_apache",
        "_configure_kvm",
        "_configure_monitoring_services",
        "_configure_ceph",
        "_configure_masakari_services",
        "_configure_sriov_agent_service",
    ]:
        mocker.patch.object(hooks, name)

    ensure_stopped = mocker.patch.object(hooks, "_ensure_services_stopped")
    restart_services = mocker.patch.object(hooks, "_restart_services")

    rendered_config = snap.paths.common / agent_config
    rendered_config.parent.mkdir(parents=True, exist_ok=True)
    rendered_config.write_text("previous configuration\n", encoding="utf-8")
    return ensure_stopped, restart_services


def test_configure_restarts_eligible_ovn_agent_with_valid_environment(mocker, snap):
    ovn_env = snap.paths.data / "microovn" / "ovn-env" / "env" / "ovn.env"
    ovn_env.parent.mkdir(parents=True)
    ovn_env.write_text(
        'OVN_NB_CONNECT="ssl:192.0.2.10:6641"\n' 'OVN_SB_CONNECT="ssl:192.0.2.10:6642"\n',
        encoding="utf-8",
    )
    ensure_stopped, restart_services = _prepare_configure_reconciliation(mocker, snap)
    snap.services.list.return_value = {
        "neutron-ovn-agent": service_mock(enabled=False, active=False)
    }
    snapctl = mocker.patch.object(hooks, "SnapCtl").return_value

    hooks.configure(snap)

    excluded_services = ensure_stopped.call_args.args[1]
    assert "neutron-ovn-agent" not in excluded_services
    restarted_services = restart_services.call_args.args[1]
    assert set(restarted_services) == {"neutron-ovn-agent"}
    snapctl.start.assert_not_called()


def test_configure_starts_eligible_inactive_ovn_agent_when_config_is_unchanged(mocker, snap):
    nb_connection = "ssl:192.0.2.10:6641"
    sb_connection = "ssl:192.0.2.10:6642"
    ovn_env = snap.paths.data / "microovn" / "ovn-env" / "env" / "ovn.env"
    ovn_env.parent.mkdir(parents=True)
    ovn_env.write_text(
        f'OVN_NB_CONNECT="{nb_connection}"\n' f'OVN_SB_CONNECT="{sb_connection}"\n',
        encoding="utf-8",
    )
    ensure_stopped, restart_services = _prepare_configure_reconciliation(mocker, snap)
    rendered_config = snap.paths.common / "etc/neutron/neutron_ovn_agent.ini"
    rendered_config.write_text(f"{nb_connection}|{sb_connection}", encoding="utf-8")
    snap.services.list.return_value = {
        "neutron-ovn-agent": service_mock(enabled=False, active=False)
    }
    snapctl = mocker.patch.object(hooks, "SnapCtl").return_value

    hooks.configure(snap)

    excluded_services = ensure_stopped.call_args.args[1]
    assert "neutron-ovn-agent" not in excluded_services
    restart_services.assert_not_called()
    snapctl.start.assert_called_once_with("neutron-ovn-agent", enable=True)


@pytest.mark.parametrize(
    "ovn_env_contents",
    [
        None,
        'OVN_NB_CONNECT="ssl:192.0.2.10:6641"\n' 'OVN_SB_CONNECT="malformed"\n',
    ],
    ids=("missing", "invalid"),
)
def test_configure_stops_ovn_agent_without_usable_environment(mocker, snap, ovn_env_contents):
    if ovn_env_contents is not None:
        ovn_env = snap.paths.data / "microovn" / "ovn-env" / "env" / "ovn.env"
        ovn_env.parent.mkdir(parents=True)
        ovn_env.write_text(ovn_env_contents, encoding="utf-8")
    ensure_stopped, restart_services = _prepare_configure_reconciliation(mocker, snap)
    snap.services.list.return_value = {
        "neutron-ovn-agent": service_mock(enabled=False, active=False)
    }
    snapctl = mocker.patch.object(hooks, "SnapCtl").return_value

    hooks.configure(snap)

    excluded_services = ensure_stopped.call_args.args[1]
    assert "neutron-ovn-agent" in excluded_services
    restart_services.assert_not_called()
    snapctl.start.assert_not_called()


def test_get_configure_context_reads_ovn_connections_without_logging_them(mocker, snap, caplog):
    nb_connection = "ssl:192.0.2.10:6641"
    sb_connection = "ssl:192.0.2.10:6642"
    ovn_env = snap.paths.data / "microovn" / "ovn-env" / "env" / "ovn.env"
    ovn_env.parent.mkdir(parents=True)
    ovn_env.write_text(
        f'OVN_NB_CONNECT="{nb_connection}"\n' f'OVN_SB_CONNECT="{sb_connection}"\n',
        encoding="utf-8",
    )
    _prepare_minimal_configure_context(mocker, snap)

    context = hooks._get_configure_context(snap)
    hooks._get_exclude_services(context)

    assert context["network"]["ovn_nb_connection"] == nb_connection
    assert context["network"]["ovn_sb_connection"] == sb_connection
    assert nb_connection not in caplog.text
    assert sb_connection not in caplog.text


@pytest.mark.parametrize(
    "ovn_env_contents",
    [
        None,
        'OVN_NB_CONNECT="ssl:192.0.2.10:6641"\nOVN_SB_CONNECT="malformed-secret"\n',
    ],
)
def test_get_configure_context_excludes_ovn_agent_without_valid_environment(
    mocker, snap, caplog, ovn_env_contents
):
    if ovn_env_contents is not None:
        ovn_env = snap.paths.data / "microovn" / "ovn-env" / "env" / "ovn.env"
        ovn_env.parent.mkdir(parents=True)
        ovn_env.write_text(ovn_env_contents, encoding="utf-8")
    _prepare_minimal_configure_context(mocker, snap)

    context = hooks._get_configure_context(snap)

    assert "ovn_nb_connection" not in context["network"]
    assert "ovn_sb_connection" not in context["network"]
    assert "neutron-ovn-agent" in hooks._services_not_ready(context)
    assert "ssl:192.0.2.10:6641" not in caplog.text
    assert "malformed-secret" not in caplog.text


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
        [
            mock.call("pci-addr-eth1", "mock-driver"),
            mock.call("pci-addr-eth2", "mock-driver"),
        ]
    )
    ovs_cli.add_bridge.assert_called_with("br0", "netdev")
    ovs_cli.add_bond.assert_called_once()
    # _add_dpdk_bond creates the bond and then configures each DPDK port
    assert ovs_cli.vsctl.call_count == 2


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
    assert ovs_cli.vsctl.call_count == 2


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


class TestMicroOVNOVS:
    """Tests for the required MicroOVN OVS provider."""

    def test_configure_ovn_base_external_ovs_skips_without_ip(self, mocker, snap, ovs_cli):
        """Test external OVS base config skips when no IP is set."""
        snap.config.get.side_effect = lambda key: None

        hooks._configure_ovn_base_external_ovs(snap, ovs_cli, {"network": {}})

        ovs_cli.set.assert_not_called()


class TestConfigureMonitoringServices:
    """Tests for _configure_monitoring_services function."""

    def test_monitoring_enabled_starts_libvirt_exporter(self, mocker, snap):
        ensure_started = mocker.patch.object(hooks, "_ensure_services_started")
        snap.config.get.return_value = True

        hooks._configure_monitoring_services(snap)

        ensure_started.assert_called_once_with(snap, ["libvirt-exporter"])

    def test_monitoring_disabled_stops_all(self, mocker, snap):
        """Test that all exporters are stopped when monitoring is disabled."""
        ensure_stopped = mocker.patch.object(hooks, "_ensure_services_stopped")
        snap.config.get.return_value = False  # monitoring.enable = False

        hooks._configure_monitoring_services(snap)

        ensure_stopped.assert_called_once_with(snap, hooks.MONITORING_SERVICES)


class TestServiceReconciliation:
    """Tests for state-aware batched service reconciliation."""

    @pytest.mark.parametrize(
        "enabled,active,should_start",
        [
            (False, False, True),
            (False, True, True),
            (True, False, True),
            (True, True, False),
        ],
    )
    def test_ensure_services_started(self, mocker, snap, enabled, active, should_start):
        before = {"service": service_mock(enabled=enabled, active=active)}
        snap.services.list.return_value = before
        snapctl = mocker.patch.object(hooks, "SnapCtl").return_value

        hooks._ensure_services_started(snap, ["service"])

        snap.services.list.assert_called_once_with()
        if should_start:
            snapctl.start.assert_called_once_with("service", enable=True)
        else:
            snapctl.start.assert_not_called()

    @pytest.mark.parametrize(
        "enabled,active,should_stop",
        [
            (False, False, False),
            (False, True, True),
            (True, False, True),
            (True, True, True),
        ],
    )
    def test_ensure_services_stopped(self, mocker, snap, enabled, active, should_stop):
        before = {"service": service_mock(enabled=enabled, active=active)}
        snap.services.list.return_value = before
        snapctl = mocker.patch.object(hooks, "SnapCtl").return_value

        hooks._ensure_services_stopped(snap, ["service"])

        snap.services.list.assert_called_once_with()
        if should_stop:
            snapctl.stop.assert_called_once_with("service", disable=True)
        else:
            snapctl.stop.assert_not_called()

    def test_batches_sorted_unique_non_converged_services(self, mocker, snap):
        before = {
            "already-ready": service_mock(enabled=True, active=True),
            "service-a": service_mock(enabled=False, active=False),
            "service-b": service_mock(enabled=True, active=False),
        }
        snap.services.list.return_value = before
        snapctl_class = mocker.patch.object(hooks, "SnapCtl")

        hooks._ensure_services_started(
            snap, ["service-b", "already-ready", "service-a", "service-b"]
        )

        snapctl_class.assert_called_once_with(env=snap.environ)
        snapctl_class.return_value.start.assert_called_once_with(
            "service-a", "service-b", enable=True
        )

    def test_missing_service_fails_before_command(self, mocker, snap):
        snap.services.list.return_value = {}
        snapctl_class = mocker.patch.object(hooks, "SnapCtl")

        with pytest.raises(RuntimeError, match="missing"):
            hooks._ensure_services_started(snap, ["missing"])

        snapctl_class.assert_not_called()

    def test_command_failure_propagates(self, mocker, snap):
        stopped = {"service": service_mock(enabled=False, active=False)}
        snap.services.list.return_value = stopped
        snapctl = mocker.patch.object(hooks, "SnapCtl").return_value
        snapctl.start.side_effect = RuntimeError("command failed")

        with pytest.raises(RuntimeError, match="command failed"):
            hooks._ensure_services_started(snap, ["service"])

    def test_restart_services_batches_and_verifies(self, caplog, mocker, snap):
        before = {
            "service-a": service_mock(enabled=True, active=True),
            "service-b": service_mock(enabled=True, active=True),
        }
        snap.services.list.return_value = before
        snapctl = mocker.patch.object(hooks, "SnapCtl").return_value

        hooks._restart_services(snap, ["service-b", "service-a", "service-b"])

        snap.services.list.assert_called_once_with()
        snapctl.stop.assert_called_once_with("service-a", "service-b")
        snapctl.start.assert_called_once_with("service-a", "service-b", enable=True)
        assert [
            record.getMessage()
            for record in caplog.records
            if record.getMessage().startswith("Restarting ")
        ] == ["Restarting service-a", "Restarting service-b"]

    def test_restart_services_ignores_empty_input(self, mocker, snap):
        snapctl_class = mocker.patch.object(hooks, "SnapCtl")

        hooks._restart_services(snap, [])

        snap.services.list.assert_not_called()
        snapctl_class.assert_not_called()

    def test_masakari_reconciles_enabled_services(self, mocker, snap):
        ensure_started = mocker.patch.object(hooks, "_ensure_services_started")
        snap.config.get.return_value = True

        hooks._configure_masakari_services(snap)

        ensure_started.assert_called_once_with(snap, hooks.MASAKARI_SERVICES)

    @pytest.mark.parametrize("enabled", [False, True])
    def test_sriov_reconciles_service(self, mocker, snap, enabled):
        ensure_started = mocker.patch.object(hooks, "_ensure_services_started")
        ensure_stopped = mocker.patch.object(hooks, "_ensure_services_stopped")

        hooks._configure_sriov_agent_service(snap, enabled)

        if enabled:
            ensure_started.assert_called_once_with(snap, ["neutron-sriov-nic-agent"])
            ensure_stopped.assert_not_called()
        else:
            ensure_stopped.assert_called_once_with(snap, ["neutron-sriov-nic-agent"])
            ensure_started.assert_not_called()


class TestRestartOnChange:
    """Tests for change-triggered service restarts."""

    def test_unchanged_files_do_not_list_services(self, snap):
        config = snap.paths.common / "service.conf"
        config.parent.mkdir(parents=True)
        config.write_text("unchanged")

        with hooks.RestartOnChange(snap, {Path("service.conf"): {"services": ["service"]}}):
            pass

        snap.services.list.assert_not_called()

    def test_changed_file_restarts_service(self, mocker, snap):
        config = snap.paths.common / "service.conf"
        config.parent.mkdir(parents=True)
        config.write_text("before")
        restart_services = mocker.patch.object(hooks, "_restart_services")

        with hooks.RestartOnChange(snap, {Path("service.conf"): {"services": ["service"]}}):
            config.write_text("after")

        restart_services.assert_called_once_with(snap, {"service"})


class TestConfigureTLS:
    """Tests for TLS configuration orchestration."""

    def test_skips_ovn_tls_when_deferred(self, mocker, snap):
        """OVN TLS is skipped while MicroOVN configuration is deferred."""
        mock_ovn_tls = mocker.patch.object(hooks, "_configure_ovn_tls")
        mock_libvirt_tls = mocker.patch.object(hooks, "_configure_libvirt_tls")
        mock_cabundle_tls = mocker.patch.object(hooks, "_configure_cabundle_tls")

        hooks._configure_tls(snap, configure_ovn_tls=False)

        mock_ovn_tls.assert_not_called()
        mock_libvirt_tls.assert_called_once_with(snap)
        mock_cabundle_tls.assert_called_once_with(snap)


class TestConfigureNetworking:
    """Tests for _configure_networking function."""

    def test_external_ovs_clears_restart_flag_when_ready(self, mocker, snap, ovs_cli):
        mocker.patch.object(hooks, "_configure_ovn_base_external_ovs")
        mocker.patch.object(hooks, "_configure_ovs", return_value=False)
        mocker.patch.object(hooks, "_process_dpdk_ports")
        mocker.patch.object(hooks, "_dpdk_config_is_ready", return_value=True)

        hooks._configure_networking(snap, ovs_cli, {"network": {}})

        snap.config.set.assert_any_call({"network.external-switch-restart": False})

    def test_external_ovs_keeps_restart_flag_when_context_set(self, mocker, snap, ovs_cli):
        """Test that external-switch-restart is not overridden if already set in context."""
        mocker.patch.object(hooks, "_configure_ovn_base_external_ovs")
        mocker.patch.object(hooks, "_configure_ovs", return_value=False)
        mocker.patch.object(hooks, "_process_dpdk_ports")
        mocker.patch.object(hooks, "_dpdk_config_is_ready", return_value=True)

        # Context has external_switch_restart already set to True (set by external caller)
        context = {"network": {"external_switch_restart": True}}

        hooks._configure_networking(snap, ovs_cli, context)

        # Verify config.set was NOT called with False when context had it set to True
        for call in snap.config.set.call_args_list:
            if call[0][0].get("network.external-switch-restart") is False:
                # This should not happen when context has it set
                assert False, "Should not override external_switch_restart when set in context"

    def test_microovn_restart_is_signalled_when_required(self, mocker, snap, ovs_cli):
        mocker.patch.object(hooks, "_configure_ovs", return_value=True)
        mocker.patch.object(hooks, "_process_dpdk_ports")
        mocker.patch.object(hooks, "_configure_ovn_base_external_ovs")
        mocker.patch.object(hooks, "_dpdk_config_is_ready", return_value=True)

        hooks._configure_networking(snap, ovs_cli, {"network": {}})

        snap.config.set.assert_any_call({"network.external-switch-restart": True})
        snap.services.list.assert_not_called()


class TestConfigureOVSDeferred:
    """Tests for configure-time MicroOVN readiness."""

    @pytest.mark.parametrize(
        "socket_available,networking_called",
        [
            (False, False),
            (True, True),
        ],
    )
    def test_microovn_socket_controls_network_configuration(
        self, mocker, snap, socket_available, networking_called
    ):
        microovn_socket = snap.paths.data / "microovn/chassis/switch/db.sock"
        if socket_available:
            microovn_socket.parent.mkdir(parents=True)
            microovn_socket.touch()
        snap.services.list.return_value = {}
        mocker.patch.object(hooks, "_mkdirs")
        mocker.patch.object(hooks, "_update_default_config")
        mocker.patch.object(hooks, "_setup_secrets")
        mocker.patch.object(hooks, "_detect_compute_flavors")
        mocker.patch.object(hooks, "_get_configure_context", return_value={"network": {}})
        mocker.patch.object(hooks, "_get_exclude_services", return_value=[])
        mocker.patch.object(hooks, "OVSCli", return_value=mock.Mock())
        restart_on_change = mock.Mock(restarted_services=set())
        mocker.patch.object(hooks, "RestartOnChange", return_value=nullcontext(restart_on_change))
        mocker.patch.object(hooks, "_render_templates")
        mocker.patch.object(hooks, "_ensure_services_started")
        mocker.patch.object(hooks, "_configure_webdav_apache")
        mocker.patch.object(hooks, "_configure_kvm")
        mocker.patch.object(hooks, "_configure_monitoring_services")
        mocker.patch.object(hooks, "_configure_ceph")
        mocker.patch.object(hooks, "_configure_masakari_services")
        mocker.patch.object(hooks, "_configure_sriov_agent_service")
        configure_tls = mocker.patch.object(hooks, "_configure_tls")
        configure_networking = mocker.patch.object(hooks, "_configure_networking")

        hooks.configure(snap)

        assert configure_tls.call_args.kwargs["configure_ovn_tls"] is socket_available
        assert configure_networking.called is networking_called


class TestDPDKConfigReady:
    """Tests for _dpdk_config_is_ready function."""

    def test_ready_when_dpdk_not_enabled(self, mocker, snap, ovs_cli):
        """Test returns True when DPDK is not enabled."""
        context = {"network": {"ovs_dpdk_enabled": False, "hw_offloading": False}}

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is True

    def test_not_ready_when_dpdk_not_initialized(self, mocker, snap, ovs_cli):
        """Test returns False when DPDK is enabled but not initialized."""
        ovs_cli.get_dpdk_initialized.return_value = False

        context = {"network": {"ovs_dpdk_enabled": True, "hw_offloading": False}}

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is False
        ovs_cli.get_dpdk_initialized.assert_called_once()

    def test_ready_when_dpdk_initialized(self, mocker, snap, ovs_cli):
        """Test returns True when DPDK is properly initialized."""
        mocker.patch.object(hooks, "_dpdk_supported", return_value=True)
        ovs_cli.get_dpdk_initialized.return_value = True
        ovs_cli.list_table.return_value = {"other_config": {"dpdk-init": "try"}}
        ovs_cli.list_bridges.return_value = []

        # Mock internal.dpdk_port_mappings to return empty
        mocker.patch.object(hooks, "_get_dpdk_mappings", return_value={"ports": {}, "bonds": {}})

        context = {
            "network": {"ovs_dpdk_enabled": True, "hw_offloading": False},
            "internal": {},
        }

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is True

    def test_not_ready_when_config_mismatch(self, mocker, snap, ovs_cli):
        """Test returns False when DPDK config doesn't match expected."""
        mocker.patch.object(hooks, "_dpdk_supported", return_value=True)
        ovs_cli.get_dpdk_initialized.return_value = True
        ovs_cli.list_table.return_value = {"other_config": {"dpdk-init": "false"}}

        context = {
            "network": {"ovs_dpdk_enabled": True, "hw_offloading": False},
            "internal": {},
        }

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is False

    def test_not_ready_when_hw_offload_not_enabled(self, mocker, snap, ovs_cli):
        """Test returns False when hw-offload is expected but not enabled."""
        ovs_cli.list_table.return_value = {"other_config": {"hw-offload": "false"}}

        context = {"network": {"ovs_dpdk_enabled": False, "hw_offloading": True}}

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is False

    def test_ready_when_hw_offload_enabled(self, mocker, snap, ovs_cli):
        """Test returns True when hw-offload is properly configured."""
        ovs_cli.list_table.return_value = {"other_config": {"hw-offload": "true"}}
        ovs_cli.appctl.return_value = "offload stats"

        context = {"network": {"ovs_dpdk_enabled": False, "hw_offloading": True}}

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is True

    def test_not_ready_when_dpdk_port_missing(self, mocker, snap, ovs_cli):
        """Test returns False when expected DPDK port is missing."""
        mocker.patch.object(hooks, "_dpdk_supported", return_value=True)
        ovs_cli.get_dpdk_initialized.return_value = True
        ovs_cli.list_table.return_value = {"other_config": {"dpdk-init": "try"}}
        ovs_cli.list_bridges.return_value = ["br0"]
        ovs_cli.list_bridge_interfaces.return_value = []  # No interfaces

        mocker.patch.object(
            hooks,
            "_get_dpdk_mappings",
            return_value={
                "ports": {
                    "eth0": {
                        "dpdk_port_name": "dpdk-eth0",
                        "bridge": "br0",
                    }
                },
                "bonds": {},
            },
        )

        context = {
            "network": {"ovs_dpdk_enabled": True, "hw_offloading": False},
            "internal": {},
        }

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is False

    def test_ready_when_all_dpdk_ports_exist(self, mocker, snap, ovs_cli):
        """Test returns True when all expected DPDK ports exist."""
        mocker.patch.object(hooks, "_dpdk_supported", return_value=True)
        ovs_cli.get_dpdk_initialized.return_value = True
        ovs_cli.list_table.return_value = {"other_config": {"dpdk-init": "try"}}
        ovs_cli.list_bridges.return_value = ["br0"]
        ovs_cli.list_bridge_interfaces.return_value = ["dpdk-eth0"]

        mocker.patch.object(
            hooks,
            "_get_dpdk_mappings",
            return_value={
                "ports": {
                    "eth0": {
                        "dpdk_port_name": "dpdk-eth0",
                        "bridge": "br0",
                    }
                },
                "bonds": {},
            },
        )

        context = {
            "network": {"ovs_dpdk_enabled": True, "hw_offloading": False},
            "internal": {},
        }

        result = hooks._dpdk_config_is_ready(snap, ovs_cli, context)

        assert result is True
