# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"

BASE_CONTEXT = {
    "snap": "/snap/openstack-hypervisor/current",
    "snap_common": "/var/snap/openstack-hypervisor/common",
    "logging": {"debug": False},
    "rabbitmq": {"url": "rabbit://guest:guest@mq.internal:5672/openstack"},
    "ca": {"bundle": "bundle"},
    "node": {"fqdn": "compute-0.internal", "ip_address": "10.0.0.10"},
    "network": {
        "ovs_socket_path": "unix:/var/run/openvswitch/db.sock",
        "ovn_nb_connection": "ssl:10.0.0.10:6641",
        "ovn_sb_connection": "ssl:10.0.0.10:6642",
        "dns_servers": "",
        "nova_metadata_proxy_url": "http://internal/nova-metadata",
        "nova_metadata_proxy_scheme": "http",
        "nova_metadata_proxy_host": "internal",
        "nova_metadata_proxy_server_host": "internal",
        "nova_metadata_proxy_port": 80,
        "nova_metadata_proxy_host_header": "internal",
        "nova_metadata_proxy_path": "/nova-metadata",
        "nova_metadata_proxy_ssl": False,
    },
    "compute": {
        "resume_on_boot": False,
        "multipath_enabled": False,
        "virt_type": "kvm",
        "cpu_mode": "host-passthrough",
        "cpu_models": "",
        "migration_address": "",
        "key_manager_enabled": True,
        "allocated_cores": "",
        "cpu_shared_set": "",
        "rbd_secret_uuid": "",
        "rbd_user": "",
        "flavors": [],
        "pci_device_specs": [],
        "pci_aliases": [],
        "spice_proxy_url": "",
        "spice_proxy_address": "",
    },
    "credentials": {"ovn_metadata_proxy_shared_secret": "secret"},
    "telemetry": {"publisher_secret": "publisher"},
    "identity": {
        "auth_url": "https://keystone.internal:5000/v3",
        "project_domain_name": "Default",
        "user_domain_name": "Default",
        "project_domain_id": "default",
        "user_domain_id": "default",
        "project_name": "service",
        "username": "nova",
        "password": "supersecret",
        "region_name": "RegionOne",
        "keystone_region_name": "RegionOne",
        "admin_role": "admin",
    },
}


def _render(template_name: str, **context_overrides) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        keep_trailing_newline=True,
    )
    context = dict(BASE_CONTEXT)
    context.update(context_overrides)
    return env.get_template(template_name).render(context)


def test_nova_clients_use_internal_interface():
    output = _render("nova.conf.j2")

    assert "[cinder]" in output
    assert "valid_interfaces = internal" in output
    assert output.count("valid_interfaces = internal") == 1
    assert "[neutron]" in output
    assert "[placement]" in output
    assert "[barbican]" in output
    assert output.count("interface = internal") >= 3
    assert output.count("barbican_endpoint_type = internal") == 1
    assert "region_name = RegionOne" in output
    assert (
        "cafile = /var/snap/openstack-hypervisor/common/etc/ssl/certs/receive-ca-bundle.pem"
        in output
    )
    assert (
        "verify_ssl_path = /var/snap/openstack-hypervisor/common/etc/ssl/certs/receive-ca-bundle.pem"
        in output
    ) == 1


def test_neutron_clients_use_internal_interface():
    output = _render("neutron.conf.j2")

    assert "[placement]" in output
    assert "[nova]" in output
    assert output.count("interface = internal") == 2
    assert output.count("region_name = RegionOne") >= 3
    assert (
        "cafile = /var/snap/openstack-hypervisor/common/etc/ssl/certs/receive-ca-bundle.pem"
        in output
    )


def test_neutron_ovn_agent_enables_metadata_with_all_ovsdb_connections():
    output = _render("neutron_ovn_agent.ini.j2")

    assert "nova_metadata_host = 127.0.0.1" in output
    assert "nova_metadata_port = 8775" in output
    assert "metadata_proxy_shared_secret = secret" in output
    assert "extensions = metadata" in output
    assert "ovsdb_connection = unix:/var/run/openvswitch/db.sock" in output
    assert "ovn_nb_connection = ssl:10.0.0.10:6641" in output
    assert "ovn_sb_connection = ssl:10.0.0.10:6642" in output
    for option, relative_path in {
        "ovn_nb_private_key": "private/ovn-key.pem",
        "ovn_nb_certificate": "certs/ovn-cert.pem",
        "ovn_nb_ca_cert": "certs/ovn-cacert.pem",
        "ovn_sb_private_key": "private/ovn-key.pem",
        "ovn_sb_certificate": "certs/ovn-cert.pem",
        "ovn_sb_ca_cert": "certs/ovn-cacert.pem",
    }.items():
        assert (
            f"{option} = /var/snap/openstack-hypervisor/common/etc/ssl/{relative_path}" in output
        )


def test_metadata_templates_render_before_credentials_are_configured():
    """First snap configure can run before charm-provided credentials exist."""
    output = _render("nova.conf.j2", credentials={})

    assert "service_metadata_proxy = True" not in output
    assert "metadata_proxy_shared_secret" not in output

    output = _render("neutron_ovn_agent.ini.j2", credentials={})

    assert "nova_metadata_host = 127.0.0.1" in output
    assert "nova_metadata_port = 8775" in output
    assert "metadata_proxy_shared_secret" not in output


def test_ceilometer_service_credentials_use_internal_interface_and_cafile():
    output = _render("ceilometer.conf.j2")

    assert "[service_credentials]" in output
    assert "interface = internal" in output
    assert "region_name = RegionOne" in output
    assert (
        "cafile = /var/snap/openstack-hypervisor/common/etc/ssl/certs/receive-ca-bundle.pem"
        in output
    )


def test_masakarimonitors_keeps_internal_api_and_region():
    output = _render("masakarimonitors.conf.j2")

    assert "api_interface = internal" in output
    assert "region = RegionOne" in output
    assert (
        "cafile = /var/snap/openstack-hypervisor/common/etc/ssl/certs/receive-ca-bundle.pem"
        in output
    )


def test_nova_metadata_is_local_reverse_proxy():
    output = _render("nova_metadata_haproxy.cfg.j2")

    assert "bind 127.0.0.1:8775" in output
    assert "http-request set-header Host internal" in output
    assert "http-request set-path /nova-metadata%[path]" in output
    assert "http-response del-header Transfer-Encoding" in output
    assert "http-response set-header Connection close" in output
    assert "server nova-metadata internal:80" in output
    assert output.endswith("\n")
    assert "WSGIScriptAlias" not in output


def test_nova_metadata_proxy_preserves_neutron_request_shape():
    output = _render("nova_metadata_haproxy.cfg.j2")

    assert "http-request set-header X-Forwarded-Proto http" in output
    assert "mode http" in output
