# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"

BASE_CONTEXT = {
    "snap_common": "/var/snap/openstack-hypervisor/common",
    "logging": {"debug": False},
    "rabbitmq": {"url": "rabbit://guest:guest@mq.internal:5672/openstack"},
    "ca": {"bundle": "bundle"},
    "node": {"fqdn": "compute-0.internal", "ip_address": "10.0.0.10"},
    "network": {
        "ovs_socket_path": "unix:/var/run/openvswitch/db.sock",
        "dns_servers": "",
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
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
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
    assert output.count("interface = internal") >= 4
    assert "region_name = RegionOne" in output
    assert (
        "cafile = /var/snap/openstack-hypervisor/common/etc/ssl/certs/receive-ca-bundle.pem"
        in output
    )


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
