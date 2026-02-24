# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import base64
import json
import logging
import sys
import typing

import click
from novaclient import client
from snaphelpers import Snap, UnknownConfigKey

from openstack_hypervisor import manage_guests
from openstack_hypervisor.bridge_datapath import OVSCli
from openstack_hypervisor.cli.common import (
    JSON_FORMAT,
    JSON_INDENT_FORMAT,
    VALUE_FORMAT,
    click_option_format,
)
from openstack_hypervisor.hooks import (
    _dpdk_config_is_ready,
    _get_configure_context,
    ovs_switch_socket,
    ovs_switchd_ctl_socket,
)

if typing.TYPE_CHECKING:
    from novaclient.v2.client import Client
    from novaclient.v2.services import Service


logger = logging.getLogger(__name__)


class HypervisorError(Exception):
    """Hypervisor base class error."""


def get_client_from_env(snap: Snap) -> "Client":
    """Get a nova client from the snap environment.

    This function looks into snap configuration to get identity and tls
    configuration to create a nova client.
    """
    try:
        identity_options = snap.config.get_options("identity")
    except UnknownConfigKey:
        raise HypervisorError("Missing identity configuration")

    try:
        ca_bundle = base64.b64decode(snap.config.get("ca.bundle"))
    except UnknownConfigKey:
        ca_bundle = None

    auth_url = identity_options.get("identity.auth-url")
    username = identity_options.get("identity.username")
    password = identity_options.get("identity.password")
    project_id = identity_options.get("identity.project-id")
    user_domain_id = identity_options.get("identity.user-domain-id")
    project_domain_id = identity_options.get("identity.project-domain-id")
    if not all([auth_url, username, password, project_id, user_domain_id, project_domain_id]):
        raise HypervisorError("Missing identity configuration")

    return client.Client(
        "2.95",
        username,
        password,
        project_id,
        auth_url,
        user_domain_id=user_domain_id,
        project_domain_id=project_domain_id,
        cacert=ca_bundle,
        endpoint_type="internal",
    )


def get_hostname(snap: Snap) -> str:
    """Get the hostname from the snap configuration."""
    try:
        return snap.config.get("node.fqdn")
    except UnknownConfigKey:
        raise HypervisorError("Missing hostname configuration")


def get_service(client: "Client", hostname: str) -> "Service":
    """Find the nova-compute service for the hypervisor."""
    try:
        service = client.services.find(binary="nova-compute", host=hostname)
        logger.debug("Found service %s for host %s", service.id, hostname)
        return service
    except Exception as e:
        raise HypervisorError(f"Failed to find hypervisor: {e}")


@click.group("hypervisor")
def hypervisor():
    """Set of utilities for managing the hypervisor."""


@hypervisor.command("disable")
@click.option(
    "--reason",
    help="Reason for disabling the hypervisor",
    default="Disabled by snap action",
    type=str,
)
def disable(reason: str):
    """Disable the hypervisor."""
    snap = Snap()
    client = get_client_from_env(snap)
    service = get_service(client, get_hostname(snap))
    client.services.disable_log_reason(service.id, reason)
    click.echo("Hypervisor disabled")


@hypervisor.command("enable")
def enable():
    """Enable the hypervisor."""
    snap = Snap()
    client = get_client_from_env(snap)
    service = get_service(client, get_hostname(snap))
    client.services.enable(service.id)
    click.echo("Hypervisor enabled")


@hypervisor.command("running-guests")
@click_option_format
def running_guests(format: str):
    """List the running guests on the hypervisor."""
    guests = manage_guests.all_guests()
    logger.debug("Found %s guests", len(guests))
    os_guests = [guest for guest in guests if manage_guests.openstack_guest(guest.XMLDesc())]
    logger.debug("Found %s OpenStack guests", len(os_guests))
    running_openstack_guests = [
        manage_guests.guest_uuid(guest.XMLDesc())
        for guest in manage_guests.running_guests(os_guests)
    ]
    logger.debug("Found %s running OpenStack guests", len(running_openstack_guests))
    if format == VALUE_FORMAT:
        click.echo("Running OpenStack guests:")
        for guest in running_openstack_guests:
            click.echo(guest)
    elif format in (JSON_FORMAT, JSON_INDENT_FORMAT):
        indent = 2 if format == JSON_INDENT_FORMAT else None
        click.echo(json.dumps(running_openstack_guests, indent=indent))


@hypervisor.command("dpdk-ready")
def dpdk_ready() -> None:
    """Check if DPDK configuration is ready.

    Validates that DPDK and hardware offload configuration is properly
    applied in OVS. This is particularly useful when using external OVS
    (e.g., MicroOVN) where configuration changes may require an OVS restart.

    The command checks:
    - DPDK initialization status when enabled
    - OVS configuration (dpdk-init, hw-offload) matches expected values
    - All expected DPDK ports and bonds exist in OVS

    Exit codes:
    - 0: DPDK configuration is ready
    - 1: DPDK configuration is not ready (restart may be required)
    """
    snap = Snap()
    ovs_socket = ovs_switch_socket(snap)
    switchd_ctl_socket = ovs_switchd_ctl_socket(snap)
    ovs_cli = OVSCli(ovs_socket, switchd_ctl_socket)
    context = _get_configure_context(snap)

    ready = _dpdk_config_is_ready(snap, ovs_cli, context)

    if ready:
        click.echo("DPDK configuration is ready")
        sys.exit(0)
    else:
        click.echo("DPDK configuration is NOT ready - external OVS restart may be required")
        sys.exit(1)
