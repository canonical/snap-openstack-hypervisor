# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import glob
import json
import logging
import os
import pathlib
from typing import Any, Dict, Iterable, Optional

import click
import prettytable
import pydantic
import pyroute2
from pyroute2.ndb.objects.interface import Interface

from openstack_hypervisor import devspec
from openstack_hypervisor.cli.common import (
    JSON_FORMAT,
    JSON_INDENT_FORMAT,
    TABLE_FORMAT,
    VALUE_FORMAT,
)

logger = logging.getLogger(__name__)


class InterfaceOutput(pydantic.BaseModel):
    """Output schema for an interface."""

    name: str = pydantic.Field(description="Main name of the interface")
    configured: bool = pydantic.Field(
        description="Whether the interface has an IP address configured"
    )
    up: bool = pydantic.Field(description="Whether the interface is up")
    connected: bool = pydantic.Field(description="Whether the interface is connected")

    sriov_available: bool = pydantic.Field(description="Whether SR-IOV is supported")
    sriov_totalvfs: int = pydantic.Field(description="Total number of SR-IOV VFs")
    sriov_numvfs: int = pydantic.Field(description="Number of enabled SR-IOV VFs")
    hw_offload_available: bool = pydantic.Field(
        description="Whether switchdev hardware offload is supported"
    )
    pci_address: str = pydantic.Field(description="The PCI address of the interface")
    product_id: str = pydantic.Field(description="The PCI product id of the interface")
    vendor_id: str = pydantic.Field(description="The PCI vendor id of the interface")


class NicList(pydantic.RootModel[list[InterfaceOutput]]):
    """Root schema for a list of interfaces."""


def get_interfaces(ndb) -> list[Interface]:
    """Get all interfaces from the system."""
    return list(ndb.interfaces.values())


def is_link_local(address: str) -> bool:
    """Check if address is link local."""
    return address.startswith("fe80")


def is_interface_configured(nic: Interface) -> bool:
    """Check if interface has an IP address configured."""
    ipaddr = nic.ipaddr
    if ipaddr is None:
        return False
    for record in ipaddr.summary():
        if (ip := record["address"]) and not is_link_local(ip):
            logger.debug("Interface %r has IP address %r", nic["ifname"], ip)
            return True
    return False


def is_nic_connected(interface: Interface) -> bool:
    """Check if nic is physically connected."""
    return interface["operstate"].lower() == "up"


def is_nic_up(interface: Interface) -> bool:
    """Check if nic is up."""
    return interface["state"].lower() == "up"


def load_virtual_interfaces() -> list[str]:
    """Load virtual interfaces from the system."""
    virtual_nic_dir = "/sys/devices/virtual/net/*"
    return [pathlib.Path(p).name for p in glob.iglob(virtual_nic_dir)]


def get_pci_address(ifname: str) -> str:
    """Determine the interface PCI address.

    :param: ifname: interface name
    :type: str
    :returns: the PCI address of the device.
    :rtype: str
    """
    net_dev_path = f"/sys/class/net/{ifname}/device"
    if not (os.path.exists(net_dev_path) and os.path.islink(net_dev_path)):
        # Not a PCI device.
        return ""
    resolved_path = os.path.realpath(net_dev_path)
    parts = resolved_path.split("/")
    if "virtio" in parts[-1]:
        return parts[-2]
    return parts[-1]


def get_pci_product_id(ifname: str) -> str:
    """Determine the PCI product id of the specified interface.

    :param: ifname: interface name
    :type: str
    :returns: the PCI product id of the device.
    :rtype: str
    """
    path = f"/sys/class/net/{ifname}/device/device"
    if not os.path.exists(path):
        return ""
    with open(path, "r") as f:
        return f.read().strip()


def get_pci_vendor_id(ifname: str) -> str:
    """Determine the PCI product id of the specified interface.

    :param: ifname: interface name
    :type: str
    :returns: the PCI product id of the device.
    :rtype: str
    """
    path = f"/sys/class/net/{ifname}/device/vendor"
    if not os.path.exists(path):
        return ""
    with open(path, "r") as f:
        return f.read().strip()


def is_sriov_capable(ifname: str) -> bool:
    """Determine whether a device is SR-IOV capable.

    :param: ifname: interface name
    :type: str
    :returns: whether device is SR-IOV capable or not
    :rtype: bool
    """
    sriov_totalvfs_file = f"/sys/class/net/{ifname}/device/sriov_totalvfs"
    return os.path.exists(sriov_totalvfs_file)


def is_hw_offload_available(ifname: str) -> bool:
    """Determine whether a devices supports switchdev hardware offload.

    :param: ifname: interface name
    :type: str
    :returns: whether device is SR-IOV capable or not
    :rtype: bool
    """
    phys_port_name_file = f"/sys/class/net/{ifname}/phys_port_name"
    if not os.path.isfile(phys_port_name_file):
        return False

    try:
        with open(phys_port_name_file, "r") as f:
            phys_port_name = f.readline().strip()
            return phys_port_name != ""
    except (OSError, IOError):
        return False


def get_sriov_totalvfs(ifname: str) -> int:
    """Read total VF capacity for a device.

    :param: ifname: interface name
    :type: str
    :returns: number of VF's the device supports
    :rtype: int
    """
    sriov_totalvfs_file = f"/sys/class/net/{ifname}/device/sriov_totalvfs"
    with open(sriov_totalvfs_file, "r") as f:
        read_data = f.read()
    return int(read_data.strip())


def get_sriov_numvfs(ifname: str) -> int:
    """Read configured VF capacity for a device.

    :param: ifname: interface name
    :type: str
    :returns: number of VF's the device is configured with
    :rtype: int
    """
    sriov_numvfs_file = f"/sys/class/net/{ifname}/device/sriov_numvfs"
    with open(sriov_numvfs_file, "r") as f:
        read_data = f.read()
    return int(read_data.strip())


def filter_candidate_nics(nics: Iterable[Interface]) -> list[str]:
    """Return a list of candidate nics.

    Candidate nics are:
      - not part of a bond
      - not a virtual nic except for bond and vlan
      - not configured (unless include_configured is True)
    """
    configured_nics = []
    virtual_nics = load_virtual_interfaces()
    for nic in nics:
        ifname = nic["ifname"]
        logger.debug("Checking interface %r", ifname)

        if nic["slave_kind"] == "bond":
            logger.debug("Ignoring interface %r, it is part of a bond", ifname)
            continue

        if ifname in virtual_nics:
            kind = nic["kind"]
            if kind in ("bond", "vlan"):
                logger.debug("Interface %r is a %s", ifname, kind)
            else:
                logger.debug(
                    "Ignoring interface %r, it is a virtual interface, kind: %s", ifname, kind
                )
                continue

        is_configured = is_interface_configured(nic)
        logger.debug("Interface %r is configured: %r", ifname, is_configured)
        logger.debug("Adding interface %r as a candidate", ifname)
        configured_nics.append(ifname)

    return configured_nics


def to_output_schema(nics: list[Interface]) -> NicList:
    """Convert the interfaces to the output schema."""
    nics_ = []
    for nic in nics:
        ifname = nic["ifname"]

        sriov_available = is_sriov_capable(ifname)
        if sriov_available:
            sriov_totalvfs = get_sriov_totalvfs(ifname)
            sriov_numvfs = get_sriov_numvfs(ifname)
        else:
            sriov_totalvfs = 0
            sriov_numvfs = 0

        nics_.append(
            InterfaceOutput(
                name=ifname,
                configured=is_interface_configured(nic),
                up=is_nic_up(nic),
                connected=is_nic_connected(nic),
                sriov_available=sriov_available,
                sriov_totalvfs=sriov_totalvfs,
                sriov_numvfs=sriov_numvfs,
                hw_offload_available=is_hw_offload_available(ifname),
                pci_address=get_pci_address(ifname),
                product_id=get_pci_product_id(ifname),
                vendor_id=get_pci_vendor_id(ifname),
            )
        )
    return NicList(nics_)


def display_nics(nics: NicList, candidate_nics: list[str], format: str):
    """Display the result depending on the format."""
    if format in (VALUE_FORMAT, TABLE_FORMAT):
        table = prettytable.PrettyTable()
        table.title = "All NICs"
        table.field_names = ["Name", "Configured", "Up", "Connected", "SR-IOV", "HW offload"]
        for nic in nics.root:
            table.add_row(
                [
                    nic.name,
                    nic.configured,
                    nic.up,
                    nic.connected,
                    nic.sriov_available,
                    nic.hw_offload_available,
                ]
            )
        print(table)

        if candidate_nics:
            table = prettytable.PrettyTable()
            table.title = "Candidate NICs"
            table.field_names = ["Name"]
            for candidate in candidate_nics:
                table.add_row([candidate])
            print(table)
    elif format in (JSON_FORMAT, JSON_INDENT_FORMAT):
        indent = 2 if format == JSON_INDENT_FORMAT else None
        print(json.dumps({"nics": nics.model_dump(), "candidates": candidate_nics}, indent=indent))


@click.command("list-nics")
@click.option(
    "-f",
    "--format",
    default=JSON_FORMAT,
    type=click.Choice([VALUE_FORMAT, TABLE_FORMAT, JSON_FORMAT, JSON_INDENT_FORMAT]),
    help="Output format",
)
def list_nics(format: str):
    """List nics that are candidates for use by OVN/OVS subsystem.

    This nic will be used by OVS to provide external connectivity to the VMs.

    The output specifies which adapters are SR-IOV capable, including PCI
    information that can be used to identify and expose SR-IOV devices.

    It also specifies whether the adapters support hardware offloading
    (switchdev), which allows SR-IOV VFs to be connected to the OVS
    bridge, offloading the flows to the adapter.
    """
    with pyroute2.NDB() as ndb:
        nics = get_interfaces(ndb)
        candidate_nics = filter_candidate_nics(nics)
        nics_ = to_output_schema(nics)
    display_nics(nics_, candidate_nics, format)


def get_sriov_pf_physnet(
    nic: InterfaceOutput, pci_device_spec: list[Dict[Any, Any]]
) -> Optional[str]:
    """Obtain the corresponding Neutron physnet of an SR-IOV PF."""
    if not nic.sriov_available:
        logger.debug("Not an SR-IOV device: %s", nic.name)
        return ""

    for spec_dict in pci_device_spec:
        physical_network = spec_dict.get("physical_network")
        if not physical_network:
            logger.debug("The pci spec doesn't contain a physical network, continuing.")
            continue

        pci_spec = devspec.PciDeviceSpec(spec_dict)
        if not pci_spec.match(
            {
                "vendor_id": nic.vendor_id,
                "product_id": nic.product_id,
                "address": nic.address,
                "parent_addr": None,  # we only care about PFs.
            }
        ):
            continue

        return physical_network


def get_assignable_sriov_nics(pci_device_spec: list[Dict[Any, Any]]) -> list[dict]:
    """Obtain the list of SR-IOV PFs that can expose VFs to Nova instances.

    Discovers the local SR-IOV capable devices and checks the Nova PCI
    passthrough whitelist that was provided through the `compute.pci.device-spec`
    config option.

    :param: pci_device_spec: a list of dictionaries as defined by Nova:
            https://docs.openstack.org/nova/latest/configuration/config.html#pci.device_spec
    :type: list[dict]
    :returns: A list of dictionaries containing assignable PFs and corresponding physnet.
    :rtype: list[dict]

    Device spec example:
    [
        {
            "vendor_id":"a2d6",
            "product_id":"15b3",
            "address": "0000:82:00.0",
            "physical_network":"physnet1",
            "remote_managed": "true"
        },
    ]
    """
    with pyroute2.NDB() as ndb:
        nics = get_interfaces(ndb)

    out_list = []
    for nic in nics:
        physnet = get_sriov_pf_physnet(to_output_schema(nic))
        if not physnet:
            logging.debug("No physical network associated with nic: %s", nic.name)
            continue

        assignable_nic = {
            "vendor_id": nic.vendor_id,
            "product_id": nic.product_id,
            "address": nic.address,
            "physical_network": physnet,
            "name": nic.name,
        }
        out_list.append(assignable_nic)

    return out_list
