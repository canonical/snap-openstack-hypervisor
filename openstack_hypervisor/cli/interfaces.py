# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import glob
import json
import logging
import os
import pathlib
from typing import Iterable

import click
import prettytable
import pydantic
import pyroute2
from pyroute2.ndb.objects.interface import Interface
from snaphelpers import Snap
from snaphelpers._conf import UnknownConfigKey

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

    pf_pci_address: str = pydantic.Field(description="The PF PCI address of a given SR-IOV VF")
    pci_whitelisted: bool = pydantic.Field(
        description="Whether Nova is configured to expose this PCI device."
    )
    pci_physnet: str = pydantic.Field(
        description="The Neutron physical network associated with this PCI device."
    )


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


def get_pf_pci_address(ifname: str) -> str:
    """Get the corresponding PF PCI address for a given VF."""
    pf_path = f"/sys/class/net/{ifname}/device/physfn"
    if not (os.path.exists(pf_path) and os.path.islink(pf_path)):
        # Not a VF.
        return ""
    resolved_path = os.path.realpath(pf_path)
    return resolved_path.split("/")[-1]


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


def _get_pci_spec_cfg():
    snap = Snap()

    try:
        pci_spec_cfg = snap.config.get("compute.pci-device-specs") or []
        if isinstance(pci_spec_cfg, str):
            pci_spec_cfg = json.loads(pci_spec_cfg)
    except UnknownConfigKey:
        # Unfortunately snap.config.get doesn't take a default value...
        pci_spec_cfg = []

    return pci_spec_cfg


def to_output_schema(nics: list[Interface]) -> NicList:
    """Convert the interfaces to the output schema."""
    nics_ = []

    pci_spec_cfg = _get_pci_spec_cfg()

    for nic in nics:
        ifname = nic["ifname"]

        sriov_available = is_sriov_capable(ifname)
        if sriov_available:
            sriov_totalvfs = get_sriov_totalvfs(ifname)
            sriov_numvfs = get_sriov_numvfs(ifname)
        else:
            sriov_totalvfs = 0
            sriov_numvfs = 0

        out = InterfaceOutput(
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
            pf_pci_address=get_pf_pci_address(ifname),
            pci_physnet="",
            pci_whitelisted=False,
        )

        if out.pci_address and out.vendor_id and out.product_id:
            for spec_dict in pci_spec_cfg:
                if not isinstance(spec_dict, dict):
                    raise ValueError("Invalid device spec, expecting a dict: %s." % spec_dict)

                pci_spec = devspec.PciDeviceSpec(spec_dict)
                dev = {
                    "vendor_id": out.vendor_id.lstrip("0x"),
                    "product_id": out.product_id.lstrip("0x"),
                    "address": out.pci_address,
                    "parent_addr": out.pf_pci_address,
                }
                match = pci_spec.match(dev)
                if match:
                    out.pci_whitelisted = True
                    if not out.pci_physnet:
                        out.pci_physnet = spec_dict.get("physical_network")
        nics_.append(out)
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


def get_nics() -> NicList:
    """List nics that are candidates for use by OVN/OVS subsystem."""
    # TODO: consider moving out reusable functions.
    with pyroute2.NDB() as ndb:
        nics = get_interfaces(ndb)
        return to_output_schema(nics)
