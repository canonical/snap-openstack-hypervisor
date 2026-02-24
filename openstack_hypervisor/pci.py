# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import copy
import logging
import os
import subprocess

from openstack_hypervisor import devspec

LOG = logging.getLogger(__name__)

# PCI device class definitions: https://admin.pci-ids.ucw.cz/read/PD
PCI_CLASS_NETWORK_CONTROLLER = "0x02"
PCI_CLASS_DISPLAY_CONTROLLER = "0x03"
PCI_SUBCLASS_PROCESSING_ACCELERATOR = "0x1200"


def get_pci_product_id(address: str) -> str:
    """Determine the PCI product id for the specified PCI address."""
    path = f"/sys/bus/pci/devices/{address}/device"
    if not os.path.exists(path):
        return ""
    with open(path, "r") as f:
        return f.read().strip()


def get_pci_vendor_id(address: str) -> str:
    """Determine the PCI vendor id for the specified PCI address."""
    path = f"/sys/bus/pci/devices/{address}/vendor"
    if not os.path.exists(path):
        return ""
    with open(path, "r") as f:
        return f.read().strip()


def get_pci_class(address: str) -> str:
    """Determine the PCI class for the specified PCI address."""
    path = f"/sys/bus/pci/devices/{address}/class"
    if not os.path.exists(path):
        return ""
    with open(path, "r") as f:
        return f.read().strip()


def is_sriov_capable(address: str) -> bool:
    """Determine whether a device is SR-IOV capable."""
    path = f"/sys/bus/pci/devices/{address}/sriov_totalvfs"
    return os.path.exists(path)


def get_sriov_totalvfs(address: str) -> int:
    """Read total VF capacity for a device."""
    path = f"/sys/bus/pci/devices/{address}/sriov_totalvfs"
    with open(path, "r") as f:
        read_data = f.read()
    return int(read_data.strip())


def get_sriov_numvfs(address: str) -> int:
    """Read configured VF capacity for a device."""
    path = f"/sys/bus/pci/devices/{address}/sriov_numvfs"
    with open(path, "r") as f:
        read_data = f.read()
    return int(read_data.strip())


def get_pci_description(address: str) -> dict:
    """Obtain human readable PCI information.

    Leverages "lspci -vmm" to obtain human readable PCI
    vendor and product names as opposed to parsing
    /usr/share/misc/pci.ids directly.
    """
    result = subprocess.run(
        ["lspci", "-s", address, "-vmm"], capture_output=True, check=True, text=True
    )
    lines = result.stdout.replace("\t", "").split("\n")
    raw_dict = {}
    for line in lines:
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        raw_dict[key] = val

    return {
        "class_name": raw_dict.get("Class"),
        "vendor_name": raw_dict.get("Vendor"),
        "device_name": raw_dict.get("Device"),
        "subsystem_vendor_name": raw_dict.get("SVendor"),
        "subsystem_device_name": raw_dict.get("SDevice"),
    }


def get_physfn_address(address: str) -> str:
    """Get the corresponding PF PCI address for a given VF."""
    path = f"/sys/bus/pci/devices/{address}/physfn"
    if not (os.path.exists(path) and os.path.islink(path)):
        # Not a VF.
        return ""
    resolved_path = os.path.realpath(path)
    return resolved_path.split("/")[-1]


def is_network_device(pci_class: str) -> bool:
    """Specifies whether the PCI class represents a network device."""
    # PCI class format:
    #   * class code (8 bytes)
    #   * subclass code (8 bytes)
    #   * vendor specific (8 bytes)
    return pci_class.startswith(PCI_CLASS_NETWORK_CONTROLLER)


def is_display_device(pci_class: str) -> bool:
    """Specifies whether the PCI class represents a display device."""
    # PCI class format:
    #   * class code (8 bytes)
    #   * subclass code (8 bytes)
    #   * vendor specific (8 bytes)
    return pci_class.startswith(PCI_CLASS_DISPLAY_CONTROLLER)


def is_accelerator_device(pci_class: str) -> bool:
    """Specifies whether the PCI class and subclass represents a accelerator device."""
    # PCI class format:
    #   * class code (8 bytes)
    #   * subclass code (8 bytes)
    #   * vendor specific (8 bytes)
    return pci_class.startswith(PCI_SUBCLASS_PROCESSING_ACCELERATOR)


def is_gpu_device(pci_class: str) -> bool:
    """Specifies whether the PCI represents a display or accelerator device."""
    return is_display_device(pci_class) or is_accelerator_device(pci_class)


def list_pci_devices() -> list[dict]:
    """Enumerate PCI devices."""
    devices = []
    addresses = os.listdir("/sys/bus/pci/devices/")
    for address in addresses:
        device = {
            "address": address,
            "product_id": get_pci_product_id(address),
            "vendor_id": get_pci_vendor_id(address),
            "physfn_address": get_physfn_address(address),
            "class": get_pci_class(address),
        }
        devices.append(device)
    return devices


def apply_exclusion_list(pci_device_specs: list[dict], excluded_devices: list[str]) -> list[dict]:
    """Exclude the specified devices from Nova's pci device whitelist.

    Receives a pci device spec list as defined by Nova[1] and a list of excluded
    PCI addresses. Updates the pci device specs based on the exclusion list and
    the identified PCI devices.

    For example, let's say that the user whitelisted all Intel x550 devices and then
    excluded one out of 4 such interfaces:
        pci_device_specs = [{"vendor_id": "8086", "product_id": "1563"}]
        excluded_devices = ["0000:1b:00.1"]

    The updated device spec will contain the vendor/product and pci address of the remaining
    3 Intel x550 devies.

        [
            {"vendor_id": "8086", "product_id": "1563", "address": "0000:19:00.0"},
            {"vendor_id": "8086", "product_id": "1563", "address": "0000:19:00.1"},
            {"vendor_id": "8086", "product_id": "1563", "address": "0000:1b:00.0"},
        ]

    A device spec that doesn't contain any excluded devices will not be modified.

    [1] https://docs.openstack.org/nova/latest/configuration/config.html#pci.device_spec
    """
    LOG.debug(
        "Applying PCI exclusion list. PCI device specs: %s, excluded devices: %s",
        pci_device_specs,
        excluded_devices,
    )
    if not excluded_devices:
        LOG.debug("No excluded devices, no changes made.")
        return pci_device_specs

    all_pci_devices = list_pci_devices()

    updated_pci_device_specs: list[dict] = []
    for dev_spec in pci_device_specs:
        if not isinstance(dev_spec, dict):
            raise ValueError("Invalid device spec, expecting a dict: %s." % dev_spec)
        pci_spec = devspec.PciDeviceSpec(dev_spec)

        # Converted device spec obtained by replacing wildcards and product/vendor id
        # rules with exact PCI addresses.
        granular_device_specs = []
        # Specifies if there are PCI devices matched by this device spec which are also
        # in the exclusion list, in which case the device spec must be replaced with
        # a granular whitelist.
        matched_excluded_devices = False
        for device in all_pci_devices:
            # We won't pass "parent_addr", the VF list gets populated separately and
            # we want to avoid duplicates, see "process_whitelisted_sriov_pfs".
            match = pci_spec.match(
                {
                    "vendor_id": device["vendor_id"].replace("0x", ""),
                    "product_id": device["product_id"].replace("0x", ""),
                    "address": device["address"],
                }
            )
            if match:
                if device["address"] in excluded_devices:
                    matched_excluded_devices = True
                    # Device excluded, do not include it in our granular
                    # device spec.
                else:
                    granular_spec = copy.deepcopy(dev_spec)
                    # Apply granular PCI filters.
                    granular_spec.update(
                        {
                            "vendor_id": device["vendor_id"],
                            "product_id": device["product_id"],
                            "address": device["address"],
                        }
                    )
                    granular_device_specs.append(granular_spec)

        if matched_excluded_devices:
            updated_pci_device_specs += granular_device_specs
        else:
            updated_pci_device_specs.append(dev_spec)

    LOG.debug("New PCI whitelist: %s", updated_pci_device_specs)
    return updated_pci_device_specs


def set_driver_override(pci_address: str, driver_name: str):
    """Persistently bind the pci device to the specified driver."""
    logging.info("Setting driver override: %s -> %s", pci_address, driver_name)
    subprocess.check_call(["driverctl", "set-override", pci_address, driver_name])


def get_driver_overrides() -> dict[str, str]:
    """Obtain a map of persistent driver overrides (address -> driver)."""
    overrides = {}
    try:
        out = subprocess.check_output(["driverctl", "list-overrides"])
    except subprocess.CalledProcessError:
        # driverctl returns non-zero (1) if there are no overrides...
        return overrides

    for line in out.decode().split("\n"):
        if not line or " " not in line:
            continue
        address, driver = line.split(" ", 1)
        if driver != "(none)":
            overrides[address] = driver
    return overrides


def ensure_driver_override(pci_address, driver_name):
    """Persistently bind the pci device to the specified driver.

    Avoids unbinding the driver if the desired driver is already configured.
    """
    overrides = get_driver_overrides()
    current_override = overrides.get(pci_address)
    if current_override != driver_name:
        LOG.info(
            "%s: found driver override: %s, changing to %s",
            pci_address,
            current_override,
            driver_name,
        )
        set_driver_override(pci_address, driver_name)
    else:
        LOG.info("%s: driver override already set: %s", pci_address, driver_name)
