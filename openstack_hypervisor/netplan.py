# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0


# Netplan configuration utils
#
# Unfortunately libnetplan doesn't expose all the fields that we need
# and isn't very well documented, even less so the CFFI Python bindings.
#
# At the same time, the configuration may be scattered across multiple
# yaml files, as such it's more convenient to just leverage the Netplan CLI.

import io
import logging
import os
import subprocess

import yaml


def get_netplan_config() -> dict:
    """Retrieve the Netplan configuration.

    Note that Netplan may contain multiple configuration files that
    are going to be merged.

    :return: a dict containing the parsed yaml.
    """
    raw_yaml = subprocess.check_output(["netplan", "get"]).decode()
    return yaml.safe_load(io.StringIO(raw_yaml))


def remove_interface_from_bridge(bridge_name: str, interface_name: str) -> bool:
    """Remove an interface (or bond) from a bridge.

    :return: A boolean stating if changes were made.
    """
    logging.debug("Removing interface %s from bridge %s", interface_name, bridge_name)

    config = get_netplan_config().get("network") or {}
    bridge = (config.get("bridges") or {}).get(bridge_name)
    if not bridge:
        logging.debug(
            "Could not find bridge: %s, skipped removing interface: %s",
            bridge_name,
            interface_name,
        )
        return False

    interfaces = bridge.get("interfaces") or []
    if interface_name not in interfaces:
        logging.debug("Bridge %s doesn't contain interface %s.", bridge_name, interface_name)
        return False

    interfaces.remove(interface_name)

    if not interfaces:
        interfaces_arg = "NULL"
    else:
        interfaces_arg = "[%s]" % ",".join(interfaces)
    subprocess.check_call(["netplan", "set", f"bridges.{bridge_name}.interfaces={interfaces_arg}"])
    return True


def remove_bond(bond_name: str):
    """Remove bond."""
    logging.info("Removing bond: %s", bond_name)

    subprocess.check_call(["netplan", "set", f"bonds.{bond_name}=NULL"])
    if os.path.exists(f"/proc/net/bonding/{bond_name}"):
        subprocess.check_call(["ip", "link", "delete", "dev", bond_name])


def remove_ethernet(interface_name: str):
    """Remove interface configuration."""
    logging.info("Removing interface: %s", interface_name)
    subprocess.check_call(["netplan", "set", f"ethernets.{interface_name}=NULL"])


def apply_netplan():
    """Apply the Netplan configuration."""
    logging.info("Applying Netplan configuration.")

    subprocess.check_call(["netplan", "apply"])
