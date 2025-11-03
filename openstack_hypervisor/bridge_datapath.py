# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import logging
from dataclasses import dataclass
from typing import TypedDict

logging.basicConfig(level=logging.INFO)


@dataclass(frozen=True)
class BridgeMapping:
    """Represents a mapping between physnet, bridge, and interface."""

    physnet: str
    bridge: str
    interface: str | None

    def physnet_bridge_pair(self) -> str:
        """Return the physnet:bridge pair string."""
        return f"{self.physnet}:{self.bridge}"


class InterfaceChanges(TypedDict):
    """Interface changes for a bridge."""

    removed: list[str]
    added: list[str]


class BridgeResolutionStatus(TypedDict):
    """Status of bridge resolution between old and new configurations."""

    renamed_bridges: list[tuple[str, str]]
    added_bridges: list[str]
    removed_bridges: list[str]
    interface_changes: dict[str, InterfaceChanges]


def resolve_bridge_mappings(  # noqa: C901
    external_bridge: str,
    physnet_name: str,
    external_nic: str,
    physnet_mapping: str,
    interface_mapping: str,
) -> list[BridgeMapping]:
    """Resolve bridge mappings for OVN external networking.

    External bridge, physnet name and external nic are deprecated in favour of
    physnet and interface bridge mappings. This function resolves the effective
    mappings to use.

    :param external_bridge: Name of external bridge.
    :param physnet_name: Name of physical network.
    :param external_nic: Name of external NIC.
    :param physnet_mapping: Physnet to bridge mapping string.
    :param interface_mapping: Bridge to interface mapping string.
    :return: List of BridgeMapping objects.
    """
    mappings: list[BridgeMapping] = []

    if physnet_mapping or interface_mapping:
        physnet_map: dict[str, str] = {}
        if physnet_mapping:
            for mapping in physnet_mapping.split(" "):
                try:
                    physnet, bridge = mapping.split(":")
                    physnet_map[physnet.strip()] = bridge.strip()
                except ValueError:
                    logging.warning(f"Invalid physnet-bridge mapping: {mapping}")

        interface_map: dict[str, str] = {}
        if interface_mapping:
            for mapping in interface_mapping.split(" "):
                try:
                    bridge, iface = mapping.split(":")
                    interface_map[bridge.strip()] = iface.strip()
                except ValueError:
                    logging.warning(f"Invalid bridge-interface mapping: {mapping}")

        for physnet, bridge in physnet_map.items():
            interface: str | None = interface_map.get(bridge)
            mappings.append(BridgeMapping(physnet, bridge, interface))
    elif external_bridge and physnet_name:
        mappings.append(BridgeMapping(physnet_name, external_bridge, external_nic or None))
    else:
        logging.info("No OVN external networking configuration found.")

    return mappings


def resolve_ovs_changes(  # noqa: C901
    previous_mapping: list[BridgeMapping], new_mapping: list[BridgeMapping]
) -> BridgeResolutionStatus:
    """This function outputs a structured status of changes between 2 mappings.

    We need to detect:
      - Renamed bridges (we don't support them, so we'll consider them as the older bridge.)
      - New bridge
      - Removed bridge
      - Interface removed from which bridge
      - Interface added to which bridge
      - An interface cannot be in 2 bridges

    We use physnet to help detect a bridge rename and handle it smoothly.
    The physnet is the primary identifier - if the same physnet points to a different
    bridge name, that's a rename attempt.
    """
    status: BridgeResolutionStatus = {
        "renamed_bridges": [],
        "added_bridges": [],
        "removed_bridges": [],
        "interface_changes": {},
    }

    # Build physnet-to-bridge mappings for both old and new configs
    prev_physnet_map: dict[str, str] = {m.physnet: m.bridge for m in previous_mapping}
    new_physnet_map: dict[str, str] = {m.physnet: m.bridge for m in new_mapping}

    # Build bridge-to-interface mappings
    prev_bridge_interfaces: dict[str, set[str]] = {}
    for m in previous_mapping:
        if m.bridge not in prev_bridge_interfaces:
            prev_bridge_interfaces[m.bridge] = set()
        if m.interface:
            prev_bridge_interfaces[m.bridge].add(m.interface)

    new_bridge_interfaces: dict[str, set[str]] = {}
    for m in new_mapping:
        if m.bridge not in new_bridge_interfaces:
            new_bridge_interfaces[m.bridge] = set()
        if m.interface:
            new_bridge_interfaces[m.bridge].add(m.interface)

    # Track all physnets we've seen
    all_physnets = set(prev_physnet_map.keys()) | set(new_physnet_map.keys())

    # Track which bridges are accounted for
    renamed_old_bridges = set()
    renamed_new_bridges = set()

    # Detect renamed bridges by tracking physnet identity
    for physnet in all_physnets:
        prev_bridge = prev_physnet_map.get(physnet)
        new_bridge = new_physnet_map.get(physnet)

        if prev_bridge and new_bridge and prev_bridge != new_bridge:
            # Same physnet, different bridge name = rename attempt
            status["renamed_bridges"].append((prev_bridge, new_bridge))
            renamed_old_bridges.add(prev_bridge)
            renamed_new_bridges.add(new_bridge)

    # Detect removed bridges (existed before, physnet no longer exists)
    prev_bridges = set(prev_physnet_map.values())
    new_bridges = set(new_physnet_map.values())

    removed_bridges = prev_bridges - new_bridges - renamed_old_bridges
    status["removed_bridges"].extend(sorted(removed_bridges))

    # Detect added bridges (new physnet with new bridge)
    added_bridges = new_bridges - prev_bridges - renamed_new_bridges
    status["added_bridges"].extend(sorted(added_bridges))

    # Detect interface changes
    # For each physnet, compare interfaces between old and new
    for physnet in all_physnets:
        prev_bridge = prev_physnet_map.get(physnet)
        new_bridge = new_physnet_map.get(physnet)

        if not prev_bridge and not new_bridge:
            continue

        # Use the old bridge name for tracking (since renames aren't supported)
        # Even for renamed bridges, we track changes under the old bridge name
        tracking_bridge: str = prev_bridge if prev_bridge else new_bridge  # type: ignore

        prev_interfaces: set[str] = (
            prev_bridge_interfaces.get(prev_bridge, set()) if prev_bridge else set()
        )
        new_interfaces: set[str] = (
            new_bridge_interfaces.get(new_bridge, set()) if new_bridge else set()
        )

        removed: set[str] = prev_interfaces - new_interfaces
        added: set[str] = new_interfaces - prev_interfaces

        if removed or added:
            status["interface_changes"][tracking_bridge] = {
                "removed": sorted(removed),
                "added": sorted(added),
            }

    return status
