# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import hashlib
import logging
import subprocess
from dataclasses import dataclass
from typing import TypedDict

DEFAULT_LAA_MAC_PREFIX = "0a:c5"
INTEGRATION_BRIDGE = "br-int"


@dataclass(frozen=True)
class BridgeMapping:
    """Represents a mapping between physnet, bridge, and interface."""

    bridge: str
    physnet: str
    interface: str | None

    def physnet_bridge_pair(self) -> str:
        """Return the physnet:bridge pair string."""
        return f"{self.physnet}:{self.bridge}"

    def physnet_mac_pair(self, machine_id: str) -> str:
        """Return the physnet:MAC pair string for this mapping."""
        mac = generate_stable_laa_mac(
            prefix=DEFAULT_LAA_MAC_PREFIX,
            physnet=self.physnet,
            machine_id=machine_id,
        )
        return f"{self.physnet}:{mac}"


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


class OVSCommandError(RuntimeError):
    """Raised when querying OVS state fails."""


def _normalize_ovs_vsctl_value(raw_value: str) -> str | None:
    """Normalize ovs-vsctl output values into plain strings."""
    cleaned = raw_value.strip()
    if not cleaned or cleaned in {"[]", "{}"}:
        return None
    if cleaned.startswith('"') and cleaned.endswith('"'):
        cleaned = cleaned[1:-1]
    return cleaned or None


class OVSCli:
    """Client for interacting with Open vSwitch via ovs-vsctl."""

    def __init__(self, db_sock: str | None = None):
        """Initialize OVS CLI client.

        Args:
            db_sock: Optional database socket path to use for all commands.
        """
        self.db_sock = db_sock

    def vsctl(self, *args: str, retry: bool = True, timeout: int | None = None) -> str:
        """Run ovs-vsctl with the provided arguments and return stdout.

        Args:
            *args: Arguments to pass to ovs-vsctl.
            retry: Whether to use the --retry flag.
            timeout: Optional timeout in seconds for the command.

        Returns:
            The stdout output from the command.

        Raises:
            OVSCommandError: If the command fails or ovs-vsctl is not found.
        """
        cmd = ["ovs-vsctl"]
        if self.db_sock:
            cmd.append("--db=" + self.db_sock)
        if retry:
            cmd.append("--retry")
        if timeout is not None:
            cmd.append(f"--timeout={timeout}")
        cmd.extend(args)
        logging.debug("Executing command: %s", " ".join(cmd))

        try:
            completed = subprocess.run(  # nosec B603
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise OVSCommandError("ovs-vsctl binary not found") from exc
        except subprocess.CalledProcessError as exc:  # pragma: no cover - defensive
            stderr = (exc.stderr or "").strip()
            stdout = (exc.stdout or "").strip()
            details = stderr or stdout or f"Command failed with exit code {exc.returncode}"
            raise OVSCommandError(details) from exc

        return completed.stdout

    def list_bridges(self) -> list[str]:
        """Return the list of bridges currently present in OVS.

        Returns:
            Sorted list of bridge names.
        """
        output = self.vsctl("list-br")
        return sorted({bridge for bridge in output.splitlines() if bridge.strip()})

    def list_bridge_interfaces(self, bridge: str) -> list[str]:
        """Return interfaces attached to a bridge.

        Args:
            bridge: Name of the bridge to query.

        Returns:
            Sorted list of interface names attached to the bridge.
        """
        output = self.vsctl("list-ifaces", bridge)
        bridge_ifaces = {iface.strip() for iface in output.splitlines() if iface.strip()}

        if not bridge_ifaces:
            return []

        # Filter out patch and internal ports
        actual_ifaces_output = self.vsctl(
            "--bare",
            "--columns=name",
            "find",
            "Interface",
            "type!=patch",
            "type!=internal",
        )
        actual_ifaces = {
            iface.strip() for iface in actual_ifaces_output.splitlines() if iface.strip()
        }

        return sorted(bridge_ifaces & actual_ifaces)

    def get_bridge_physnet_map(self) -> dict[str, str]:
        """Return a bridge-to-physnet mapping from the global OVS configuration.

        Returns:
            Dictionary mapping bridge names to physnet names.
        """
        try:
            raw_value = self.vsctl("get", "open", ".", "external_ids:ovn-bridge-mappings")
        except OVSCommandError:
            return {}

        normalized = _normalize_ovs_vsctl_value(raw_value)
        if not normalized:
            return {}

        mapping: dict[str, str] = {}
        for pair in normalized.split(","):
            if not pair.strip():
                continue
            if ":" not in pair:
                logging.debug("Skipping malformed bridge mapping entry: %s", pair)
                continue
            physnet, bridge = pair.split(":", 1)
            physnet = physnet.strip()
            bridge = bridge.strip()
            if bridge:
                mapping[bridge] = physnet

        return mapping


def resolve_bridge_mappings(  # noqa: C901
    external_bridge: str,
    physnet_name: str,
    external_nic: str,
    bridge_mapping: str,
) -> list[BridgeMapping]:
    """Resolve bridge mappings for OVN external networking.

    External bridge, physnet name and external nic are deprecated in favour of
    physnet and interface bridge mappings. This function resolves the effective
    mappings to use.

    :param external_bridge: Name of external bridge.
    :param physnet_name: Name of physical network.
    :param external_nic: Name of external NIC.
    :param bridge_mapping: Bridge:Physnet:Interface mapping string.
    :return: List of BridgeMapping objects.
    """
    mappings: list[BridgeMapping] = []

    seen_physnets: list[str] = []
    seen_bridges: list[str] = []
    seen_interfaces: list[str] = []

    if bridge_mapping:
        for mapping in bridge_mapping.strip().split(" "):
            if not mapping:
                # whitespaces only
                continue
            split = mapping.split(":")
            if len(split) == 2:
                bridge, physnet = split
                iface = None
            elif len(split) == 3:
                bridge, physnet, iface = split
            else:
                raise ValueError("Invalid mapping format")
            if physnet in seen_physnets:
                raise ValueError(f"Duplicate physnet in mapping: {physnet}")
            if bridge in seen_bridges:
                raise ValueError(f"Duplicate bridge in mapping: {bridge}")
            if iface and iface in seen_interfaces:
                raise ValueError(f"Duplicate interface in mapping: {iface}")
            seen_physnets.append(physnet)
            seen_bridges.append(bridge)
            if iface:
                seen_interfaces.append(iface)
            mappings.append(BridgeMapping(bridge, physnet, iface or None))
    elif external_bridge and physnet_name:
        mappings.append(BridgeMapping(external_bridge, physnet_name, external_nic or None))
    else:
        logging.info("No OVN external networking configuration found.")

    return mappings


def resolve_ovs_changes(  # noqa: C901
    previous_mapping: list[BridgeMapping], new_mapping: list[BridgeMapping]
) -> BridgeResolutionStatus:
    """This function outputs a structured status of changes between 2 mappings.

    We need to detect:
      - Renamed bridges (detected by tracking physnet changes,
                         handled by keeping the existing bridge name)
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


def update_mappings_from_rename(
    mappings: list[BridgeMapping],
    renames: list[tuple[str, str]],
) -> list[BridgeMapping]:
    """Update bridge mappings based on renames.

    We don't want to recreate the bridges on rename, so we keep the old
    bridge names in the mappings.
    """
    if not renames:
        return mappings

    rename_dict = dict((new_name, old_name) for old_name, new_name in renames)
    updated_mappings = []
    for mapping in mappings:
        if mapping.bridge not in rename_dict:
            updated_mappings.append(mapping)
            continue
        new_bridge = rename_dict.get(mapping.bridge, mapping.bridge)
        updated_mappings.append(
            BridgeMapping(
                physnet=mapping.physnet,
                bridge=new_bridge,
                interface=mapping.interface,
            )
        )
    return updated_mappings


def detect_current_mappings(ovs_cli: OVSCli | None = None) -> list[BridgeMapping]:  # noqa: C901
    """Detect current bridge mappings from system configuration.

    Args:
        ovs_cli: Optional OVSCli instance to use. If not provided, a new one is created.

    Returns:
        List of BridgeMapping objects representing current system state.
    """
    if ovs_cli is None:
        ovs_cli = OVSCli()

    try:
        bridges = ovs_cli.list_bridges()
    except OVSCommandError as exc:
        logging.warning("Unable to query OVS bridges: %s", exc)
        return []

    if not bridges:
        logging.info("No OVS bridges found while detecting current mappings.")
        return []

    bridge_physnet_map = ovs_cli.get_bridge_physnet_map()
    mappings: list[BridgeMapping] = []
    seen: set[tuple[str, str, str | None]] = set()

    def add_mapping(entry: tuple[str, str, str | None]) -> None:
        if entry in seen:
            return
        seen.add(entry)
        mappings.append(BridgeMapping(*entry))

    for bridge in bridges:
        if bridge == INTEGRATION_BRIDGE:
            continue  # Skip internal integration bridge
        physnet = bridge_physnet_map.get(bridge)

        if not physnet:
            logging.warning(
                "Physnet mapping missing for bridge %s; skipping.",
                bridge,
            )
            continue

        try:
            interfaces = ovs_cli.list_bridge_interfaces(bridge)
        except OVSCommandError as exc:
            logging.warning("Failed to list interfaces for bridge %s: %s", bridge, exc)
            add_mapping((bridge, physnet, None))
            continue

        # Ignore the internal bridge interface (same name as the bridge).
        interfaces = [iface for iface in interfaces if iface != bridge]

        if not interfaces:
            add_mapping((bridge, physnet, None))
            continue

        for interface in interfaces:
            if not interface:
                continue
            add_mapping((bridge, physnet, interface))

    return mappings


def generate_stable_laa_mac(prefix: str, physnet: str, machine_id: str) -> str:
    """Generate a stable, deterministic LAA MAC address.

    This function generates a Locally Administered Address (LAA) MAC address
    based on a given prefix, physnet name, and a stable machine identifier.
    The resulting MAC address is constructed as follows:
    [LAA Prefix (2 bytes)] : [PHYSNET HASH (1 byte)] : [Machine_ID_HASH (3 bytes)]

    Uses SHA256 hashing to ensure deterministic output. The same inputs will
    always produce the same MAC address.

    Args:
        prefix (str): The chosen LAA prefix (e.g., '0A:C5'). The 2nd bit must be '1'
                      (e.g., 02, 06, 0A, 0E, etc. for the first octet).
        physnet (str): The name of the physnet (e.g., 'physnet1').
        machine_id (str): A stable and unique ID for the node (e.g., host UUID, management IP).

    Returns:
        str: The stable LAA MAC address in the format "XX:XX:XX:XX:XX:XX".

    Raises:
        ValueError: If prefix is not exactly 2 octets or doesn't have LAA bit set.
    """
    prefix_parts = prefix.split(":")
    if len(prefix_parts) != 2:
        raise ValueError(f"Prefix must be exactly 2 octets, got: {prefix}")

    try:
        first_octet = int(prefix_parts[0], 16)
    except ValueError as exc:
        raise ValueError(f"Invalid hex value in prefix: {prefix}") from exc

    if not (first_octet & 0x02):
        raise ValueError(
            f"Prefix first octet must have LAA bit set (bit 1), got: {prefix_parts[0]}"
        )

    physnet_hash = hashlib.sha256(physnet.encode("utf-8")).digest()
    physnet_bytes = f"{physnet_hash[0]:02x}"

    machine_hash = hashlib.sha256(machine_id.encode("utf-8")).digest()
    machine_bytes = f"{machine_hash[0]:02x}:{machine_hash[1]:02x}:{machine_hash[2]:02x}"

    return f"{prefix}:{physnet_bytes}:{machine_bytes}"
