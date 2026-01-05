# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import contextlib
import hashlib
import json
import logging
import subprocess
from collections.abc import Generator
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


class OVSError(RuntimeError):
    """Common base class for OVS-related errors."""


class OVSCommandError(OVSError):
    """Raised when querying OVS state fails."""


def _normalize_ovs_vsctl_value(raw_value: str) -> str | None:
    """Normalize ovs-vsctl output values into plain strings."""
    cleaned = raw_value.strip()
    if not cleaned or cleaned in {"[]", "{}"}:
        return None
    if cleaned.startswith('"') and cleaned.endswith('"'):
        cleaned = cleaned[1:-1]
    return cleaned or None


def _parse_ovsdb_data(data):
    """Parse OVSDB data according to RFC 7047.

    https://tools.ietf.org/html/rfc7047#section-5.1
    """
    if isinstance(data, list) and len(data) == 2:
        if data[0] == "set":
            return [_parse_ovsdb_data(element) for element in data[1]]
        if data[0] == "map":
            return {_parse_ovsdb_data(key): _parse_ovsdb_data(value) for key, value in data[1]}
        if data[0] == "uuid":
            import uuid

            return uuid.UUID(data[1])
    return data


class OVSCli:
    """Client for interacting with Open vSwitch via ovs-vsctl."""

    def __init__(self, db_sock: str | None = None):
        """Initialize OVS CLI client.

        Args:
            db_sock: Optional database socket path to use for all commands.
        """
        self.db_sock = db_sock
        self._in_transaction: bool = False
        self._transaction_commands: list[list[str]] = []

    @contextlib.contextmanager
    def transaction(self, retry: bool = True) -> Generator["OVSCli", None, None]:
        """Context manager for batching multiple OVS commands into a single transaction.

        All ovs-vsctl commands executed within this context will be collected and
        executed as a single atomic operation when the context exits. Commands are
        joined using the ovs-vsctl '--' separator syntax.

        Note: This is not thread-safe. Do not use the same OVSCli instance
        concurrently from multiple threads while a transaction is active.

        Yields:
            self: The OVSCli instance for method chaining.

        Raises:
            OVSCommandError: If the batched command fails during commit.

        Example:
            with ovs_cli.transaction():
                ovs_cli.add_bridge("br-ex")
                ovs_cli.add_port("br-ex", "eth0")
            # All commands execute atomically here
        """
        if self._in_transaction:
            raise OVSError("Nested transactions are not supported")

        self._in_transaction = True
        self._transaction_commands = []
        try:
            yield self
            self.commit(retry=retry)
        finally:
            self._in_transaction = False
            self._transaction_commands = []

    def commit(self, retry) -> str:
        """Execute all batched commands in a single ovs-vsctl transaction.

        This method executes all commands that have been collected during a
        transaction context. It is automatically called when exiting a
        transaction() context, but can also be called manually.

        Returns:
            The stdout output from the batched command, or empty string if
            no commands were batched.

        Raises:
            OVSCommandError: If the batched command fails.
        """
        if not self._transaction_commands:
            return ""

        # Build the combined command with '--' separators
        args: list[str] = []
        for i, command_args in enumerate(self._transaction_commands):
            if i > 0:
                args.append("--")
            args.extend(command_args)

        try:
            return self._execute_vsctl(args, retry=retry)
        finally:
            self._transaction_commands = []

    def _execute_vsctl(
        self, args: list[str], retry: bool = True, timeout: int | None = None
    ) -> str:
        """Execute ovs-vsctl with the provided arguments.

        This is the internal method that performs the actual subprocess execution.

        Args:
            args: Arguments to pass to ovs-vsctl.
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

    def vsctl(
        self,
        *args: str,
        retry: bool = True,
        timeout: int | None = None,
        skip_transaction: bool = False,
    ) -> str:
        """Run ovs-vsctl with the provided arguments and return stdout.

        Args:
            *args: Arguments to pass to ovs-vsctl.
            retry: Whether to use the --retry flag (ignored in transaction mode).
            timeout: Optional timeout in seconds for the command (ignored in transaction mode).
            skip_transaction: If True, execute immediately even when in transaction mode.
                This is useful for read-only commands (e.g., list, get) that should
                not be batched.

        Returns:
            The stdout output from the command, or empty string if in transaction mode
            and skip_transaction is False.

        Raises:
            OVSCommandError: If the command fails or ovs-vsctl is not found.
        """
        # In transaction mode, store the command for later execution (unless skipped)
        if self._in_transaction and not skip_transaction:
            self._transaction_commands.append(list(args))
            return ""

        return self._execute_vsctl(list(args), retry=retry, timeout=timeout)

    def list_bridges(self) -> list[str]:
        """Return the list of bridges currently present in OVS.

        Returns:
            Sorted list of bridge names.
        """
        output = self.vsctl("list-br", skip_transaction=True)
        return sorted({bridge for bridge in output.splitlines() if bridge.strip()})

    def list_bridge_interfaces(self, bridge: str) -> list[str]:
        """Return interfaces attached to a bridge.

        Args:
            bridge: Name of the bridge to query.

        Returns:
            Sorted list of interface names attached to the bridge.
        """
        output = self.vsctl("list-ifaces", bridge, skip_transaction=True)
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
            skip_transaction=True,
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
            raw_value = self.vsctl(
                "get",
                "open",
                ".",
                "external_ids:ovn-bridge-mappings",
                skip_transaction=True,
            )
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

    def set(self, table: str, record: str, column: str, settings: dict[str, str]) -> None:
        """Set column values in an OVS table.

        Args:
            table: OVS table name (e.g., 'open', 'Open_vSwitch', 'Port').
            record: Record to modify.
            column: Column to modify (e.g., 'external_ids', 'other_config').
            settings: Dictionary of key=value pairs to set.

        Raises:
            OVSCommandError: If the command fails.
        """
        if not settings:
            logging.warning("No ovs values to set, skipping...")
            return

        args = ["set", table, record]
        for key, value in settings.items():
            args.append(f"{column}:{key}={value}")
        self.vsctl(*args)

    def list_table(self, table: str, record: str, columns: list[str] | None = None) -> dict:
        """List table entries and parse JSON output.

        Args:
            table: OVS table name.
            record: Record to query.
            columns: Optional list of column names to retrieve.

        Returns:
            Dictionary of parsed table data.

        Raises:
            OVSCommandError: If the command fails.
        """
        args = ["--format", "json", "--if-exists"]
        if columns:
            args.append(f"--columns={','.join(columns)}")
        args.extend(["list", table, record])

        try:
            output = self.vsctl(*args, skip_transaction=True)
        except OVSCommandError:
            # The columns may not exist. --if-exists only applies to the record, not columns.
            return {}

        raw_json = json.loads(output)
        headings = raw_json["headings"]
        data = raw_json["data"]

        parsed = {}
        # We've requested a single record.
        for record_data in data:
            for position, heading in enumerate(headings):
                parsed[heading] = _parse_ovsdb_data(record_data[position])

        return parsed

    def find(self, table: str, *conditions: str) -> dict:
        """Find rows in a table matching conditions and parse JSON output.

        Args:
            table: OVS table name.
            *conditions: Query conditions (e.g., "external-ids:key=value").

        Returns:
            Dictionary with 'headings' and 'data' keys from JSON output.

        Raises:
            OVSCommandError: If the command fails.
        """
        args = ["-f", "json", "find", table]
        args.extend(conditions)
        output = self.vsctl(*args, skip_transaction=True)
        return json.loads(output)

    def add_bridge(self, bridge_name: str, datapath_type: str = "system", *cmd_args: str) -> None:
        """Add a bridge to OVS.

        Args:
            bridge_name: Name of the bridge to add.
            datapath_type: Datapath type ("system" or "netdev").
            *cmd_args: Additional arguments to pass (e.g., "protocols=OpenFlow13").

        Raises:
            OVSCommandError: If the command fails.
        """
        args = [
            "--may-exist",
            "add-br",
            bridge_name,
            "--",
            "set",
            "bridge",
            bridge_name,
            f"datapath_type={datapath_type}",
        ]
        args.extend(cmd_args)
        self.vsctl(*args)

    def del_bridge(self, bridge_name: str) -> None:
        """Delete a bridge from OVS.

        Args:
            bridge_name: Name of the bridge to delete.

        Raises:
            OVSCommandError: If the command fails.
        """
        self.vsctl("del-br", bridge_name)

    def add_port(
        self,
        bridge_name: str,
        port_name: str,
        port_type: str | None = None,
        options: dict[str, str] | None = None,
        external_ids: dict[str, str] | None = None,
        mtu: int | None = None,
    ) -> None:
        """Add a port to a bridge.

        Args:
            bridge_name: Name of the bridge.
            port_name: Name of the port to add.
            port_type: Optional port type (e.g., "dpdk", "patch").
            options: Optional port options dictionary.
            external_ids: Optional external IDs dictionary.
            mtu: Optional MTU value.

        Raises:
            OVSCommandError: If the command fails.
        """
        args = ["--may-exist", "add-port", bridge_name, port_name]

        set_interface = ["--", "set", "Interface", port_name]
        if port_type:
            args.extend(set_interface + [f"type={port_type}"])
        if mtu:
            args.extend(set_interface + [f"mtu-request={mtu}"])
        if options:
            args.extend(set_interface)
            for key, value in options.items():
                args.append(f"options:{key}={value}")
        if external_ids:
            args.extend(["--", "set", "Port", port_name])
            for key, value in external_ids.items():
                args.append(f"external_ids:{key}={value}")

        self.vsctl(*args)

    def del_port(self, bridge_name: str, port_name: str) -> None:
        """Delete a port from a bridge.

        Args:
            bridge_name: Name of the bridge.
            port_name: Name of the port to delete.

        Raises:
            OVSCommandError: If the command fails.
        """
        self.vsctl("--if-exists", "del-port", bridge_name, port_name)

    def add_bond(
        self,
        bridge_name: str,
        bond_name: str,
        ports: list[str],
        bond_mode: str | None = None,
        lacp_mode: str | None = None,
        lacp_time: str | None = None,
    ) -> None:
        """Add a bond to a bridge.

        Args:
            bridge_name: Name of the bridge.
            bond_name: Name of the bond to create.
            ports: List of port names to include in the bond.
            bond_mode: Bond mode (e.g., "balance-tcp", "active-backup").
            lacp_mode: LACP mode ("active", "passive", or "off").
            lacp_time: LACP time ("fast" or "slow").

        Raises:
            OVSCommandError: If the command fails.
        """
        args = ["--may-exist", "add-bond", bridge_name, bond_name]
        args.extend(ports)

        # Build arguments for port settings after bond creation
        if bond_mode or lacp_mode or lacp_time:
            args.extend(["--", "set", "port", bond_name])

            if bond_mode:
                args.append(f"bond_mode={bond_mode}")

            if lacp_mode:
                args.append(f"lacp={lacp_mode}")

            if lacp_time:
                args.append(f"other-config:lacp-time={lacp_time}")

        self.vsctl(*args)

    def set_check(self, table: str, record: str, column: str, settings: dict[str, str]) -> bool:
        """Apply settings and return whether changes were made.

        Args:
            table: OVS table name.
            record: Record to modify.
            column: Column to modify.
            settings: Dictionary of settings to apply.

        Returns:
            True if changes were made, False otherwise.

        Raises:
            OVSCommandError: If the command fails.
        """
        config_changed = False
        current_values = self.list_table(table, record, [column]).get(column, {})
        for key, new_val in settings.items():
            if key not in current_values or str(new_val) != str(current_values[key]):
                config_changed = True

        if config_changed:
            self.set(table, record, column, settings)

        return config_changed

    def remove(self, table: str, record: str, column: str, key: str) -> bool:
        """Remove a key from a column in an OVS table.

        This method is idempotent - it will not raise an error if the key
        doesn't exist.

        Args:
            table: OVS table name.
            record: Record to modify.
            column: Column name (e.g., 'external_ids', 'other_config').
            key: Key to remove from the column.

        Returns:
            True if the key was removed, False if it didn't exist.

        Raises:
            OVSCommandError: If the command fails for reasons other than missing key.
        """
        args = ["remove", table, record, column, key]
        try:
            self.vsctl(*args)
            logging.debug("Removed %s:%s from %s.%s", column, key, table, record)
            return True
        except OVSCommandError as exc:
            # Check if error is due to key not existing
            error_msg = str(exc).lower()
            if "not found" in error_msg or "no such key" in error_msg:
                logging.debug("Key %s not found in %s.%s, treating as no-op", key, table, record)
                return False
            # Re-raise if it's a different error
            raise

    def set_ssl(self, private_key: str, certificate: str, ca_cert: str) -> None:
        """Configure SSL for OVS.

        Args:
            private_key: Path to the private key file.
            certificate: Path to the certificate file.
            ca_cert: Path to the CA certificate file.

        Raises:
            OVSCommandError: If the command fails.
            FileNotFoundError: If any required file doesn't exist or is unreadable.
        """
        import os

        # Validate all files exist and are readable
        files = {
            "private key": private_key,
            "certificate": certificate,
            "CA certificate": ca_cert,
        }

        for file_type, file_path in files.items():
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"SSL {file_type} file not found: {file_path}")
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"SSL {file_type} path is not a file: {file_path}")
            if not os.access(file_path, os.R_OK):
                raise FileNotFoundError(f"SSL {file_type} file is not readable: {file_path}")

        logging.info("Configuring OVS SSL with certificate: %s", certificate)
        self.vsctl("set-ssl", private_key, certificate, ca_cert)


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
