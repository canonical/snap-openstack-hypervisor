# SPDX-FileCopyrightText: 2026 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import ipaddress
import re
from pathlib import Path

REQUIRED_CONNECTIONS = ("OVN_NB_CONNECT", "OVN_SB_CONNECT")
SUPPORTED_PROTOCOLS = frozenset(("ssl", "tcp"))

_ASSIGNMENT = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<quote>['\"])(?P<value>.*)(?P=quote)"
)
_IPV4_ENDPOINT = re.compile(r"(?P<host>[^:]+):(?P<port>[0-9]+)")
_IPV6_ENDPOINT = re.compile(r"\[(?P<host>[^]]+)\]:(?P<port>[0-9]+)")


class OVNEnvError(ValueError):
    """Raised when MicroOVN's generated environment is unavailable or invalid."""


def _validate_endpoint(endpoint: str, connection_name: str) -> None:
    """Validate one MicroOVN-generated OVSDB endpoint."""
    if not endpoint or any(character.isspace() for character in endpoint):
        raise OVNEnvError(f"Invalid endpoint in {connection_name}")

    try:
        protocol, address = endpoint.split(":", 1)
    except ValueError as exc:
        raise OVNEnvError(f"Invalid endpoint in {connection_name}") from exc
    if protocol not in SUPPORTED_PROTOCOLS:
        raise OVNEnvError(f"Unsupported endpoint protocol in {connection_name}")

    ipv6 = address.startswith("[")
    match = (_IPV6_ENDPOINT if ipv6 else _IPV4_ENDPOINT).fullmatch(address)
    if match is None:
        raise OVNEnvError(f"Invalid endpoint address in {connection_name}")

    try:
        parsed_address = ipaddress.ip_address(match.group("host"))
    except ValueError as exc:
        raise OVNEnvError(f"Invalid endpoint address in {connection_name}") from exc
    if ipv6 != (parsed_address.version == 6):
        raise OVNEnvError(f"Invalid endpoint address in {connection_name}")

    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        raise OVNEnvError(f"Invalid endpoint port in {connection_name}")


def _validate_connection(connection: str, connection_name: str) -> None:
    """Validate every endpoint in a comma-separated connection string."""
    endpoints = connection.split(",")
    if not endpoints:
        raise OVNEnvError(f"Empty required assignment: {connection_name}")
    for endpoint in endpoints:
        _validate_endpoint(endpoint, connection_name)


def _read_lines(path: Path) -> list[str]:
    """Read the environment as UTF-8 without interpreting its contents."""
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise OVNEnvError("Unable to read OVN environment file") from exc


def _parse_required_assignments(lines: list[str]) -> dict[str, str]:
    """Extract required quoted assignments and reject malformed input."""
    connections: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        match = _ASSIGNMENT.fullmatch(line)
        if match is None:
            raise OVNEnvError(f"Malformed assignment on line {line_number}")

        name = match.group("name")
        if name not in REQUIRED_CONNECTIONS:
            continue
        if name in connections:
            raise OVNEnvError(f"Duplicate required assignment: {name}")

        value = match.group("value")
        if not value:
            raise OVNEnvError(f"Empty required assignment: {name}")
        connections[name] = value

    missing = [name for name in REQUIRED_CONNECTIONS if name not in connections]
    if missing:
        raise OVNEnvError(f"Missing required assignment: {', '.join(missing)}")
    return connections


def parse_ovn_env(path: Path) -> dict[str, str]:
    """Strictly parse required OVN connections without executing the file."""
    connections = _parse_required_assignments(_read_lines(path))

    for name, connection in connections.items():
        _validate_connection(connection, name)
    return connections
