# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import socket as pysocket
from typing import TypeVar, Union

import click
from pydantic import BaseModel

from .schemas import (
    ActionType,
    AllocateCoresRequest,
    AllocateCoresResponse,
    ListAllocationsRequest,
)

VALUE_FORMAT = "value"
JSON_FORMAT = "json"
JSON_INDENT_FORMAT = "json-indent"
TABLE_FORMAT = "table"

SOCKET_FILENAME = "epa.sock"
SOCKET_PATH = os.path.join(os.environ["SNAP_DATA"], "data", SOCKET_FILENAME)
click_option_format = click.option(
    "-f",
    "--format",
    default=JSON_FORMAT,
    type=click.Choice([VALUE_FORMAT, JSON_FORMAT, JSON_INDENT_FORMAT]),
    help="Output format",
)

T = TypeVar("T", bound=BaseModel)


class SocketCommunicationError(Exception):
    """Exception raised when socket communication fails."""

    pass


class EPAOrchestratorError(Exception):
    """Exception raised when the EPA orchestrator returns an error."""

    pass


def _communicate_with_socket(
    request: Union[AllocateCoresRequest, ListAllocationsRequest],
    response_model: type[T],
    socket_path: str = SOCKET_PATH,
) -> T:
    """Helper function for socket communication with EPA orchestrator.

    Args:
        request: The request to send to the EPA orchestrator
        response_model: The expected response model type
        socket_path: Path to the Unix socket

    Returns:
        The parsed response from the EPA orchestrator

    Raises:
        SocketCommunicationError: If socket communication fails (connection,
                                 data transmission, or validation errors)
        EPAOrchestratorError: If the EPA orchestrator returns an error response
    """
    try:
        with pysocket.socket(pysocket.AF_UNIX, pysocket.SOCK_STREAM) as s:
            s.connect(socket_path)
            s.sendall(request.json().encode())
            data = s.recv(4096)
            response_dict = json.loads(data.decode())
            if "error" in response_dict:
                raise EPAOrchestratorError(response_dict["error"])
            response = response_model(**response_dict)
            return response
    except (pysocket.error, OSError) as e:
        raise SocketCommunicationError(f"Socket communication failed: {e}")


def get_cpu_pinning_from_socket(
    service_name: str,
    cores_requested: int = 0,
    socket_path: str = SOCKET_PATH,
) -> tuple[str, str]:
    """Get CPU pinning info from the epa-orchestrator snap via Unix socket.

    This function communicates with the EPA orchestrator to request CPU core allocation
    and returns the shared and allocated CPU sets for the requesting snap.

    Args:
        service_name: Name of the service requesting CPU allocation
        cores_requested: Number of dedicated cores requested (0 means default allocation)
        socket_path: Path to the Unix socket for EPA orchestrator communication

    Returns:
        A tuple containing (shared_cpus, allocated_cores) where both are
        comma-separated CPU range strings

    Raises:
        SocketCommunicationError: If socket communication fails (connection issues,
            data transmission errors, or validation failures)
        EPAOrchestratorError: If the EPA orchestrator returns an error response
    """
    request = AllocateCoresRequest(
        service_name=service_name,
        action=ActionType.ALLOCATE_CORES,
        cores_requested=cores_requested,
    )
    try:
        response = _communicate_with_socket(request, AllocateCoresResponse, socket_path)
        return (response.shared_cpus, response.allocated_cores)
    except (SocketCommunicationError, EPAOrchestratorError) as e:
        logging.error("Failed to get CPU pinning info from socket: {}".format(e))
        raise
