# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import socket as pysocket

import click
from pydantic import ValidationError

from .schemas import (
    ActionType,
    AllocateCoresResponse,
    EpaRequest,
    ListAllocationsResponse,
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


def get_cpu_pinning_from_socket(
    snap_name: str,
    cores_requested: int = 0,
    socket_path: str = SOCKET_PATH,
) -> tuple[str, str]:
    """Get CPU pinning info from the epa-orchestrator snap via Unix socket."""
    request = EpaRequest(
        snap_name=snap_name, action=ActionType.ALLOCATE_CORES, cores_requested=cores_requested
    )

    try:
        with pysocket.socket(pysocket.AF_UNIX, pysocket.SOCK_STREAM) as s:
            s.connect(socket_path)
            s.sendall(request.json().encode())
            data = s.recv(4096)
            response = AllocateCoresResponse(**json.loads(data.decode()))

            if response.error:
                raise RuntimeError(f"EPA orchestrator error: {response.error}")

            return response.shared_cpus, response.allocated_cores

    except (ValidationError, Exception) as e:
        logging.error(f"Failed to get CPU pinning info from socket: {e}")
        return "", ""


def get_allocations_from_socket(
    socket_path: str = SOCKET_PATH,
) -> ListAllocationsResponse:
    """Get current allocations from the epa-orchestrator snap via Unix socket."""
    request = EpaRequest(
        snap_name="",  # Not needed for list action
        action=ActionType.LIST_ALLOCATIONS,
        cores_requested=None,
    )

    try:
        with pysocket.socket(pysocket.AF_UNIX, pysocket.SOCK_STREAM) as s:
            s.connect(socket_path)
            s.sendall(request.json().encode())
            data = s.recv(4096)
            response = ListAllocationsResponse(**json.loads(data.decode()))

            if response.error:
                raise RuntimeError(f"EPA orchestrator error: {response.error}")

            return response

    except (ValidationError, Exception) as e:
        logging.error(f"Failed to get allocations from socket: {e}")
        return ListAllocationsResponse(
            total_allocations=0,
            total_allocated_cpus=0,
            total_available_cpus=0,
            remaining_available_cpus=0,
            allocations=[],
        )
