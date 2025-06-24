# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

import json
import logging
import os
import socket as pysocket

import click
from pydantic import ValidationError

from .schemas import EpaRequest, EpaResponse

VALUE_FORMAT = "value"
JSON_FORMAT = "json"
JSON_INDENT_FORMAT = "json-indent"

click_option_format = click.option(
    "-f",
    "--format",
    default=JSON_FORMAT,
    type=click.Choice([VALUE_FORMAT, JSON_FORMAT, JSON_INDENT_FORMAT]),
    help="Output format",
)


def get_cpu_pinning_from_socket(
    cores_requested: int = 0,
    socket_path: str = os.path.join(os.environ.get("SNAP_DATA"), "data", "epa.sock"),
) -> tuple[str, str]:
    """Get CPU pinning info from the epa-orchestrator snap via Unix socket."""
    request = EpaRequest(cores_requested=cores_requested)

    try:
        with pysocket.socket(pysocket.AF_UNIX, pysocket.SOCK_STREAM) as s:
            s.connect(socket_path)
            s.sendall(request.json().encode())
            data = s.recv(4096)
            response = EpaResponse(**json.loads(data.decode()))

            if response.error:
                raise RuntimeError(f"EPA orchestrator error: {response.error}")

            return response.shared_cpus, response.vcpu_pin_set

    except (ValidationError, Exception) as e:
        logging.error(f"Failed to get CPU pinning info from socket: {e}")
        return "", ""
