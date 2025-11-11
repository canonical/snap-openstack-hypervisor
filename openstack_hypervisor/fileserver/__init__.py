# SPDX-FileCopyrightText: 2025 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0
"""Fileserver package for remote file operations over HTTP.

Exposes a small HTTP server and matching client used by the hypervisor
to transfer files between hosts.
"""

from .server import application

__all__ = [
    "application",
]
