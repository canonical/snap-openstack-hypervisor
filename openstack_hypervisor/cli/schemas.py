# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

from typing import Literal

from pydantic import BaseModel, Field

API_VERSION = "1.0"


class EpaRequest(BaseModel):
    """Pydantic model for epa request."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    cores_requested: int = Field(default=0, ge=0)


class EpaResponse(BaseModel):
    """Pydantic model for epa response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    shared_cpus: str
    vcpu_pin_set: str
    error: str = ""
