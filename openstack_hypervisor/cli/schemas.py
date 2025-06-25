# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0

"""Pydantic schemas for socket communication."""
from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

API_VERSION = "1.0"


class ActionType(str, Enum):
    """Enum for different action types."""

    ALLOCATE_CORES = "allocate_cores"
    LIST_ALLOCATIONS = "list_allocations"


class EpaRequest(BaseModel):
    """Pydantic model for epa request."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    snap_name: str = Field(description="Name of the requesting snap")
    action: ActionType = Field(description="Type of action to perform")
    cores_requested: Optional[int] = Field(
        default=None,
        ge=0,
        description=("Number of dedicated cores requested " "(only for allocate_cores)"),
    )

    @field_validator("cores_requested")
    @classmethod
    def validate_cores_requested(cls, v, info):
        """Validate and adjust the value of cores_requested based on the action type."""
        action = info.data.get("action")
        if action == ActionType.ALLOCATE_CORES and v is None:
            # For allocate_cores, if cores_requested is None, set it to 0
            # (which means 80% allocation)
            return 0
        elif action == ActionType.LIST_ALLOCATIONS and v is not None:
            # For list_allocations, cores_requested should be None or ignored
            return None
        return v


class AllocateCoresResponse(BaseModel):
    """Pydantic model for allocate cores response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    snap_name: str = Field(description="Name of the snap that was allocated cores")
    cores_requested: int = Field(description="Number of cores that were requested")
    cores_allocated: int = Field(description="Number of cores that were actually allocated")
    allocated_cores: str = Field(description="Comma-separated list of allocated CPU ranges")
    shared_cpus: str = Field(description="Comma-separated list of shared CPU ranges")
    total_available_cpus: int = Field(description="Total number of CPUs available in the system")
    remaining_available_cpus: int = Field(
        description="Number of CPUs still available for allocation"
    )
    error: str = ""


class SnapAllocation(BaseModel):
    """Model for snap allocation information."""

    snap_name: str = Field(description="Name of the snap")
    allocated_cores: str = Field(description="Comma-separated list of allocated CPU ranges")
    cores_count: int = Field(description="Number of cores allocated to this snap")


class ListAllocationsResponse(BaseModel):
    """Pydantic model for list allocations response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    total_allocations: int = Field(description="Total number of snap allocations")
    total_allocated_cpus: int = Field(
        description="Total number of CPUs allocated across all snaps"
    )
    total_available_cpus: int = Field(description="Total number of CPUs available in the system")
    remaining_available_cpus: int = Field(
        description="Number of CPUs still available for allocation"
    )
    allocations: List[SnapAllocation] = Field(description="List of all snap allocations")
    error: str = ""
