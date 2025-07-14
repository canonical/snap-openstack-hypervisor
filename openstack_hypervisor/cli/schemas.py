# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0
"""Pydantic schemas for socket communication."""
from enum import Enum
from typing import Annotated, List, Literal, Union

from pydantic import BaseModel, Field

API_VERSION: Literal["1.0"] = "1.0"


class ActionType(str, Enum):
    """Enum for different action types."""

    ALLOCATE_CORES = "allocate_cores"
    LIST_ALLOCATIONS = "list_allocations"


class AllocateCoresRequest(BaseModel):
    """Request model for allocating cores."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    action: Literal[ActionType.ALLOCATE_CORES]
    service_name: str = Field(description="Name of the requesting service")
    cores_requested: int = Field(
        default=0,
        ge=0,
        description="Number of dedicated cores requested (0 means default allocation)",
    )


class ListAllocationsRequest(BaseModel):
    """Request model for listing allocations."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    action: Literal[ActionType.LIST_ALLOCATIONS]
    service_name: str = Field(description="Name of the requesting service")


EpaRequest = Annotated[
    Union[AllocateCoresRequest, ListAllocationsRequest],
    Field(discriminator="action"),
]


class AllocateCoresResponse(BaseModel):
    """Pydantic model for allocate cores response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    service_name: str = Field(description="Name of the service that was allocated cores")
    cores_requested: int = Field(description="Number of cores that were requested")
    cores_allocated: int = Field(description="Number of cores that were actually allocated")
    allocated_cores: str = Field(description="Comma-separated list of allocated CPU ranges")
    shared_cpus: str = Field(description="Comma-separated list of shared CPU ranges")
    total_available_cpus: int = Field(description="Total number of CPUs available in the system")
    remaining_available_cpus: int = Field(
        description="Number of CPUs still available for allocation"
    )


class SnapAllocation(BaseModel):
    """Model for service allocation information."""

    service_name: str = Field(description="Name of the service")
    allocated_cores: str = Field(description="Comma-separated list of allocated CPU ranges")
    cores_count: int = Field(description="Number of cores allocated to this service")


class ListAllocationsResponse(BaseModel):
    """Pydantic model for list allocations response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    total_allocations: int = Field(description="Total number of service allocations")
    total_allocated_cpus: int = Field(
        description="Total number of CPUs allocated across all services"
    )
    total_available_cpus: int = Field(description="Total number of CPUs available in the system")
    remaining_available_cpus: int = Field(
        description="Number of CPUs still available for allocation"
    )
    allocations: List[SnapAllocation] = Field(description="List of all service allocations")


class ErrorResponse(BaseModel):
    """Pydantic model for error responses."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    error: str
