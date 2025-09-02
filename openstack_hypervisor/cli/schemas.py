# SPDX-FileCopyrightText: 2024 - Canonical Ltd
# SPDX-License-Identifier: Apache-2.0
"""Pydantic schemas for socket communication."""
from enum import Enum
from typing import Annotated, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator

API_VERSION: Literal["1.0"] = "1.0"


class ActionType(str, Enum):
    """Enum for different action types."""

    ALLOCATE_CORES = "allocate_cores"
    LIST_ALLOCATIONS = "list_allocations"
    ALLOCATE_NUMA_CORES = "allocate_numa_cores"
    GET_MEMORY_INFO = "get_memory_info"
    ALLOCATE_HUGEPAGES = "allocate_hugepages"


class AllocateCoresRequest(BaseModel):
    """Request model for allocating cores (non-NUMA)."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    action: Literal[ActionType.ALLOCATE_CORES]
    service_name: str = Field(description="Name of the requesting service")
    num_of_cores: int = Field(
        default=0,
        description=("Number of dedicated cores requested. 0 keeps default policy."),
    )
    numa_node: Optional[int] = Field(
        default=None, ge=0, description="NUMA node (must be omitted for allocate_cores)"
    )


class ListAllocationsRequest(BaseModel):
    """Request model for listing allocations."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    action: Literal[ActionType.LIST_ALLOCATIONS]
    service_name: str = Field(description="Name of the requesting service")


class AllocateNumaCoresRequest(BaseModel):
    """Request model for allocating cores from a specific NUMA node.

    Note:
        - num_of_cores > 0: allocate exactly that many cores from the node
        - num_of_cores == -1: deallocate existing cores for this service in the node
        - num_of_cores == 0: invalid
    """

    version: Literal["1.0"] = Field(default=API_VERSION)
    action: Literal[ActionType.ALLOCATE_NUMA_CORES]
    service_name: str = Field(description="Name of the requesting service")
    numa_node: int = Field(ge=0, description="NUMA node to allocate cores from")
    num_of_cores: int = Field(description="Number of cores to allocate (-1 to deallocate)")


class GetMemoryInfoRequest(BaseModel):
    """Request model for getting memory information."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    action: Literal[ActionType.GET_MEMORY_INFO]
    service_name: str = Field(description="Name of the requesting service")


class AllocateHugepagesRequest(BaseModel):
    """Request model for allocating hugepages for a specific NUMA node and size."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    action: Literal[ActionType.ALLOCATE_HUGEPAGES]
    service_name: str = Field(description="Name of the requesting service")
    hugepages_requested: int = Field(
        description=("Number of hugepages to allocate (>0) or -1 to deallocate; 0 is invalid"),
    )
    node_id: int = Field(
        ge=0,
        description="NUMA node id for per-node allocation",
    )
    size_kb: int = Field(
        gt=0,
        description="Hugepage size in KB (e.g., 2048)",
    )

    @field_validator("hugepages_requested")
    @classmethod
    def validate_hugepages_requested(cls, v: int) -> int:
        """Disallow 0; allow positive values and -1 for deallocation."""
        if v == 0:
            raise ValueError("hugepages_requested=0 is invalid for allocate_hugepages")
        return v


EpaRequest = Annotated[
    Union[
        AllocateCoresRequest,
        AllocateNumaCoresRequest,
        ListAllocationsRequest,
        GetMemoryInfoRequest,
        AllocateHugepagesRequest,
    ],
    Field(discriminator="action"),
]


class AllocateCoresResponse(BaseModel):
    """Pydantic model for allocate cores response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    service_name: str = Field(description="Name of the service that was allocated cores")
    num_of_cores: int = Field(description="Number of cores that were requested")
    cores_allocated: int = Field(description="Number of cores that were actually allocated")
    allocated_cores: str = Field(description="Comma-separated list of allocated CPU ranges")
    shared_cpus: str = Field(description="Comma-separated list of shared CPU ranges")
    total_available_cpus: int = Field(description="Total number of CPUs available in the system")
    remaining_available_cpus: int = Field(
        description="Number of CPUs still available for allocation"
    )


class AllocateNumaCoresResponse(BaseModel):
    """Pydantic model for NUMA allocate cores response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    service_name: str = Field(description="Name of the service that was allocated cores")
    numa_node: int = Field(description="NUMA node cores were allocated from")
    num_of_cores: int = Field(description="Number of cores that were requested (or -1 to dealloc)")
    cores_allocated: str = Field(description="Cores that were actually allocated")
    total_available_cpus: int = Field(description="Total number of CPUs available in the system")
    remaining_available_cpus: int = Field(
        description="Number of CPUs still available for allocation"
    )


class SnapAllocation(BaseModel):
    """Model for service allocation information."""

    service_name: str = Field(description="Name of the service")
    allocated_cores: str = Field(description="Comma-separated list of allocated CPU ranges")
    cores_count: int = Field(description="Number of cores allocated to this service")
    is_explicit: bool = Field(
        default=False, description="Whether this allocation was made explicitly"
    )


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


class HugepageAllocationEntry(BaseModel):
    """Single hugepage allocation entry for a service."""

    node_id: int
    size_kb: int
    count: int


class ServiceHugepageAllocations(BaseModel):
    """All hugepage allocations for a single service."""

    service_name: str
    allocations: List[HugepageAllocationEntry]


class NodeHugepageAllocation(BaseModel):
    """Flattened entry for allocations on a specific node."""

    service_name: str
    size_kb: int
    count: int


class UsageEntry(BaseModel):
    """Usage entry for a specific hugepage size on a node."""

    total: int
    free: int
    size: int


class NodeHugepagesInfo(BaseModel):
    """Per-node hugepages info with capacity list and allocations."""

    capacity: List[UsageEntry]
    allocations: Dict[str, Dict[str, int]]


class MemoryInfoResponse(BaseModel):
    """Pydantic model for NUMA hugepages information response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    service_name: str = Field(description="Name of the requesting service")
    numa_hugepages: Dict[str, NodeHugepagesInfo] = Field(
        default_factory=dict, description="Per-NUMA hugepages info keyed by node name"
    )


class AllocateHugepagesResponse(BaseModel):
    """Pydantic model for hugepage allocation response."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    service_name: str = Field(description="Name of the requesting service")
    hugepages_requested: int = Field(description="Number of hugepages requested")
    allocation_successful: bool = Field(description="Whether allocation was successful")
    message: str = Field(description="Allocation result message")
    node_id: int = Field(description="NUMA node targeted")
    size_kb: int = Field(description="Hugepage size targeted in KB")


class ErrorResponse(BaseModel):
    """Pydantic model for error responses."""

    version: Literal["1.0"] = Field(default=API_VERSION)
    error: str
