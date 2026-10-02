"""Least-privilege agent builders and stable safety instruction contracts."""

from .guest_support import GUEST_SUPPORT_INSTRUCTIONS, build_guest_support_agent
from .property_operations import (
    PROPERTY_OPERATIONS_INSTRUCTIONS,
    build_property_operations_agent,
)
from .reservations import RESERVATIONS_INSTRUCTIONS, build_reservations_agent
from .service_recovery import SERVICE_RECOVERY_INSTRUCTIONS, build_service_recovery_agent
from .supervisor import SUPERVISOR_INSTRUCTIONS, build_supervisor_agent

__all__ = [
    "GUEST_SUPPORT_INSTRUCTIONS",
    "PROPERTY_OPERATIONS_INSTRUCTIONS",
    "RESERVATIONS_INSTRUCTIONS",
    "SERVICE_RECOVERY_INSTRUCTIONS",
    "SUPERVISOR_INSTRUCTIONS",
    "build_guest_support_agent",
    "build_property_operations_agent",
    "build_reservations_agent",
    "build_service_recovery_agent",
    "build_supervisor_agent",
]
