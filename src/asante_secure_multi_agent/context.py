"""Typed trusted runtime context shared across the Asante agent workflow."""

from __future__ import annotations

from dataclasses import dataclass

from ruhusa import DelegationGrant, TaskContext


@dataclass(frozen=True)
class AsanteRunContext:
    """Trusted task and specialist-specific delegation state for one agent run."""

    task: TaskContext
    reservations_delegation: tuple[DelegationGrant, ...]
    property_operations_delegation: tuple[DelegationGrant, ...]
    guest_support_message_delegation: tuple[DelegationGrant, ...]
    service_recovery_delegation: tuple[DelegationGrant, ...]
    service_recovery_credit_request_delegation: tuple[DelegationGrant, ...]
