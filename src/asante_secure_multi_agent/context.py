"""Typed runtime context shared across the Asante agent handoff."""

from __future__ import annotations

from dataclasses import dataclass

from ruhusa import DelegationGrant, TaskContext


@dataclass(frozen=True)
class AsanteRunContext:
    """Trusted task and capability-specific delegation state for one agent run."""

    task: TaskContext
    guest_support_delegation: tuple[DelegationGrant, ...]
    guest_support_reservation_delegation: tuple[DelegationGrant, ...] | None = None
    guest_support_service_delegation: tuple[DelegationGrant, ...] | None = None
    guest_support_credit_request_delegation: tuple[DelegationGrant, ...] | None = None
