"""Typed runtime context shared across the Asante agent handoff."""

from __future__ import annotations

from dataclasses import dataclass

from ruhusa import DelegationGrant, TaskContext


@dataclass(frozen=True)
class AsanteRunContext:
    """Trusted task and delegation state carried through one agent run."""

    task: TaskContext
    guest_support_delegation: tuple[DelegationGrant, ...]
