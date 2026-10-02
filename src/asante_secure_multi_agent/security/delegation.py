"""Trusted task-bound delegation for Asante guest operations.

Agent SDK handoffs decide *who should work next*. Ruhusa delegation grants decide
*what authority that next agent actually receives*. Capability-specific chains
keep credit, reservation-read, service-operation, and approval-execution scope
separate so constraints do not bleed across tools.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ruhusa import DelegationGrant, Scope, TaskContext

from asante_secure_multi_agent.identity import (
    APPROVAL_EXECUTOR_WORKLOAD,
    GUEST_SUPPORT_WORKLOAD,
    SUPERVISOR_WORKLOAD,
)
from asante_secure_multi_agent.telemetry import get_tracer

from .runtime import AsanteSecurityRuntime

GUEST_CREDIT_ACTION = "guest.credit.issue"
RESERVATION_READ_ACTION = "reservation.read"
MAINTENANCE_CREATE_ACTION = "maintenance.create"
GUEST_MESSAGE_SEND_ACTION = "guest.message.send"
GUEST_CREDIT_REQUEST_ACTION = "guest.credit.request"
APPROVED_CREDIT_ACTION = "guest.credit.issue.approved"
RESERVATION_RESOURCE_PREFIX = "reservation:"
DEFAULT_SUPERVISOR_CREDIT_LIMIT = 100.0
DEFAULT_GUEST_SUPPORT_CREDIT_LIMIT = 25.0
DEFAULT_GUEST_SUPPORT_APPROVAL_REQUEST_LIMIT = 100.0

_tracer = get_tracer()


def _credit_scope(limit: float) -> Scope:
    """Create bounded guest-credit delegation scope."""
    if limit <= 0:
        raise ValueError("delegation limit must be greater than zero")
    return Scope(
        actions=frozenset({GUEST_CREDIT_ACTION}),
        resource_prefixes=(RESERVATION_RESOURCE_PREFIX,),
        max_numeric_arguments={"amount": float(limit)},
    )


def _reservation_read_scope() -> Scope:
    return Scope(
        actions=frozenset({RESERVATION_READ_ACTION}),
        resource_prefixes=(RESERVATION_RESOURCE_PREFIX,),
    )


def _service_operations_scope() -> Scope:
    return Scope(
        actions=frozenset({MAINTENANCE_CREATE_ACTION, GUEST_MESSAGE_SEND_ACTION}),
        resource_prefixes=(RESERVATION_RESOURCE_PREFIX,),
    )


def _credit_request_scope(limit: float) -> Scope:
    if limit <= 0:
        raise ValueError("approval request limit must be greater than zero")
    return Scope(
        actions=frozenset({GUEST_CREDIT_REQUEST_ACTION}),
        resource_prefixes=(RESERVATION_RESOURCE_PREFIX,),
        max_numeric_arguments={"amount": float(limit)},
    )


def _approved_credit_scope(limit: float) -> Scope:
    if limit <= 0:
        raise ValueError("approved credit limit must be greater than zero")
    return Scope(
        actions=frozenset({APPROVED_CREDIT_ACTION}),
        resource_prefixes=(RESERVATION_RESOURCE_PREFIX,),
        max_numeric_arguments={"amount": float(limit)},
    )


def _issue_chain(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    root_scope: Scope,
    child_scope: Scope,
) -> tuple[DelegationGrant, DelegationGrant]:
    supervisor_id = security.workload_identities.require(SUPERVISOR_WORKLOAD).principal_id
    guest_support_id = security.workload_identities.require(GUEST_SUPPORT_WORKLOAD).principal_id
    now = datetime.now(UTC)
    expires_at = min(task.expires_at, now + timedelta(minutes=30))

    root_grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=task.initiated_by,
        grantee_id=supervisor_id,
        task_id=task.task_id,
        scope=root_scope,
        issued_at=now,
        expires_at=expires_at,
    )
    guest_support_grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=supervisor_id,
        grantee_id=guest_support_id,
        task_id=task.task_id,
        scope=child_scope,
        issued_at=now,
        expires_at=expires_at,
    )
    security.grant_store.register(root_grant)
    security.grant_store.register(guest_support_grant)
    return root_grant, guest_support_grant


def issue_guest_support_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    supervisor_limit: float = DEFAULT_SUPERVISOR_CREDIT_LIMIT,
    guest_support_limit: float = DEFAULT_GUEST_SUPPORT_CREDIT_LIMIT,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Issue authenticated-human -> supervisor -> guest-support credit authority."""
    if guest_support_limit > supervisor_limit:
        raise ValueError("guest-support delegation cannot exceed supervisor authority")

    with _tracer.start_as_current_span(
        "asante.delegation.issue",
        attributes={
            "asante.delegation.depth": 2,
            "asante.delegation.action": GUEST_CREDIT_ACTION,
            "asante.delegation.supervisor_limit": float(supervisor_limit),
            "asante.delegation.guest_support_limit": float(guest_support_limit),
        },
    ):
        return _issue_chain(
            security,
            task,
            root_scope=_credit_scope(supervisor_limit),
            child_scope=_credit_scope(guest_support_limit),
        )


def issue_guest_support_reservation_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Issue a separate task-bound chain for reservation-read authority."""
    with _tracer.start_as_current_span(
        "asante.delegation.issue",
        attributes={
            "asante.delegation.depth": 2,
            "asante.delegation.action": RESERVATION_READ_ACTION,
        },
    ):
        scope = _reservation_read_scope()
        return _issue_chain(
            security,
            task,
            root_scope=scope,
            child_scope=scope,
        )


def issue_guest_support_service_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Delegate maintenance creation and guest messaging to Guest Support."""
    with _tracer.start_as_current_span(
        "asante.delegation.issue",
        attributes={
            "asante.delegation.depth": 2,
            "asante.delegation.action": "guest_service_operations",
        },
    ):
        scope = _service_operations_scope()
        return _issue_chain(
            security,
            task,
            root_scope=scope,
            child_scope=scope,
        )


def issue_guest_support_credit_request_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    limit: float = DEFAULT_GUEST_SUPPORT_APPROVAL_REQUEST_LIMIT,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Delegate authority to request, but not execute, a larger guest credit."""
    with _tracer.start_as_current_span(
        "asante.delegation.issue",
        attributes={
            "asante.delegation.depth": 2,
            "asante.delegation.action": GUEST_CREDIT_REQUEST_ACTION,
            "asante.delegation.request_limit": float(limit),
        },
    ):
        scope = _credit_request_scope(limit)
        return _issue_chain(
            security,
            task,
            root_scope=scope,
            child_scope=scope,
        )


def issue_approval_executor_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    limit: float = 100.0,
) -> tuple[DelegationGrant, ...]:
    """Delegate an authenticated human approval to the trusted executor service."""
    executor_id = security.workload_identities.require(APPROVAL_EXECUTOR_WORKLOAD).principal_id
    now = datetime.now(UTC)
    expires_at = min(task.expires_at, now + timedelta(minutes=10))
    grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=task.initiated_by,
        grantee_id=executor_id,
        task_id=task.task_id,
        scope=_approved_credit_scope(limit),
        issued_at=now,
        expires_at=expires_at,
    )
    security.grant_store.register(grant)
    return (grant,)
