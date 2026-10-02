"""Trusted task-bound delegation for least-privilege Asante specialist agents.

Phase 9 separates orchestration from authority. The Supervisor may invoke several
specialists as bounded tools, but each specialist receives only the capability
scope needed for its business function. Ruhusa validates the resulting chain on
every protected action.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ruhusa import DelegationGrant, Scope, TaskContext

from asante_secure_multi_agent.identity import (
    APPROVAL_EXECUTOR_WORKLOAD,
    GUEST_SUPPORT_WORKLOAD,
    PROPERTY_OPERATIONS_WORKLOAD,
    RESERVATIONS_WORKLOAD,
    SERVICE_RECOVERY_WORKLOAD,
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
DEFAULT_SERVICE_RECOVERY_CREDIT_LIMIT = 25.0
DEFAULT_SERVICE_RECOVERY_APPROVAL_REQUEST_LIMIT = 100.0

# Compatibility names retained for callers that import the old constants.
DEFAULT_GUEST_SUPPORT_CREDIT_LIMIT = DEFAULT_SERVICE_RECOVERY_CREDIT_LIMIT
DEFAULT_GUEST_SUPPORT_APPROVAL_REQUEST_LIMIT = DEFAULT_SERVICE_RECOVERY_APPROVAL_REQUEST_LIMIT

_tracer = get_tracer()


def _credit_scope(limit: float) -> Scope:
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


def _maintenance_scope() -> Scope:
    return Scope(
        actions=frozenset({MAINTENANCE_CREATE_ACTION}),
        resource_prefixes=(RESERVATION_RESOURCE_PREFIX,),
    )


def _guest_message_scope() -> Scope:
    return Scope(
        actions=frozenset({GUEST_MESSAGE_SEND_ACTION}),
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
    child_workload: str,
    root_scope: Scope,
    child_scope: Scope,
) -> tuple[DelegationGrant, DelegationGrant]:
    supervisor_id = security.workload_identities.require(SUPERVISOR_WORKLOAD).principal_id
    child_id = security.workload_identities.require(child_workload).principal_id
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
    child_grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=supervisor_id,
        grantee_id=child_id,
        task_id=task.task_id,
        scope=child_scope,
        issued_at=now,
        expires_at=expires_at,
    )
    security.grant_store.register(root_grant)
    security.grant_store.register(child_grant)
    return root_grant, child_grant


def _issue_specialist_chain(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    workload: str,
    action: str,
    scope: Scope,
) -> tuple[DelegationGrant, DelegationGrant]:
    with _tracer.start_as_current_span(
        "asante.delegation.issue",
        attributes={
            "asante.delegation.depth": 2,
            "asante.delegation.action": action,
            "asante.delegation.specialist": workload,
        },
    ):
        return _issue_chain(
            security,
            task,
            child_workload=workload,
            root_scope=scope,
            child_scope=scope,
        )


def issue_reservations_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Delegate reservation-read authority only to the Reservations specialist."""
    return _issue_specialist_chain(
        security,
        task,
        workload=RESERVATIONS_WORKLOAD,
        action=RESERVATION_READ_ACTION,
        scope=_reservation_read_scope(),
    )


def issue_property_operations_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Delegate maintenance creation only to the Property Operations specialist."""
    return _issue_specialist_chain(
        security,
        task,
        workload=PROPERTY_OPERATIONS_WORKLOAD,
        action=MAINTENANCE_CREATE_ACTION,
        scope=_maintenance_scope(),
    )


def issue_guest_support_message_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Delegate outbound guest messaging only to the Guest Support specialist."""
    return _issue_specialist_chain(
        security,
        task,
        workload=GUEST_SUPPORT_WORKLOAD,
        action=GUEST_MESSAGE_SEND_ACTION,
        scope=_guest_message_scope(),
    )


def issue_service_recovery_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    supervisor_limit: float = DEFAULT_SUPERVISOR_CREDIT_LIMIT,
    service_recovery_limit: float = DEFAULT_SERVICE_RECOVERY_CREDIT_LIMIT,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Delegate bounded automatic credit authority to Service Recovery."""
    if service_recovery_limit > supervisor_limit:
        raise ValueError("service-recovery delegation cannot exceed supervisor authority")

    with _tracer.start_as_current_span(
        "asante.delegation.issue",
        attributes={
            "asante.delegation.depth": 2,
            "asante.delegation.action": GUEST_CREDIT_ACTION,
            "asante.delegation.specialist": SERVICE_RECOVERY_WORKLOAD,
            "asante.delegation.supervisor_limit": float(supervisor_limit),
            "asante.delegation.specialist_limit": float(service_recovery_limit),
        },
    ):
        return _issue_chain(
            security,
            task,
            child_workload=SERVICE_RECOVERY_WORKLOAD,
            root_scope=_credit_scope(supervisor_limit),
            child_scope=_credit_scope(service_recovery_limit),
        )


def issue_service_recovery_credit_request_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    limit: float = DEFAULT_SERVICE_RECOVERY_APPROVAL_REQUEST_LIMIT,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Delegate authority to request, but not approve, a larger guest credit."""
    with _tracer.start_as_current_span(
        "asante.delegation.issue",
        attributes={
            "asante.delegation.depth": 2,
            "asante.delegation.action": GUEST_CREDIT_REQUEST_ACTION,
            "asante.delegation.specialist": SERVICE_RECOVERY_WORKLOAD,
            "asante.delegation.request_limit": float(limit),
        },
    ):
        scope = _credit_request_scope(limit)
        return _issue_chain(
            security,
            task,
            child_workload=SERVICE_RECOVERY_WORKLOAD,
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


# Backward-compatible aliases for code/tests migrating from the Phase 8 names.
def issue_guest_support_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    supervisor_limit: float = DEFAULT_SUPERVISOR_CREDIT_LIMIT,
    guest_support_limit: float = DEFAULT_GUEST_SUPPORT_CREDIT_LIMIT,
) -> tuple[DelegationGrant, DelegationGrant]:
    return issue_service_recovery_delegation(
        security,
        task,
        supervisor_limit=supervisor_limit,
        service_recovery_limit=guest_support_limit,
    )


def issue_guest_support_reservation_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
) -> tuple[DelegationGrant, DelegationGrant]:
    return issue_reservations_delegation(security, task)


def issue_guest_support_credit_request_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    limit: float = DEFAULT_GUEST_SUPPORT_APPROVAL_REQUEST_LIMIT,
) -> tuple[DelegationGrant, DelegationGrant]:
    return issue_service_recovery_credit_request_delegation(security, task, limit=limit)


def issue_guest_support_service_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Legacy alias for guest-message authority; maintenance now has its own specialist."""
    return issue_guest_support_message_delegation(security, task)
