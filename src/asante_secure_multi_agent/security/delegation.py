"""Trusted task-bound delegation for the Asante guest-credit workflow.

Agent SDK handoffs decide *who should work next*. Ruhusa delegation grants decide
*what authority that next agent actually receives*. Phase 4 additionally makes
the root grant come from an authenticated human and the agent grantees come from
trusted workload identity rather than caller-supplied names.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ruhusa import DelegationGrant, Scope, TaskContext

from asante_secure_multi_agent.identity import GUEST_SUPPORT_WORKLOAD, SUPERVISOR_WORKLOAD

from .runtime import AsanteSecurityRuntime

GUEST_CREDIT_ACTION = "guest.credit.issue"
RESERVATION_RESOURCE_PREFIX = "reservation:"
DEFAULT_SUPERVISOR_CREDIT_LIMIT = 100.0
DEFAULT_GUEST_SUPPORT_CREDIT_LIMIT = 25.0


def _credit_scope(limit: float) -> Scope:
    """Create the Ruhusa scope used for bounded guest-credit delegation."""
    if limit <= 0:
        raise ValueError("delegation limit must be greater than zero")
    return Scope(
        actions=frozenset({GUEST_CREDIT_ACTION}),
        resource_prefixes=(RESERVATION_RESOURCE_PREFIX,),
        max_numeric_arguments={"amount": float(limit)},
    )


def issue_guest_support_delegation(
    security: AsanteSecurityRuntime,
    task: TaskContext,
    *,
    supervisor_limit: float = DEFAULT_SUPERVISOR_CREDIT_LIMIT,
    guest_support_limit: float = DEFAULT_GUEST_SUPPORT_CREDIT_LIMIT,
) -> tuple[DelegationGrant, DelegationGrant]:
    """Issue authenticated-human -> supervisor -> guest-support authority.

    ``task.initiated_by`` must already contain the canonical human principal
    derived from authentication. Supervisor and Guest Support IDs are resolved
    from the trusted workload-identity provider held by the security runtime.
    """
    if guest_support_limit > supervisor_limit:
        raise ValueError("guest-support delegation cannot exceed supervisor authority")

    supervisor_id = security.workload_identities.require(SUPERVISOR_WORKLOAD).principal_id
    guest_support_id = security.workload_identities.require(GUEST_SUPPORT_WORKLOAD).principal_id

    now = datetime.now(UTC)
    expires_at = min(task.expires_at, now + timedelta(minutes=30))

    root_grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=task.initiated_by,
        grantee_id=supervisor_id,
        task_id=task.task_id,
        scope=_credit_scope(supervisor_limit),
        issued_at=now,
        expires_at=expires_at,
    )
    guest_support_grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=supervisor_id,
        grantee_id=guest_support_id,
        task_id=task.task_id,
        scope=_credit_scope(guest_support_limit),
        issued_at=now,
        expires_at=expires_at,
    )

    security.grant_store.register(root_grant)
    security.grant_store.register(guest_support_grant)
    return root_grant, guest_support_grant
