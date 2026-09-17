"""Trusted task-bound delegation for the Asante guest-credit workflow.

Agent SDK handoffs decide *who should work next*. Ruhusa delegation grants decide
*what authority that next agent actually receives*. Keeping those concepts
separate prevents a model-level handoff from becoming an implicit privilege
transfer.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ruhusa import DelegationGrant, Scope, TaskContext

from .runtime import GUEST_SUPPORT_AGENT_ID, SUPERVISOR_AGENT_ID, AsanteSecurityRuntime

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
    """Issue and register a canonical human -> supervisor -> guest-support chain.

    ``task.initiated_by`` is the authority origin. The supervisor receives a
    task-bound credit scope, then delegates a subset of that authority to Guest
    Support. The application-side issuer refuses obvious widening before
    registration; Ruhusa independently validates attenuation again at use time.

    Args:
        security: Runtime holding the trusted canonical grant registry.
        task: Task whose initiating human/service is the root authority source.
        supervisor_limit: Maximum credit authority given to the Supervisor.
        guest_support_limit: Maximum credit authority delegated to Guest Support.

    Returns:
        The canonical root and child grants in delegation-chain order.

    Raises:
        ValueError: The requested child limit would widen its parent's authority.
    """
    if guest_support_limit > supervisor_limit:
        raise ValueError("guest-support delegation cannot exceed supervisor authority")

    now = datetime.now(UTC)
    expires_at = min(task.expires_at, now + timedelta(minutes=30))

    root_grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=task.initiated_by,
        grantee_id=SUPERVISOR_AGENT_ID,
        task_id=task.task_id,
        scope=_credit_scope(supervisor_limit),
        issued_at=now,
        expires_at=expires_at,
    )
    guest_support_grant = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=SUPERVISOR_AGENT_ID,
        grantee_id=GUEST_SUPPORT_AGENT_ID,
        task_id=task.task_id,
        scope=_credit_scope(guest_support_limit),
        issued_at=now,
        expires_at=expires_at,
    )

    # Canonical registration is trusted infrastructure. The executing agent only
    # receives the resulting chain; it cannot mint equivalent-looking grants and
    # have Ruhusa treat them as authoritative.
    security.grant_store.register(root_grant)
    security.grant_store.register(guest_support_grant)
    return root_grant, guest_support_grant
