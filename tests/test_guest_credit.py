"""Authorization and delegation tests for the guest-credit vertical slice.

These tests call the secured tool directly so they assert Ruhusa decisions
without depending on the OpenAI Agents SDK or a live model.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ruhusa import DelegationGrant, Scope, TaskContext

from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_guest_support_delegation,
)
from asante_secure_multi_agent.security.runtime import (
    GUEST_SUPPORT_AGENT_ID,
    SUPERVISOR_AGENT_ID,
)
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool


def _task() -> TaskContext:
    """Build a short-lived recovery task used by every credit test."""
    return TaskContext(
        task_id=f"task-test-credit-{uuid4().hex}",
        initiated_by="user:claire",
        purpose="guest service recovery",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )


def _credit_scope(limit: float) -> Scope:
    """Build a test scope without going through the trusted application issuer."""
    return Scope(
        actions=frozenset({"guest.credit.issue"}),
        resource_prefixes=("reservation:",),
        max_numeric_arguments={"amount": limit},
    )


def test_delegation_chain_is_task_bound_registered_and_narrowed() -> None:
    """Trusted issuance creates canonical human -> supervisor -> specialist authority."""
    security = build_security_runtime()
    task = _task()

    root, child = issue_guest_support_delegation(security, task)

    assert root.grantor_id == task.initiated_by
    assert root.grantee_id == SUPERVISOR_AGENT_ID
    assert root.task_id == task.task_id
    assert root.scope.max_numeric_arguments["amount"] == 100.0

    assert child.grantor_id == SUPERVISOR_AGENT_ID
    assert child.grantee_id == GUEST_SUPPORT_AGENT_ID
    assert child.task_id == task.task_id
    assert child.scope.max_numeric_arguments["amount"] == 25.0

    assert security.grant_store.is_registered(root)
    assert security.grant_store.is_registered(child)


def test_guest_support_can_issue_small_credit_with_delegated_authority() -> None:
    """A $20 credit fits both the delegation chain and the ALLOW policy."""
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task()
    chain = issue_guest_support_delegation(security, task)

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=20.0,
        reason="Wi-Fi outage",
        task=task,
        delegation_chain=chain,
    )

    assert result["status"] == "issued"
    assert result["effect"] == "allow"
    assert result["policy_id"] == "guest-support-small-credit"
    assert len(ledger.credits) == 1


def test_default_delegation_blocks_credit_above_guest_support_limit() -> None:
    """A specialist cannot use policy headroom that was never delegated to it."""
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task()
    chain = issue_guest_support_delegation(security, task)

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=40.0,
        reason="Extended Wi-Fi outage",
        task=task,
        delegation_chain=chain,
    )

    assert result["status"] == "blocked"
    assert result["effect"] == "deny"
    assert ledger.credits == []


def test_broader_trusted_delegation_still_requires_policy_approval() -> None:
    """Delegation grants authority; it does not bypass independent policy controls."""
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task()
    chain = issue_guest_support_delegation(
        security,
        task,
        supervisor_limit=100.0,
        guest_support_limit=100.0,
    )

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=75.0,
        reason="Extended Wi-Fi outage",
        task=task,
        delegation_chain=chain,
    )

    assert result["status"] == "blocked"
    assert result["effect"] == "require_approval"
    assert ledger.credits == []


def test_credit_above_policy_ceiling_is_default_deny() -> None:
    """Even a broad trusted grant cannot make an action policy-authorized."""
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task()
    chain = issue_guest_support_delegation(
        security,
        task,
        supervisor_limit=200.0,
        guest_support_limit=200.0,
    )

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=150.0,
        reason="Requested oversized credit",
        task=task,
        delegation_chain=chain,
    )

    assert result["status"] == "blocked"
    assert result["effect"] == "deny"
    assert ledger.credits == []


def test_widened_child_grant_is_denied_even_for_small_action() -> None:
    """A child grant that expands its parent's scope invalidates the chain.

    This bypasses the application's safe delegation issuer on purpose and
    registers a malicious-looking canonical chain: the supervisor has only $25
    but the child grant claims $50. Ruhusa must reject the chain itself, even
    though the requested $20 credit would individually fit both policy and the
    parent's numeric ceiling.
    """
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task()
    now = datetime.now(UTC)
    expires_at = task.expires_at

    root = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=task.initiated_by,
        grantee_id=SUPERVISOR_AGENT_ID,
        task_id=task.task_id,
        scope=_credit_scope(25.0),
        issued_at=now,
        expires_at=expires_at,
    )
    widened_child = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=SUPERVISOR_AGENT_ID,
        grantee_id=GUEST_SUPPORT_AGENT_ID,
        task_id=task.task_id,
        scope=_credit_scope(50.0),
        issued_at=now,
        expires_at=expires_at,
    )
    security.grant_store.register(root)
    security.grant_store.register(widened_child)

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=20.0,
        reason="Wi-Fi outage",
        task=task,
        delegation_chain=(root, widened_child),
    )

    assert result["status"] == "blocked"
    assert result["effect"] == "deny"
    assert ledger.credits == []
