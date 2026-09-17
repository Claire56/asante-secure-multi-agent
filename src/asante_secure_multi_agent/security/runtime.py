"""Local Ruhusa runtime for the guest-credit vertical slice.

This module is the authorization boundary. Application agents and FastAPI do
not decide whether a credit may be issued; they prepare a trusted invocation
and ask Ruhusa. Phase 3 keeps the process-local stores from Phase 1, but adds
trusted canonical grant storage so agent handoffs are backed by real delegated
authority rather than orchestration alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from ruhusa import (
    DecisionEffect,
    ExecutionController,
    InMemoryExecutionStore,
    InMemoryGrantStore,
    InMemoryInvocationStore,
    InMemoryToolRegistry,
    PolicyRule,
    Ruhusa,
    StaticPolicyStore,
    ToolRegistration,
)
from ruhusa.integrations.trusted import TrustedInvocationFactory

# Stable identities used in policy, delegation grants, and trusted invocations.
# Changing these strings without updating the corresponding canonical security
# state would make the affected requests fail closed.
GUEST_SUPPORT_AGENT_ID = "agent:asante:guest-support"
SUPERVISOR_AGENT_ID = "agent:asante:supervisor"
CREDIT_TOOL_ID = "asante.guest-credit"
CREDIT_TOOL_IMPLEMENTATION = "asante.guest-credit@0.3.0"


@dataclass(frozen=True)
class AsanteSecurityRuntime:
    """Process-local Ruhusa components shared by secured tools.

    Attributes:
        authorizer: Policy engine that evaluates trusted invocations.
        grant_store: Canonical registry for trusted delegation grants.
        invocation_factory: Creates/stores trusted invocation provenance.
        execution_controller: Admission, revalidation, and completion fencing.
    """

    authorizer: Ruhusa
    grant_store: InMemoryGrantStore
    invocation_factory: TrustedInvocationFactory
    execution_controller: ExecutionController


def _credit_at_most(limit: float):
    """Return a policy condition that matches credits in ``(0, limit]`` USD."""

    def condition(request) -> bool:
        amount = request.arguments.get("amount")
        return isinstance(amount, (int, float)) and 0 < float(amount) <= limit

    return condition


def build_security_runtime() -> AsanteSecurityRuntime:
    """Build the local security boundary for the Asante guest-credit workflow.

    Phase 3 still uses in-memory Ruhusa stores. Delegated
    authority is now registered canonically in ``InMemoryGrantStore`` and is
    supplied on every delegated tool invocation.

    Policy remains defense in depth:
        - $0 < amount <= $25: ALLOW
        - $25 < amount <= $100: REQUIRE_APPROVAL
        - amount > $100: default DENY

    The default delegation issued to Guest Support is narrower than the policy:
    it permits at most $25. A broader trusted delegation may reach the approval
    rule, but the ordinary autonomous path cannot silently widen itself.
    """
    grant_store = InMemoryGrantStore()
    invocation_store = InMemoryInvocationStore()
    tool_registry = InMemoryToolRegistry()
    tool_registry.register(
        ToolRegistration(
            tool_id=CREDIT_TOOL_ID,
            implementation_id=CREDIT_TOOL_IMPLEMENTATION,
            allowed_actions=frozenset({"guest.credit.issue"}),
        )
    )

    # Amounts at or below $25 also satisfy the $100 rule, so the ALLOW rule is
    # listed first and must win for small credits.
    policies = StaticPolicyStore(
        rules=(
            PolicyRule(
                policy_id="guest-support-small-credit",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"guest.credit.issue"}),
                principal_ids=frozenset({GUEST_SUPPORT_AGENT_ID}),
                resource_prefixes=("reservation:",),
                condition=_credit_at_most(25.0),
                reason="guest support may issue service-recovery credit up to $25",
            ),
            PolicyRule(
                policy_id="guest-support-credit-needs-approval",
                effect=DecisionEffect.REQUIRE_APPROVAL,
                actions=frozenset({"guest.credit.issue"}),
                principal_ids=frozenset({GUEST_SUPPORT_AGENT_ID}),
                resource_prefixes=("reservation:",),
                condition=_credit_at_most(100.0),
                reason="credits above $25 and up to $100 require human approval",
                obligations=("human_approval",),
            ),
        )
    )

    authorizer = Ruhusa(
        policy_store=policies,
        grant_store=grant_store,
        invocation_store=invocation_store,
        tool_registry=tool_registry,
    )
    return AsanteSecurityRuntime(
        authorizer=authorizer,
        grant_store=grant_store,
        invocation_factory=TrustedInvocationFactory(invocation_store),
        execution_controller=ExecutionController(
            authorizer,
            execution_store=InMemoryExecutionStore(),
        ),
    )
