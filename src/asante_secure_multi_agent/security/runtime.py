from __future__ import annotations

from dataclasses import dataclass

from ruhusa import (
    DecisionEffect,
    ExecutionController,
    InMemoryExecutionStore,
    InMemoryInvocationStore,
    InMemoryToolRegistry,
    PolicyRule,
    Ruhusa,
    StaticPolicyStore,
    ToolRegistration,
)
from ruhusa.integrations.trusted import TrustedInvocationFactory

GUEST_SUPPORT_AGENT_ID = "agent:asante:guest-support"
SUPERVISOR_AGENT_ID = "agent:asante:supervisor"
CREDIT_TOOL_ID = "asante.guest-credit"
CREDIT_TOOL_IMPLEMENTATION = "asante.guest-credit@0.1.0"


@dataclass(frozen=True)
class AsanteSecurityRuntime:
    authorizer: Ruhusa
    invocation_factory: TrustedInvocationFactory
    execution_controller: ExecutionController


def _credit_at_most(limit: float):
    def condition(request) -> bool:
        amount = request.arguments.get("amount")
        return isinstance(amount, (int, float)) and 0 < float(amount) <= limit

    return condition


def build_security_runtime() -> AsanteSecurityRuntime:
    """Build the local security boundary for the first Asante vertical slice.

    Phase 1 deliberately uses in-memory stores. Production persistence and external
    identity are later milestones; the authorization semantics stay the same.
    """
    invocation_store = InMemoryInvocationStore()
    tool_registry = InMemoryToolRegistry()
    tool_registry.register(
        ToolRegistration(
            tool_id=CREDIT_TOOL_ID,
            implementation_id=CREDIT_TOOL_IMPLEMENTATION,
            allowed_actions=frozenset({"guest.credit.issue"}),
        )
    )

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
        invocation_store=invocation_store,
        tool_registry=tool_registry,
    )
    return AsanteSecurityRuntime(
        authorizer=authorizer,
        invocation_factory=TrustedInvocationFactory(invocation_store),
        execution_controller=ExecutionController(
            authorizer,
            execution_store=InMemoryExecutionStore(),
        ),
    )
