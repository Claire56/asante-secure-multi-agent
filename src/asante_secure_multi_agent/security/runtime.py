"""Local Ruhusa runtime for the guest-credit vertical slice.

Phase 5 keeps Ruhusa independent of authentication and telemetry. Human identity is verified
at the FastAPI boundary, workload identity is supplied by trusted runtime code,
and Ruhusa consumes only canonical principal IDs and delegation state.
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

from asante_secure_multi_agent.identity import (
    GUEST_SUPPORT_WORKLOAD,
    StaticSpiffeWorkloadIdentityProvider,
    WorkloadIdentityProvider,
)

CREDIT_TOOL_ID = "asante.guest-credit"
CREDIT_TOOL_IMPLEMENTATION = "asante.guest-credit@0.5.0"


@dataclass(frozen=True)
class AsanteSecurityRuntime:
    """Process-local Ruhusa and trusted workload-identity components."""

    authorizer: Ruhusa
    grant_store: InMemoryGrantStore
    invocation_factory: TrustedInvocationFactory
    execution_controller: ExecutionController
    workload_identities: WorkloadIdentityProvider


def _credit_at_most(limit: float):
    """Return a policy condition that matches credits in ``(0, limit]`` USD."""

    def condition(request) -> bool:
        amount = request.arguments.get("amount")
        return isinstance(amount, (int, float)) and 0 < float(amount) <= limit

    return condition


def build_security_runtime(
    workload_identities: WorkloadIdentityProvider | None = None,
) -> AsanteSecurityRuntime:
    """Build the local security boundary for the Asante guest-credit workflow.

    Workload identity is resolved by trusted infrastructure rather than supplied
    by the model or HTTP request. The default provider assigns SPIFFE IDs to the
    in-process Supervisor and Guest Support workloads. A later SPIRE-backed
    provider can replace it without changing Ruhusa policy or tool contracts.
    """
    identity_provider = workload_identities or StaticSpiffeWorkloadIdentityProvider()
    guest_support_id = identity_provider.require(GUEST_SUPPORT_WORKLOAD).principal_id

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

    policies = StaticPolicyStore(
        rules=(
            PolicyRule(
                policy_id="guest-support-small-credit",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"guest.credit.issue"}),
                principal_ids=frozenset({guest_support_id}),
                resource_prefixes=("reservation:",),
                condition=_credit_at_most(25.0),
                reason="guest support may issue service-recovery credit up to $25",
            ),
            PolicyRule(
                policy_id="guest-support-credit-needs-approval",
                effect=DecisionEffect.REQUIRE_APPROVAL,
                actions=frozenset({"guest.credit.issue"}),
                principal_ids=frozenset({guest_support_id}),
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
        workload_identities=identity_provider,
    )
