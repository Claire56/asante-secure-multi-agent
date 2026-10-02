"""Local Ruhusa runtime for least-privilege Asante property operations.

Phase 9 assigns each specialist agent a distinct workload identity and policy
surface. Agent prompts decide what to attempt; Ruhusa independently decides
whether that specialist is authorized to perform the requested action.
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
    APPROVAL_EXECUTOR_WORKLOAD,
    GUEST_SUPPORT_WORKLOAD,
    PROPERTY_OPERATIONS_WORKLOAD,
    RESERVATIONS_WORKLOAD,
    SERVICE_RECOVERY_WORKLOAD,
    StaticSpiffeWorkloadIdentityProvider,
    WorkloadIdentityProvider,
)

CREDIT_TOOL_ID = "asante.guest-credit"
CREDIT_TOOL_IMPLEMENTATION = "asante.guest-credit@0.9.0"
RESERVATION_TOOL_ID = "asante.reservation-reader"
RESERVATION_TOOL_IMPLEMENTATION = "asante.reservation-reader@0.9.0"
GUEST_OPERATIONS_TOOL_ID = "asante.guest-operations"
GUEST_OPERATIONS_TOOL_IMPLEMENTATION = "asante.guest-operations@0.9.0"
APPROVED_CREDIT_TOOL_ID = "asante.approved-credit"
APPROVED_CREDIT_TOOL_IMPLEMENTATION = "asante.approved-credit@0.9.0"


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


def _credit_request_between(lower_exclusive: float, upper_inclusive: float):
    """Match service-credit approval requests in the configured amount band."""

    def condition(request) -> bool:
        amount = request.arguments.get("amount")
        return (
            isinstance(amount, (int, float)) and lower_exclusive < float(amount) <= upper_inclusive
        )

    return condition


def _verified_approved_credit(limit: float):
    """Allow only trusted approval-executor requests with verified evidence."""

    def condition(request) -> bool:
        amount = request.arguments.get("amount")
        verified = request.arguments.get("approval_verified") is True
        approval_id = request.arguments.get("approval_id")
        return (
            verified
            and isinstance(approval_id, str)
            and bool(approval_id)
            and isinstance(amount, (int, float))
            and 0 < float(amount) <= limit
        )

    return condition


def build_security_runtime(
    workload_identities: WorkloadIdentityProvider | None = None,
) -> AsanteSecurityRuntime:
    """Build the local least-privilege security boundary for Asante operations."""
    identity_provider = workload_identities or StaticSpiffeWorkloadIdentityProvider()
    reservations_id = identity_provider.require(RESERVATIONS_WORKLOAD).principal_id
    property_operations_id = identity_provider.require(PROPERTY_OPERATIONS_WORKLOAD).principal_id
    guest_support_id = identity_provider.require(GUEST_SUPPORT_WORKLOAD).principal_id
    service_recovery_id = identity_provider.require(SERVICE_RECOVERY_WORKLOAD).principal_id
    approval_executor_id = identity_provider.require(APPROVAL_EXECUTOR_WORKLOAD).principal_id

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
    tool_registry.register(
        ToolRegistration(
            tool_id=RESERVATION_TOOL_ID,
            implementation_id=RESERVATION_TOOL_IMPLEMENTATION,
            allowed_actions=frozenset({"reservation.read"}),
        )
    )
    tool_registry.register(
        ToolRegistration(
            tool_id=GUEST_OPERATIONS_TOOL_ID,
            implementation_id=GUEST_OPERATIONS_TOOL_IMPLEMENTATION,
            allowed_actions=frozenset(
                {"maintenance.create", "guest.message.send", "guest.credit.request"}
            ),
        )
    )
    tool_registry.register(
        ToolRegistration(
            tool_id=APPROVED_CREDIT_TOOL_ID,
            implementation_id=APPROVED_CREDIT_TOOL_IMPLEMENTATION,
            allowed_actions=frozenset({"guest.credit.issue.approved"}),
        )
    )

    policies = StaticPolicyStore(
        rules=(
            PolicyRule(
                policy_id="reservations-read",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"reservation.read"}),
                principal_ids=frozenset({reservations_id}),
                resource_prefixes=("reservation:",),
                reason="reservations specialist may read reservations within delegated scope",
            ),
            PolicyRule(
                policy_id="property-operations-maintenance-create",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"maintenance.create"}),
                principal_ids=frozenset({property_operations_id}),
                resource_prefixes=("reservation:",),
                reason="property operations may create maintenance work orders",
            ),
            PolicyRule(
                policy_id="guest-support-message-send",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"guest.message.send"}),
                principal_ids=frozenset({guest_support_id}),
                resource_prefixes=("reservation:",),
                reason="guest support may send operational guest updates",
            ),
            PolicyRule(
                policy_id="service-recovery-credit-request",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"guest.credit.request"}),
                principal_ids=frozenset({service_recovery_id}),
                resource_prefixes=("reservation:",),
                condition=_credit_request_between(25.0, 100.0),
                reason=(
                    "service recovery may request human approval for credits above $25 up to $100"
                ),
            ),
            PolicyRule(
                policy_id="service-recovery-small-credit",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"guest.credit.issue"}),
                principal_ids=frozenset({service_recovery_id}),
                resource_prefixes=("reservation:",),
                condition=_credit_at_most(25.0),
                reason="service recovery may issue automatic service credit up to $25",
            ),
            PolicyRule(
                policy_id="service-recovery-credit-needs-approval",
                effect=DecisionEffect.REQUIRE_APPROVAL,
                actions=frozenset({"guest.credit.issue"}),
                principal_ids=frozenset({service_recovery_id}),
                resource_prefixes=("reservation:",),
                condition=_credit_at_most(100.0),
                reason="credits above $25 and up to $100 require human approval",
                obligations=("human_approval",),
            ),
            PolicyRule(
                policy_id="approved-credit-executor",
                effect=DecisionEffect.ALLOW,
                actions=frozenset({"guest.credit.issue.approved"}),
                principal_ids=frozenset({approval_executor_id}),
                resource_prefixes=("reservation:",),
                condition=_verified_approved_credit(100.0),
                reason="trusted approval executor may issue a human-approved credit up to $100",
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
