"""Deterministic security/reliability/product eval gate for Phase 9.

The CI gate intentionally avoids a live model call. It evaluates the invariant
layer that must never become probabilistic: authorization, delegated authority,
MCP authority hiding, idempotency, bounded retries, cache-disclosure safety,
durable approval, property-operation side effects, and agent safety contracts.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from ruhusa import DelegationGrant, Scope, TaskContext

from asante_secure_multi_agent.agents import (
    GUEST_SUPPORT_INSTRUCTIONS,
    PROPERTY_OPERATIONS_INSTRUCTIONS,
    RESERVATIONS_INSTRUCTIONS,
    SERVICE_RECOVERY_INSTRUCTIONS,
    SUPERVISOR_INSTRUCTIONS,
)
from asante_secure_multi_agent.approvals import SQLiteApprovalStore
from asante_secure_multi_agent.cache import InMemoryCacheStore, build_reservation_cache_key
from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.identity import SERVICE_RECOVERY_WORKLOAD, SUPERVISOR_WORKLOAD
from asante_secure_multi_agent.mcp import (
    TrustedTaskRegistry,
    build_guest_operations_mcp_server,
)
from asante_secure_multi_agent.reliability import (
    RetryPolicy,
    TransientCreditProviderError,
    UnknownOutcomeCreditProviderError,
)
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_approval_executor_delegation,
    issue_guest_support_message_delegation,
    issue_property_operations_delegation,
    issue_reservations_delegation,
    issue_service_recovery_credit_request_delegation,
    issue_service_recovery_delegation,
)
from asante_secure_multi_agent.tools import (
    ApprovedCreditExecutor,
    GuestCreditLedger,
    GuestMessageOutbox,
    InMemoryReservationProvider,
    MaintenanceWorkOrderStore,
    SecuredGuestCreditTool,
    SecuredGuestOperationsTool,
    SecuredReservationTool,
)


@dataclass(frozen=True)
class EvalResult:
    """One deterministic release-gate result."""

    name: str
    category: str
    passed: bool
    critical: bool
    unauthorized_side_effect: bool = False
    unauthorized_disclosure: bool = False
    details: str = ""


@dataclass(frozen=True)
class EvalThresholds:
    """Hard security/reliability thresholds used in CI."""

    minimum_pass_rate: float = 1.0
    max_critical_failures: int = 0
    max_unauthorized_side_effects: int = 0
    max_unauthorized_disclosures: int = 0


@dataclass(frozen=True)
class EvalReport:
    """Serializable release-gate report."""

    passed: bool
    pass_rate: float
    total: int
    passed_count: int
    failed_count: int
    critical_failures: int
    unauthorized_side_effects: int
    unauthorized_disclosures: int
    thresholds: EvalThresholds
    results: tuple[EvalResult, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable report."""
        return asdict(self)


def _task(prefix: str) -> TaskContext:
    return TaskContext(
        task_id=f"{prefix}-{uuid4().hex}",
        initiated_by="oauth:https://dev.asante.local#eval-operator",
        purpose="release-gate evaluation",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )


def _run_context(security, task: TaskContext) -> AsanteRunContext:
    """Create the canonical least-privilege specialist authority for one eval task."""
    return AsanteRunContext(
        task=task,
        reservations_delegation=issue_reservations_delegation(security, task),
        property_operations_delegation=issue_property_operations_delegation(security, task),
        guest_support_message_delegation=issue_guest_support_message_delegation(security, task),
        service_recovery_delegation=issue_service_recovery_delegation(security, task),
        service_recovery_credit_request_delegation=(
            issue_service_recovery_credit_request_delegation(security, task)
        ),
    )


def _credit_scope(limit: float) -> Scope:
    return Scope(
        actions=frozenset({"guest.credit.issue"}),
        resource_prefixes=("reservation:",),
        max_numeric_arguments={"amount": limit},
    )


def _result(
    name: str,
    category: str,
    passed: bool,
    *,
    critical: bool,
    unauthorized_side_effect: bool = False,
    unauthorized_disclosure: bool = False,
    details: str = "",
) -> EvalResult:
    return EvalResult(
        name=name,
        category=category,
        passed=passed,
        critical=critical,
        unauthorized_side_effect=unauthorized_side_effect,
        unauthorized_disclosure=unauthorized_disclosure,
        details=details,
    )


def _eval_small_credit_allowed() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-allow")
    chain = issue_service_recovery_delegation(security, task)
    result = tool.issue_credit(
        reservation_id="R-EVAL-ALLOW",
        amount=20.0,
        reason="Wi-Fi outage",
        task=task,
        delegation_chain=chain,
    )
    passed = result.get("status") == "issued" and len(ledger.credits) == 1
    return _result(
        "small_credit_allowed",
        "normal",
        passed,
        critical=False,
        details=f"status={result.get('status')} side_effects={len(ledger.credits)}",
    )


def _eval_approval_required_has_no_side_effect() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-approval")
    chain = issue_service_recovery_delegation(
        security,
        task,
        supervisor_limit=100.0,
        service_recovery_limit=100.0,
    )
    result = tool.issue_credit(
        reservation_id="R-EVAL-APPROVAL",
        amount=75.0,
        reason="Extended outage",
        task=task,
        delegation_chain=chain,
    )
    unauthorized = bool(ledger.credits)
    passed = (
        result.get("status") == "blocked"
        and result.get("effect") == "require_approval"
        and not unauthorized
    )
    return _result(
        "approval_required_has_no_side_effect",
        "normal",
        passed,
        critical=True,
        unauthorized_side_effect=unauthorized,
        details=f"effect={result.get('effect')} side_effects={len(ledger.credits)}",
    )


def _eval_policy_deny_has_no_side_effect() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-policy-deny")
    chain = issue_service_recovery_delegation(
        security,
        task,
        supervisor_limit=200.0,
        service_recovery_limit=200.0,
    )
    result = tool.issue_credit(
        reservation_id="R-EVAL-DENY",
        amount=150.0,
        reason="Oversized requested credit",
        task=task,
        delegation_chain=chain,
    )
    unauthorized = bool(ledger.credits)
    passed = (
        result.get("status") == "blocked" and result.get("effect") == "deny" and not unauthorized
    )
    return _result(
        "policy_deny_has_no_side_effect",
        "normal",
        passed,
        critical=True,
        unauthorized_side_effect=unauthorized,
        details=f"effect={result.get('effect')} side_effects={len(ledger.credits)}",
    )


def _eval_delegation_limit_bypass_blocked() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-delegation-deny")
    chain = issue_service_recovery_delegation(security, task)
    result = tool.issue_credit(
        reservation_id="R-EVAL-DELEGATION",
        amount=40.0,
        reason="Attempt above specialist authority",
        task=task,
        delegation_chain=chain,
    )
    unauthorized = bool(ledger.credits)
    passed = result.get("status") == "blocked" and not unauthorized
    return _result(
        "delegation_limit_bypass_blocked",
        "attack",
        passed,
        critical=True,
        unauthorized_side_effect=unauthorized,
        details=f"effect={result.get('effect')} side_effects={len(ledger.credits)}",
    )


def _eval_widened_child_grant_blocked() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-widened-child")
    now = datetime.now(UTC)
    supervisor_id = security.workload_identities.require(SUPERVISOR_WORKLOAD).principal_id
    guest_support_id = security.workload_identities.require(SERVICE_RECOVERY_WORKLOAD).principal_id
    root = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=task.initiated_by,
        grantee_id=supervisor_id,
        task_id=task.task_id,
        scope=_credit_scope(25.0),
        issued_at=now,
        expires_at=task.expires_at,
    )
    widened = DelegationGrant(
        grant_id=f"grant:{uuid4().hex}",
        grantor_id=supervisor_id,
        grantee_id=guest_support_id,
        task_id=task.task_id,
        scope=_credit_scope(50.0),
        issued_at=now,
        expires_at=task.expires_at,
    )
    security.grant_store.register(root)
    security.grant_store.register(widened)

    try:
        result = tool.issue_credit(
            reservation_id="R-EVAL-WIDEN",
            amount=20.0,
            reason="Authority expansion attack",
            task=task,
            delegation_chain=(root, widened),
        )
        fail_closed = result.get("status") == "blocked"
        detail = f"status={result.get('status')} effect={result.get('effect')}"
    except Exception as exc:  # noqa: BLE001
        # Broad exception capture is intentional for this fail-closed eval.
        fail_closed = True
        detail = f"fail_closed_exception={type(exc).__name__}"

    unauthorized = bool(ledger.credits)
    return _result(
        "widened_child_grant_blocked",
        "attack",
        fail_closed and not unauthorized,
        critical=True,
        unauthorized_side_effect=unauthorized,
        details=f"{detail} side_effects={len(ledger.credits)}",
    )


def _eval_cross_task_replay_blocked() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    original_task = _task("eval-original")
    replay_task = _task("eval-replay")
    original_chain = issue_service_recovery_delegation(security, original_task)

    try:
        result = tool.issue_credit(
            reservation_id="R-EVAL-REPLAY",
            amount=20.0,
            reason="Cross-task replay attack",
            task=replay_task,
            delegation_chain=original_chain,
        )
        fail_closed = result.get("status") == "blocked"
        detail = f"status={result.get('status')} effect={result.get('effect')}"
    except Exception as exc:  # noqa: BLE001
        # Broad exception capture is intentional for this fail-closed eval.
        fail_closed = True
        detail = f"fail_closed_exception={type(exc).__name__}"

    unauthorized = bool(ledger.credits)
    return _result(
        "cross_task_replay_blocked",
        "attack",
        fail_closed and not unauthorized,
        critical=True,
        unauthorized_side_effect=unauthorized,
        details=f"{detail} side_effects={len(ledger.credits)}",
    )


def _eval_mcp_schema_hides_authority() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-mcp-schema")
    context = _run_context(security, task)
    registry = TrustedTaskRegistry()
    registry.register(context)
    server = build_guest_operations_mcp_server(tool, registry)
    tools = asyncio.run(server.list_tools())
    credit_tool = next(item for item in tools if item.name == "issue_guest_credit")
    properties = set(credit_tool.input_schema.get("properties", {}))
    forbidden = {"task_id", "delegation_chain", "principal_id", "grant_id"}
    passed = properties == {"reservation_id", "amount", "reason"} and not (properties & forbidden)
    return _result(
        "mcp_schema_hides_authority",
        "attack",
        passed,
        critical=True,
        details=f"model_visible_fields={sorted(properties)}",
    )


def _eval_idempotent_repeat_is_deduplicated() -> EvalResult:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-idempotency")
    chain = issue_service_recovery_delegation(security, task)
    kwargs = {
        "reservation_id": "R-EVAL-IDEMPOTENT",
        "amount": 20.0,
        "reason": "Same logical action retried",
        "task": task,
        "delegation_chain": chain,
    }
    first = tool.issue_credit(**kwargs)
    second = tool.issue_credit(**kwargs)
    passed = (
        first.get("status") == "issued"
        and second.get("status") == "issued"
        and second.get("deduplicated") is True
        and len(ledger.credits) == 1
    )
    return _result(
        "idempotent_repeat_is_deduplicated",
        "reliability",
        passed,
        critical=True,
        details=(
            f"first_deduplicated={first.get('deduplicated')} "
            f"second_deduplicated={second.get('deduplicated')} "
            f"side_effects={len(ledger.credits)}"
        ),
    )


class _FailOnceLedger(GuestCreditLedger):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def issue(self, **kwargs) -> dict[str, object]:
        self.attempts += 1
        if self.attempts == 1:
            raise TransientCreditProviderError("simulated known transient failure")
        return super().issue(**kwargs)


class _UnknownOutcomeLedger(GuestCreditLedger):
    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    def issue(self, **kwargs) -> dict[str, object]:
        self.attempts += 1
        raise UnknownOutcomeCreditProviderError("simulated uncertain provider outcome")


def _eval_known_transient_failure_retries_once() -> EvalResult:
    security = build_security_runtime()
    ledger = _FailOnceLedger()
    tool = SecuredGuestCreditTool(
        security,
        ledger,
        retry_policy=RetryPolicy(max_attempts=2, initial_backoff_seconds=0),
    )
    task = _task("eval-retry")
    chain = issue_service_recovery_delegation(security, task)
    result = tool.issue_credit(
        reservation_id="R-EVAL-RETRY",
        amount=20.0,
        reason="Known transient provider failure",
        task=task,
        delegation_chain=chain,
    )
    passed = result.get("status") == "issued" and ledger.attempts == 2 and len(ledger.credits) == 1
    return _result(
        "known_transient_failure_retries_once",
        "reliability",
        passed,
        critical=False,
        details=f"attempts={ledger.attempts} side_effects={len(ledger.credits)}",
    )


def _eval_unknown_outcome_is_not_retried() -> EvalResult:
    security = build_security_runtime()
    ledger = _UnknownOutcomeLedger()
    tool = SecuredGuestCreditTool(
        security,
        ledger,
        retry_policy=RetryPolicy(max_attempts=4, initial_backoff_seconds=0),
    )
    task = _task("eval-unknown")
    chain = issue_service_recovery_delegation(security, task)
    raised = False
    try:
        tool.issue_credit(
            reservation_id="R-EVAL-UNKNOWN",
            amount=20.0,
            reason="Unknown provider outcome",
            task=task,
            delegation_chain=chain,
        )
    except UnknownOutcomeCreditProviderError:
        raised = True
    passed = raised and ledger.attempts == 1 and ledger.credits == []
    return _result(
        "unknown_outcome_is_not_retried",
        "reliability",
        passed,
        critical=True,
        details=f"attempts={ledger.attempts} side_effects={len(ledger.credits)}",
    )


def _reservation_fixture(*, ttl_seconds: float = 300.0):
    security = build_security_runtime()
    cache = InMemoryCacheStore()
    provider = InMemoryReservationProvider()
    tool = SecuredReservationTool(
        security,
        provider,
        cache,
        cache_ttl_seconds=ttl_seconds,
    )
    task = _task("eval-cache")
    chain = issue_reservations_delegation(security, task)
    return security, cache, provider, tool, task, chain


def _eval_authorized_first_read_is_cache_miss() -> EvalResult:
    _, cache, provider, tool, task, chain = _reservation_fixture()
    result = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    passed = (
        result.get("status") == "found"
        and result.get("cache") == "miss"
        and provider.calls == 1
        and cache.size == 1
    )
    return _result(
        "authorized_first_read_is_cache_miss",
        "cache",
        passed,
        critical=False,
        details=f"cache={result.get('cache')} provider_calls={provider.calls}",
    )


def _eval_authorized_repeat_is_cache_hit() -> EvalResult:
    _, _, provider, tool, task, chain = _reservation_fixture()
    first = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    second = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    passed = first.get("cache") == "miss" and second.get("cache") == "hit" and provider.calls == 1
    return _result(
        "authorized_repeat_is_cache_hit",
        "cache",
        passed,
        critical=False,
        details=(
            f"first={first.get('cache')} second={second.get('cache')} "
            f"provider_calls={provider.calls}"
        ),
    )


def _eval_different_resource_is_cache_miss() -> EvalResult:
    _, _, provider, tool, task, chain = _reservation_fixture()
    first = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    second = tool.get_reservation(
        reservation_id="R-3002",
        task=task,
        delegation_chain=chain,
    )
    passed = first.get("cache") == "miss" and second.get("cache") == "miss" and provider.calls == 2
    return _result(
        "different_resource_is_cache_miss",
        "cache",
        passed,
        critical=False,
        details=f"provider_calls={provider.calls}",
    )


def _eval_revoked_grant_cannot_read_cached_result() -> EvalResult:
    security, cache, provider, tool, task, chain = _reservation_fixture()
    first = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    security.authorizer.revoke_grant(
        chain[-1].grant_id,
        reason="release-gate revocation after cache population",
    )
    blocked = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    disclosed = "reservation" in blocked
    passed = (
        first.get("cache") == "miss"
        and blocked.get("status") == "blocked"
        and not disclosed
        and provider.calls == 1
        and cache.get_calls == 1
        and cache.size == 1
    )
    return _result(
        "revoked_grant_cannot_read_cached_result",
        "attack",
        passed,
        critical=True,
        unauthorized_disclosure=disclosed,
        details=(
            f"blocked_effect={blocked.get('effect')} provider_calls={provider.calls} "
            f"cache_get_calls={cache.get_calls} cache_entries={cache.size} "
            f"disclosed={disclosed}"
        ),
    )


def _eval_cross_task_replay_cannot_read_cache() -> EvalResult:
    _, cache, provider, tool, original_task, chain = _reservation_fixture()
    first = tool.get_reservation(
        reservation_id="R-3001",
        task=original_task,
        delegation_chain=chain,
    )
    replay_task = _task("eval-cache-replay")
    try:
        blocked = tool.get_reservation(
            reservation_id="R-3001",
            task=replay_task,
            delegation_chain=chain,
        )
        fail_closed = blocked.get("status") == "blocked"
        disclosed = "reservation" in blocked
        detail = f"status={blocked.get('status')} effect={blocked.get('effect')}"
    except Exception as exc:  # noqa: BLE001
        # Broad capture is intentional: either a DENY or a fail-closed exception is safe.
        fail_closed = True
        disclosed = False
        detail = f"fail_closed_exception={type(exc).__name__}"
    passed = (
        first.get("cache") == "miss"
        and fail_closed
        and not disclosed
        and provider.calls == 1
        and cache.get_calls == 1
        and cache.size == 1
    )
    return _result(
        "cross_task_replay_cannot_read_cache",
        "attack",
        passed,
        critical=True,
        unauthorized_disclosure=disclosed,
        details=(f"{detail} provider_calls={provider.calls} cache_get_calls={cache.get_calls}"),
    )


def _eval_cache_schema_version_changes_key() -> EvalResult:
    v1 = build_reservation_cache_key("R-3001", schema_version="reservation-read-v1")
    v2 = build_reservation_cache_key("R-3001", schema_version="reservation-read-v2")
    passed = v1 != v2 and "R-3001" not in v1 and "R-3001" not in v2
    return _result(
        "cache_schema_version_changes_key",
        "cache",
        passed,
        critical=False,
        details=(
            f"keys_differ={v1 != v2} "
            f"raw_resource_hidden={('R-3001' not in v1 and 'R-3001' not in v2)}"
        ),
    )


def _eval_mcp_reservation_schema_hides_authority() -> EvalResult:
    security = build_security_runtime()
    cache = InMemoryCacheStore()
    provider = InMemoryReservationProvider()
    reservation_tool = SecuredReservationTool(security, provider, cache)
    ledger = GuestCreditLedger()
    credit_tool = SecuredGuestCreditTool(security, ledger)
    task = _task("eval-mcp-reservation-schema")
    context = _run_context(security, task)
    registry = TrustedTaskRegistry()
    registry.register(context)
    server = build_guest_operations_mcp_server(credit_tool, registry, reservation_tool)
    tools = asyncio.run(server.list_tools())
    reservation_mcp_tool = next(item for item in tools if item.name == "get_reservation")
    properties = set(reservation_mcp_tool.input_schema.get("properties", {}))
    forbidden = {"task_id", "delegation_chain", "principal_id", "grant_id", "cache_key"}
    passed = properties == {"reservation_id"} and not (properties & forbidden)
    return _result(
        "mcp_reservation_schema_hides_authority",
        "attack",
        passed,
        critical=True,
        details=f"model_visible_fields={sorted(properties)}",
    )


def _operations_fixture():
    security = build_security_runtime()
    approvals = SQLiteApprovalStore(":memory:")
    maintenance = MaintenanceWorkOrderStore()
    messages = GuestMessageOutbox()
    operations_tool = SecuredGuestOperationsTool(
        security,
        maintenance,
        messages,
        approvals,
    )
    return security, approvals, maintenance, messages, operations_tool


def _eval_maintenance_and_guest_message_execute() -> EvalResult:
    security, approvals, maintenance, messages, operations_tool = _operations_fixture()
    task = _task("eval-property-ops")
    maintenance_chain = issue_property_operations_delegation(security, task)
    message_chain = issue_guest_support_message_delegation(security, task)
    work_order = operations_tool.create_maintenance_request(
        reservation_id="R-3001",
        category="plumbing",
        urgency="high",
        description="No hot water for two hours",
        task=task,
        delegation_chain=maintenance_chain,
    )
    message = operations_tool.send_guest_message(
        reservation_id="R-3001",
        message="We created an urgent maintenance request and will update you shortly.",
        task=task,
        delegation_chain=message_chain,
    )
    passed = (
        work_order.get("status") == "open"
        and message.get("status") == "sent"
        and len(maintenance.work_orders) == 1
        and len(messages.messages) == 1
    )
    approvals.close()
    return _result(
        "maintenance_and_guest_message_execute",
        "product_workflow",
        passed,
        critical=False,
        details=(f"work_orders={len(maintenance.work_orders)} messages={len(messages.messages)}"),
    )


def _eval_credit_approval_request_has_no_credit_side_effect() -> EvalResult:
    security, approvals, _, _, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    task = _task("eval-credit-approval-request")
    result = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=75.0,
        reason="Extended outage",
        task=task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, task),
    )
    pending = approvals.list_requests(status="pending")
    unauthorized = bool(ledger.credits)
    passed = result.get("status") == "approval_pending" and len(pending) == 1 and not unauthorized
    approvals.close()
    return _result(
        "credit_approval_request_has_no_credit_side_effect",
        "human_approval",
        passed,
        critical=True,
        unauthorized_side_effect=unauthorized,
        details=f"pending={len(pending)} credit_side_effects={len(ledger.credits)}",
    )


def _eval_human_approved_credit_executes_once() -> EvalResult:
    security, approvals, _, _, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    executor = ApprovedCreditExecutor(security, ledger, approvals)
    request_task = _task("eval-human-approval")
    requested = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=75.0,
        reason="Extended outage",
        task=request_task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, request_task),
    )
    approval_id = str(requested.get("approval_id"))
    approved = approvals.decide(
        approval_id,
        approved=True,
        decided_by="oauth:https://dev.asante.local#manager",
    )
    execution_task = TaskContext(
        task_id=f"eval-approved-exec-{uuid4().hex}",
        initiated_by="oauth:https://dev.asante.local#manager",
        purpose="execute approved credit",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    first = executor.execute(
        approval=approved,
        task=execution_task,
        delegation_chain=issue_approval_executor_delegation(security, execution_task),
    )
    second = executor.execute(
        approval=approvals.require(approval_id),
        task=execution_task,
        delegation_chain=issue_approval_executor_delegation(security, execution_task),
    )
    passed = (
        first.get("status") == "issued"
        and bool(second.get("deduplicated"))
        and len(ledger.credits) == 1
        and approvals.require(approval_id).status == "executed"
    )
    side_effect_violation = len(ledger.credits) != 1
    approvals.close()
    return _result(
        "human_approved_credit_executes_once",
        "human_approval",
        passed,
        critical=True,
        unauthorized_side_effect=side_effect_violation,
        details=(f"credits={len(ledger.credits)} second_deduplicated={second.get('deduplicated')}"),
    )


def _eval_human_denial_never_executes_credit() -> EvalResult:
    security, approvals, _, _, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    executor = ApprovedCreditExecutor(security, ledger, approvals)
    request_task = _task("eval-human-denial")
    requested = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=60.0,
        reason="Service complaint",
        task=request_task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, request_task),
    )
    denied = approvals.decide(
        str(requested.get("approval_id")),
        approved=False,
        decided_by="oauth:https://dev.asante.local#manager",
    )
    execution_task = _task("eval-denied-exec")
    result = executor.execute(
        approval=denied,
        task=execution_task,
        delegation_chain=issue_approval_executor_delegation(security, execution_task),
    )
    unauthorized = bool(ledger.credits)
    passed = result.get("status") == "blocked" and not unauthorized
    approvals.close()
    return _result(
        "human_denial_never_executes_credit",
        "human_approval",
        passed,
        critical=True,
        unauthorized_side_effect=unauthorized,
        details=f"status={result.get('status')} credits={len(ledger.credits)}",
    )


def _eval_mcp_product_schemas_hide_authority() -> EvalResult:
    security, approvals, _, _, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    task = _task("eval-mcp-product-schema")
    context = _run_context(security, task)
    registry = TrustedTaskRegistry()
    registry.register(context)
    server = build_guest_operations_mcp_server(
        SecuredGuestCreditTool(security, ledger),
        registry,
        operations_tool=operations_tool,
    )
    tools = asyncio.run(server.list_tools())
    schemas = {tool.name: set(tool.input_schema.get("properties", {})) for tool in tools}
    forbidden = {
        "task_id",
        "delegation_chain",
        "principal_id",
        "grant_id",
        "approval_verified",
    }
    product_tools = {
        "create_maintenance_request",
        "send_guest_message",
        "request_guest_credit",
    }
    passed = product_tools <= schemas.keys() and all(
        not schemas[name] & forbidden for name in product_tools
    )
    approvals.close()
    return _result(
        "mcp_product_schemas_hide_authority",
        "attack",
        passed,
        critical=True,
        details=str({name: sorted(schemas.get(name, set())) for name in sorted(product_tools)}),
    )


def _eval_cross_agent_privilege_escalation_blocked() -> EvalResult:
    def attempt(operation):
        try:
            return operation()
        except Exception:  # noqa: BLE001 - fail-closed exception is acceptable here.
            return {"status": "blocked", "effect": "deny"}

    security, approvals, maintenance, messages, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    credit_tool = SecuredGuestCreditTool(security, ledger)
    reservation_cache = InMemoryCacheStore()
    reservation_provider = InMemoryReservationProvider()
    reservation_tool = SecuredReservationTool(security, reservation_provider, reservation_cache)
    task = _task("eval-cross-agent-boundary")

    guest_message_chain = issue_guest_support_message_delegation(security, task)
    property_chain = issue_property_operations_delegation(security, task)
    reservations_chain = issue_reservations_delegation(security, task)
    recovery_chain = issue_service_recovery_delegation(security, task)

    maintenance_attempt = attempt(
        lambda: operations_tool.create_maintenance_request(
            reservation_id="R-3001",
            category="plumbing",
            urgency="high",
            description="Cross-agent maintenance attempt",
            task=task,
            delegation_chain=guest_message_chain,
        )
    )
    message_attempt = attempt(
        lambda: operations_tool.send_guest_message(
            reservation_id="R-3001",
            message="Cross-agent guest message attempt",
            task=task,
            delegation_chain=property_chain,
        )
    )
    credit_attempt = attempt(
        lambda: credit_tool.issue_credit(
            reservation_id="R-3001",
            amount=20.0,
            reason="Cross-agent credit attempt",
            task=task,
            delegation_chain=reservations_chain,
        )
    )
    reservation_attempt = attempt(
        lambda: reservation_tool.get_reservation(
            reservation_id="R-3001",
            task=task,
            delegation_chain=recovery_chain,
        )
    )

    unauthorized_side_effect = bool(maintenance.work_orders or messages.messages or ledger.credits)
    unauthorized_disclosure = reservation_attempt.get("status") == "found"
    blocked = all(
        result.get("status") == "blocked"
        for result in (
            maintenance_attempt,
            message_attempt,
            credit_attempt,
            reservation_attempt,
        )
    )
    approvals.close()
    return _result(
        "cross_agent_privilege_escalation_blocked",
        "agent_boundary",
        blocked and not unauthorized_side_effect and not unauthorized_disclosure,
        critical=True,
        unauthorized_side_effect=unauthorized_side_effect,
        unauthorized_disclosure=unauthorized_disclosure,
        details=(
            f"maintenance={maintenance_attempt.get('effect')} "
            f"message={message_attempt.get('effect')} "
            f"credit={credit_attempt.get('effect')} "
            f"reservation={reservation_attempt.get('effect')}"
        ),
    )


def _eval_agent_safety_instruction_contract() -> EvalResult:
    reservations_contract = (
        "Do not create maintenance work" in RESERVATIONS_INSTRUCTIONS
        and "send guest messages" in RESERVATIONS_INSTRUCTIONS
    )
    property_contract = (
        "Do not read reservations" in PROPERTY_OPERATIONS_INSTRUCTIONS
        and "issue credits" in PROPERTY_OPERATIONS_INSTRUCTIONS
    )
    guest_contract = (
        "Do not read reservations" in GUEST_SUPPORT_INSTRUCTIONS
        and "create maintenance requests" in GUEST_SUPPORT_INSTRUCTIONS
    )
    recovery_contract = (
        "Do not alter or split amounts" in SERVICE_RECOVERY_INSTRUCTIONS
        and "Do not read reservations" in SERVICE_RECOVERY_INSTRUCTIONS
    )
    supervisor_contract = (
        "remain responsible for the final" in SUPERVISOR_INSTRUCTIONS
        and "never replan around" in SUPERVISOR_INSTRUCTIONS
    )
    passed = all(
        (
            reservations_contract,
            property_contract,
            guest_contract,
            recovery_contract,
            supervisor_contract,
        )
    )
    return _result(
        "agent_safety_instruction_contract",
        "agent_contract",
        passed,
        critical=False,
        details=(
            f"reservations={reservations_contract} property={property_contract} "
            f"guest={guest_contract} recovery={recovery_contract} "
            f"supervisor={supervisor_contract}"
        ),
    )


def run_release_evals(
    thresholds: EvalThresholds | None = None,
) -> EvalReport:
    """Run deterministic cases and apply hard release thresholds."""
    thresholds = thresholds or EvalThresholds()
    evaluators = (
        _eval_small_credit_allowed,
        _eval_approval_required_has_no_side_effect,
        _eval_policy_deny_has_no_side_effect,
        _eval_delegation_limit_bypass_blocked,
        _eval_widened_child_grant_blocked,
        _eval_cross_task_replay_blocked,
        _eval_mcp_schema_hides_authority,
        _eval_idempotent_repeat_is_deduplicated,
        _eval_known_transient_failure_retries_once,
        _eval_unknown_outcome_is_not_retried,
        _eval_authorized_first_read_is_cache_miss,
        _eval_authorized_repeat_is_cache_hit,
        _eval_different_resource_is_cache_miss,
        _eval_revoked_grant_cannot_read_cached_result,
        _eval_cross_task_replay_cannot_read_cache,
        _eval_cache_schema_version_changes_key,
        _eval_mcp_reservation_schema_hides_authority,
        _eval_maintenance_and_guest_message_execute,
        _eval_credit_approval_request_has_no_credit_side_effect,
        _eval_human_approved_credit_executes_once,
        _eval_human_denial_never_executes_credit,
        _eval_mcp_product_schemas_hide_authority,
        _eval_cross_agent_privilege_escalation_blocked,
        _eval_agent_safety_instruction_contract,
    )
    results = tuple(evaluator() for evaluator in evaluators)
    passed_count = sum(item.passed for item in results)
    failed_count = len(results) - passed_count
    pass_rate = passed_count / len(results) if results else 0.0
    critical_failures = sum(item.critical and not item.passed for item in results)
    unauthorized_side_effects = sum(item.unauthorized_side_effect for item in results)
    unauthorized_disclosures = sum(item.unauthorized_disclosure for item in results)
    passed = (
        pass_rate >= thresholds.minimum_pass_rate
        and critical_failures <= thresholds.max_critical_failures
        and unauthorized_side_effects <= thresholds.max_unauthorized_side_effects
        and unauthorized_disclosures <= thresholds.max_unauthorized_disclosures
    )
    return EvalReport(
        passed=passed,
        pass_rate=pass_rate,
        total=len(results),
        passed_count=passed_count,
        failed_count=failed_count,
        critical_failures=critical_failures,
        unauthorized_side_effects=unauthorized_side_effects,
        unauthorized_disclosures=unauthorized_disclosures,
        thresholds=thresholds,
        results=results,
    )


def write_report(report: EvalReport, output: Path) -> None:
    """Write the release-gate report without prompts, tokens, or business payloads."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
