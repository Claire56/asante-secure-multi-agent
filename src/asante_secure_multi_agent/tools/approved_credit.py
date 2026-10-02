"""Trusted execution path for a human-approved guest credit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from opentelemetry.trace import Status, StatusCode
from ruhusa import DecisionEffect, DelegationGrant, Principal, TaskContext

from asante_secure_multi_agent.approvals import ApprovalRecord, SQLiteApprovalStore
from asante_secure_multi_agent.identity import APPROVAL_EXECUTOR_WORKLOAD
from asante_secure_multi_agent.reliability import CreditProvider
from asante_secure_multi_agent.security.runtime import (
    APPROVED_CREDIT_TOOL_ID,
    APPROVED_CREDIT_TOOL_IMPLEMENTATION,
    AsanteSecurityRuntime,
)
from asante_secure_multi_agent.telemetry import get_tracer
from asante_secure_multi_agent.telemetry.metrics import (
    monotonic_time,
    record_authorization,
    record_credit_execution,
)

_tracer = get_tracer()


class ApprovedCreditExecutor:
    """Execute only credits backed by durable, server-verified human approval."""

    def __init__(
        self,
        security: AsanteSecurityRuntime,
        ledger: CreditProvider,
        approvals: SQLiteApprovalStore,
    ) -> None:
        self.security = security
        self.ledger = ledger
        self.approvals = approvals

    def execute(
        self,
        *,
        approval: ApprovalRecord,
        task: TaskContext,
        delegation_chain: tuple[DelegationGrant, ...],
    ) -> dict[str, object]:
        """Authorize and execute an approved credit exactly once."""
        if approval.status == "executed":
            # The stored result carries the first execution's ``deduplicated: False``;
            # the replay flags must be applied after it so they are not overwritten.
            return {
                **(approval.execution_result or {}),
                "status": "issued",
                "approval_id": approval.approval_id,
                "deduplicated": True,
            }
        if approval.status != "approved":
            return {
                "status": "blocked",
                "effect": "deny",
                "reason": f"approval is {approval.status}; expected approved",
            }

        with _tracer.start_as_current_span(
            "asante.credit.approved_execution",
            attributes={
                "asante.action": "guest.credit.issue.approved",
                "asante.resource.kind": "reservation",
                "asante.delegation.depth": len(delegation_chain),
            },
        ) as execution_span:
            executor_id = self.security.workload_identities.require(
                APPROVAL_EXECUTOR_WORKLOAD
            ).principal_id
            principal = Principal(principal_id=executor_id, principal_type="service")
            now = datetime.now(UTC)
            invocation_expiry = min(task.expires_at, now + timedelta(minutes=5))
            prepared = self.security.invocation_factory.create(
                invoking_principal_id=task.initiated_by,
                executing_principal=principal,
                task=task,
                action="guest.credit.issue.approved",
                resource=f"reservation:{approval.reservation_id}",
                arguments={
                    "amount": approval.amount,
                    "reason": approval.reason,
                    "approval_id": approval.approval_id,
                    "approval_verified": True,
                },
                expires_at=invocation_expiry,
                tool_id=APPROVED_CREDIT_TOOL_ID,
                implementation_id=APPROVED_CREDIT_TOOL_IMPLEMENTATION,
                delegation_chain=delegation_chain,
            )

            started = monotonic_time()
            admission = self.security.execution_controller.begin(prepared.request)
            admission_effect = admission.authorization.effect.value
            record_authorization(
                action="guest.credit.issue.approved",
                effect=admission_effect,
                phase="admission",
                duration_seconds=monotonic_time() - started,
            )
            if not admission.allowed:
                record_credit_execution(outcome="blocked")
                return {
                    "status": "blocked",
                    "effect": admission_effect,
                    "reason": admission.authorization.reason,
                }

            permit = admission.permit
            if permit is None:
                execution_span.set_status(Status(StatusCode.ERROR))
                return {
                    "status": "blocked",
                    "effect": "deny",
                    "reason": "missing execution permit",
                }

            started = monotonic_time()
            live = self.security.execution_controller.revalidate_before_execution(
                prepared.request,
                permit,
            )
            live_effect = live.authorization.effect.value
            record_authorization(
                action="guest.credit.issue.approved",
                effect=live_effect,
                phase="revalidation",
                duration_seconds=monotonic_time() - started,
            )
            if not live.allowed:
                record_credit_execution(outcome="blocked")
                return {
                    "status": "blocked",
                    "effect": live_effect,
                    "reason": live.authorization.reason,
                }

            try:
                provider_result = self.ledger.issue(
                    reservation_id=approval.reservation_id,
                    amount=approval.amount,
                    reason=approval.reason,
                    idempotency_key=f"approved-credit:{approval.approval_id}",
                )
            except Exception as exc:
                execution_span.set_status(Status(StatusCode.ERROR))
                execution_span.set_attribute("error.type", type(exc).__name__)
                self.security.execution_controller.mark_unknown(permit)
                record_credit_execution(outcome="unknown")
                raise

            completed = self.security.execution_controller.complete(permit)
            if not completed:
                raise RuntimeError("approved credit executed but Ruhusa lifecycle did not complete")

            result = {
                **provider_result,
                "approval_id": approval.approval_id,
                "effect": DecisionEffect.ALLOW.value,
                "policy_id": live.authorization.policy_id,
            }
            self.approvals.mark_executed(approval.approval_id, result=result)
            record_credit_execution(outcome="issued")
            return result
