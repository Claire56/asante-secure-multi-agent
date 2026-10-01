"""Guest-credit side effect fenced by Ruhusa and protected for safe retries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from opentelemetry.trace import Status, StatusCode
from ruhusa import DecisionEffect, DelegationGrant, Principal, TaskContext

from asante_secure_multi_agent.identity import GUEST_SUPPORT_WORKLOAD, SUPERVISOR_WORKLOAD
from asante_secure_multi_agent.reliability import (
    CreditProvider,
    RetryPolicy,
    build_credit_idempotency_key,
    execute_with_bounded_retry,
)
from asante_secure_multi_agent.security.runtime import (
    CREDIT_TOOL_ID,
    CREDIT_TOOL_IMPLEMENTATION,
    AsanteSecurityRuntime,
)
from asante_secure_multi_agent.telemetry import get_tracer
from asante_secure_multi_agent.telemetry.metrics import (
    monotonic_time,
    record_authorization,
    record_credit_deduplication,
    record_credit_execution,
    record_credit_retry,
)

_tracer = get_tracer()


@dataclass
class GuestCreditLedger:
    """Fake external system with server-side idempotency for the learning app."""

    credits: list[dict[str, object]] = field(default_factory=list)
    _by_idempotency_key: dict[str, dict[str, object]] = field(
        default_factory=dict,
        repr=False,
    )

    def issue(
        self,
        *,
        reservation_id: str,
        amount: float,
        reason: str,
        idempotency_key: str | None = None,
    ) -> dict[str, object]:
        """Record one credit, deduplicating a repeated logical operation."""
        if idempotency_key is not None:
            existing = self._by_idempotency_key.get(idempotency_key)
            if existing is not None:
                return {**existing, "deduplicated": True}

        credit = {
            "reservation_id": reservation_id,
            "amount": amount,
            "reason": reason,
            "status": "issued",
        }
        self.credits.append(credit)
        if idempotency_key is not None:
            self._by_idempotency_key[idempotency_key] = credit
        return {**credit, "deduplicated": False}


class SecuredGuestCreditTool:
    """Issue guest credits only after Ruhusa admits and revalidates the action."""

    def __init__(
        self,
        security: AsanteSecurityRuntime,
        ledger: CreditProvider,
        *,
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.security = security
        self.ledger = ledger
        self.retry_policy = retry_policy or RetryPolicy()

    def issue_credit(
        self,
        *,
        reservation_id: str,
        amount: float,
        reason: str,
        task: TaskContext,
        delegation_chain: tuple[DelegationGrant, ...],
    ) -> dict[str, object]:
        """Resolve identity, authorize, revalidate, execute, and emit safe telemetry."""
        with _tracer.start_as_current_span(
            "asante.credit.secured_execution",
            attributes={
                "asante.action": "guest.credit.issue",
                "asante.resource.kind": "reservation",
                "asante.delegation.depth": len(delegation_chain),
            },
        ) as execution_span:
            supervisor_id = self.security.workload_identities.require(
                SUPERVISOR_WORKLOAD
            ).principal_id
            guest_support_id = self.security.workload_identities.require(
                GUEST_SUPPORT_WORKLOAD
            ).principal_id
            principal = Principal(principal_id=guest_support_id, principal_type="agent")
            now = datetime.now(UTC)
            invocation_expiry = min(task.expires_at, now + timedelta(minutes=5))

            prepared = self.security.invocation_factory.create(
                invoking_principal_id=supervisor_id,
                executing_principal=principal,
                task=task,
                action="guest.credit.issue",
                resource=f"reservation:{reservation_id}",
                arguments={"amount": amount, "reason": reason},
                expires_at=invocation_expiry,
                tool_id=CREDIT_TOOL_ID,
                implementation_id=CREDIT_TOOL_IMPLEMENTATION,
                delegation_chain=delegation_chain,
            )

            started = monotonic_time()
            with _tracer.start_as_current_span(
                "ruhusa.authorization.admission",
                attributes={"asante.action": "guest.credit.issue"},
            ) as admission_span:
                admission = self.security.execution_controller.begin(prepared.request)
                admission_effect = admission.authorization.effect.value
                admission_span.set_attribute("asante.authorization.effect", admission_effect)
                if admission.authorization.policy_id:
                    admission_span.set_attribute(
                        "asante.authorization.policy_id",
                        admission.authorization.policy_id,
                    )
            record_authorization(
                action="guest.credit.issue",
                effect=admission_effect,
                phase="admission",
                duration_seconds=monotonic_time() - started,
            )

            if not admission.allowed:
                execution_span.set_attribute("asante.execution.outcome", "blocked")
                record_credit_execution(outcome="blocked")
                return {
                    "status": "blocked",
                    "effect": admission_effect,
                    "reason": admission.authorization.reason,
                }

            permit = admission.permit
            if permit is None:
                execution_span.set_status(Status(StatusCode.ERROR))
                execution_span.set_attribute("error.type", "missing_execution_permit")
                record_credit_execution(outcome="error")
                return {
                    "status": "blocked",
                    "effect": "deny",
                    "reason": "missing execution permit",
                }

            started = monotonic_time()
            with _tracer.start_as_current_span(
                "ruhusa.authorization.revalidation",
                attributes={"asante.action": "guest.credit.issue"},
            ) as live_span:
                live = self.security.execution_controller.revalidate_before_execution(
                    prepared.request,
                    permit,
                )
                live_effect = live.authorization.effect.value
                live_span.set_attribute("asante.authorization.effect", live_effect)
                if live.authorization.policy_id:
                    live_span.set_attribute(
                        "asante.authorization.policy_id",
                        live.authorization.policy_id,
                    )
            record_authorization(
                action="guest.credit.issue",
                effect=live_effect,
                phase="revalidation",
                duration_seconds=monotonic_time() - started,
            )

            if not live.allowed:
                execution_span.set_attribute("asante.execution.outcome", "blocked")
                record_credit_execution(outcome="blocked")
                return {
                    "status": "blocked",
                    "effect": live_effect,
                    "reason": live.authorization.reason,
                }

            idempotency_key = build_credit_idempotency_key(
                task_id=task.task_id,
                reservation_id=reservation_id,
                amount=amount,
            )

            try:
                with _tracer.start_as_current_span(
                    "asante.credit.provider_write",
                    attributes={"asante.side_effect.system": "in_memory_credit_ledger"},
                ):
                    result = execute_with_bounded_retry(
                        lambda: self.ledger.issue(
                            reservation_id=reservation_id,
                            amount=amount,
                            reason=reason,
                            idempotency_key=idempotency_key,
                        ),
                        policy=self.retry_policy,
                        on_retry=lambda attempt: record_credit_retry(attempt=attempt),
                    )
            except Exception as exc:
                # A provider adapter should raise TransientCreditProviderError only when
                # it knows no side effect happened. Any failure that escapes the bounded
                # retry loop is conservatively marked unknown in the Ruhusa lifecycle.
                execution_span.set_status(Status(StatusCode.ERROR))
                execution_span.set_attribute("error.type", type(exc).__name__)
                self.security.execution_controller.mark_unknown(permit)
                record_credit_execution(outcome="unknown")
                raise

            completed = self.security.execution_controller.complete(permit)
            if not completed:
                execution_span.set_status(Status(StatusCode.ERROR))
                execution_span.set_attribute("error.type", "execution_completion_failed")
                record_credit_execution(outcome="error")
                raise RuntimeError(
                    "credit executed but Ruhusa could not complete execution lifecycle"
                )

            deduplicated = bool(result.get("deduplicated", False))
            outcome = "deduplicated" if deduplicated else "issued"
            if deduplicated:
                record_credit_deduplication()
            execution_span.set_attribute("asante.execution.outcome", outcome)
            record_credit_execution(outcome=outcome)
            return {
                **result,
                "effect": DecisionEffect.ALLOW.value,
                "policy_id": live.authorization.policy_id,
            }
