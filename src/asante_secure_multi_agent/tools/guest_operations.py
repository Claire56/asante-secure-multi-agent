"""Secured Asante guest messaging, maintenance, and approval-request actions."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from opentelemetry.trace import Status, StatusCode
from ruhusa import DecisionEffect, DelegationGrant, Principal, TaskContext

from asante_secure_multi_agent.approvals import SQLiteApprovalStore
from asante_secure_multi_agent.identity import (
    GUEST_SUPPORT_WORKLOAD,
    PROPERTY_OPERATIONS_WORKLOAD,
    SERVICE_RECOVERY_WORKLOAD,
    SUPERVISOR_WORKLOAD,
)
from asante_secure_multi_agent.security.runtime import (
    GUEST_OPERATIONS_TOOL_ID,
    GUEST_OPERATIONS_TOOL_IMPLEMENTATION,
    AsanteSecurityRuntime,
)
from asante_secure_multi_agent.telemetry import get_tracer
from asante_secure_multi_agent.telemetry.metrics import (
    monotonic_time,
    record_authorization,
    record_operation_execution,
)

_tracer = get_tracer()

MAINTENANCE_URGENCIES = frozenset({"low", "medium", "high", "emergency"})


def _idempotency_key(action: str, task_id: str, reservation_id: str, payload: str) -> str:
    canonical = f"{action}\n{task_id}\n{reservation_id}\n{payload}"
    return "operation:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class MaintenanceWorkOrderStore:
    """In-memory maintenance provider with task-local idempotency."""

    work_orders: list[dict[str, object]] = field(default_factory=list)
    _by_key: dict[str, dict[str, object]] = field(default_factory=dict, repr=False)

    def create(
        self,
        *,
        reservation_id: str,
        category: str,
        urgency: str,
        description: str,
        idempotency_key: str,
    ) -> dict[str, object]:
        existing = self._by_key.get(idempotency_key)
        if existing is not None:
            return {**existing, "deduplicated": True}
        work_order = {
            "work_order_id": f"WO-{uuid4().hex[:10].upper()}",
            "reservation_id": reservation_id,
            "category": category,
            "urgency": urgency,
            "description": description,
            "status": "open",
            "created_at": datetime.now(UTC).isoformat(),
        }
        self.work_orders.append(work_order)
        self._by_key[idempotency_key] = work_order
        return {**work_order, "deduplicated": False}


@dataclass
class GuestMessageOutbox:
    """In-memory outbound guest-message provider with idempotency."""

    messages: list[dict[str, object]] = field(default_factory=list)
    _by_key: dict[str, dict[str, object]] = field(default_factory=dict, repr=False)

    def send(
        self,
        *,
        reservation_id: str,
        message: str,
        idempotency_key: str,
    ) -> dict[str, object]:
        existing = self._by_key.get(idempotency_key)
        if existing is not None:
            return {**existing, "deduplicated": True}
        outbound = {
            "message_id": f"MSG-{uuid4().hex[:10].upper()}",
            "reservation_id": reservation_id,
            "message": message,
            "status": "sent",
            "sent_at": datetime.now(UTC).isoformat(),
        }
        self.messages.append(outbound)
        self._by_key[idempotency_key] = outbound
        return {**outbound, "deduplicated": False}


class SecuredGuestOperationsTool:
    """Execute guest operations only after live Ruhusa authorization succeeds."""

    def __init__(
        self,
        security: AsanteSecurityRuntime,
        maintenance: MaintenanceWorkOrderStore,
        messages: GuestMessageOutbox,
        approvals: SQLiteApprovalStore,
    ) -> None:
        self.security = security
        self.maintenance = maintenance
        self.messages = messages
        self.approvals = approvals

    def create_maintenance_request(
        self,
        *,
        reservation_id: str,
        category: str,
        urgency: str,
        description: str,
        task: TaskContext,
        delegation_chain: tuple[DelegationGrant, ...],
    ) -> dict[str, object]:
        """Create one idempotent maintenance work order after authorization."""
        normalized_urgency = urgency.strip().lower()
        if normalized_urgency not in MAINTENANCE_URGENCIES:
            return {
                "status": "blocked",
                "effect": "deny",
                "reason": f"unsupported maintenance urgency: {urgency}",
            }
        payload = f"{category.strip()}\n{normalized_urgency}\n{description.strip()}"
        key = _idempotency_key("maintenance.create", task.task_id, reservation_id, payload)
        return self._execute(
            action="maintenance.create",
            executing_workload=PROPERTY_OPERATIONS_WORKLOAD,
            reservation_id=reservation_id,
            arguments={
                "category": category,
                "urgency": normalized_urgency,
                "description": description,
            },
            task=task,
            delegation_chain=delegation_chain,
            operation=lambda: self.maintenance.create(
                reservation_id=reservation_id,
                category=category,
                urgency=normalized_urgency,
                description=description,
                idempotency_key=key,
            ),
        )

    def send_guest_message(
        self,
        *,
        reservation_id: str,
        message: str,
        task: TaskContext,
        delegation_chain: tuple[DelegationGrant, ...],
    ) -> dict[str, object]:
        """Send one idempotent guest update after authorization."""
        if not message.strip():
            return {"status": "blocked", "effect": "deny", "reason": "message is empty"}
        key = _idempotency_key(
            "guest.message.send",
            task.task_id,
            reservation_id,
            message.strip(),
        )
        return self._execute(
            action="guest.message.send",
            executing_workload=GUEST_SUPPORT_WORKLOAD,
            reservation_id=reservation_id,
            arguments={"message": message},
            task=task,
            delegation_chain=delegation_chain,
            operation=lambda: self.messages.send(
                reservation_id=reservation_id,
                message=message,
                idempotency_key=key,
            ),
        )

    def request_guest_credit(
        self,
        *,
        reservation_id: str,
        amount: float,
        reason: str,
        task: TaskContext,
        delegation_chain: tuple[DelegationGrant, ...],
    ) -> dict[str, object]:
        """Create a durable approval request; this never issues the credit itself."""

        def create_request() -> dict[str, object]:
            existing = self.approvals.find_credit_request(
                task_id=task.task_id,
                reservation_id=reservation_id,
                amount=amount,
            )
            record = self.approvals.create_credit_request(
                task_id=task.task_id,
                requested_by=task.initiated_by,
                reservation_id=reservation_id,
                amount=amount,
                reason=reason,
                policy_id="service-recovery-credit-request",
            )
            return {
                # A repeated request reports the existing record's real state.
                "status": f"approval_{record.status}",
                "approval_id": record.approval_id,
                "reservation_id": reservation_id,
                "amount": amount,
                "reason": record.reason,
                "deduplicated": existing is not None,
            }

        return self._execute(
            action="guest.credit.request",
            executing_workload=SERVICE_RECOVERY_WORKLOAD,
            reservation_id=reservation_id,
            arguments={"amount": amount, "reason": reason},
            task=task,
            delegation_chain=delegation_chain,
            operation=create_request,
        )

    def _execute(
        self,
        *,
        action: str,
        executing_workload: str,
        reservation_id: str,
        arguments: dict[str, object],
        task: TaskContext,
        delegation_chain: tuple[DelegationGrant, ...],
        operation: Callable[[], dict[str, object]],
    ) -> dict[str, object]:
        with _tracer.start_as_current_span(
            "asante.guest_operation.secured_execution",
            attributes={
                "asante.action": action,
                "asante.resource.kind": "reservation",
                "asante.delegation.depth": len(delegation_chain),
                "asante.workload": executing_workload,
            },
        ) as execution_span:
            supervisor_id = self.security.workload_identities.require(
                SUPERVISOR_WORKLOAD
            ).principal_id
            executing_principal_id = self.security.workload_identities.require(
                executing_workload
            ).principal_id
            principal = Principal(
                principal_id=executing_principal_id,
                principal_type="agent",
            )
            now = datetime.now(UTC)
            invocation_expiry = min(task.expires_at, now + timedelta(minutes=5))
            prepared = self.security.invocation_factory.create(
                invoking_principal_id=supervisor_id,
                executing_principal=principal,
                task=task,
                action=action,
                resource=f"reservation:{reservation_id}",
                arguments=arguments,
                expires_at=invocation_expiry,
                tool_id=GUEST_OPERATIONS_TOOL_ID,
                implementation_id=GUEST_OPERATIONS_TOOL_IMPLEMENTATION,
                delegation_chain=delegation_chain,
            )

            started = monotonic_time()
            admission = self.security.execution_controller.begin(prepared.request)
            admission_effect = admission.authorization.effect.value
            record_authorization(
                action=action,
                effect=admission_effect,
                phase="admission",
                duration_seconds=monotonic_time() - started,
            )
            if not admission.allowed:
                execution_span.set_attribute("asante.execution.outcome", "blocked")
                record_operation_execution(action=action, outcome="blocked")
                return {
                    "status": "blocked",
                    "effect": admission_effect,
                    "reason": admission.authorization.reason,
                }

            permit = admission.permit
            if permit is None:
                execution_span.set_status(Status(StatusCode.ERROR))
                record_operation_execution(action=action, outcome="error")
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
                action=action,
                effect=live_effect,
                phase="revalidation",
                duration_seconds=monotonic_time() - started,
            )
            if not live.allowed:
                execution_span.set_attribute("asante.execution.outcome", "blocked")
                record_operation_execution(action=action, outcome="blocked")
                return {
                    "status": "blocked",
                    "effect": live_effect,
                    "reason": live.authorization.reason,
                }

            try:
                result = operation()
            except Exception as exc:
                execution_span.set_status(Status(StatusCode.ERROR))
                execution_span.set_attribute("error.type", type(exc).__name__)
                self.security.execution_controller.mark_unknown(permit)
                record_operation_execution(action=action, outcome="unknown")
                raise

            completed = self.security.execution_controller.complete(permit)
            if not completed:
                execution_span.set_status(Status(StatusCode.ERROR))
                record_operation_execution(action=action, outcome="error")
                raise RuntimeError("operation executed but Ruhusa lifecycle did not complete")

            outcome = str(result.get("status", "completed"))
            execution_span.set_attribute("asante.execution.outcome", outcome)
            record_operation_execution(action=action, outcome=outcome)
            return {
                **result,
                "effect": DecisionEffect.ALLOW.value,
                "policy_id": live.authorization.policy_id,
            }
