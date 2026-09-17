from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from ruhusa import DecisionEffect, Principal, TaskContext

from asante_secure_multi_agent.security.runtime import (
    CREDIT_TOOL_ID,
    CREDIT_TOOL_IMPLEMENTATION,
    GUEST_SUPPORT_AGENT_ID,
    SUPERVISOR_AGENT_ID,
    AsanteSecurityRuntime,
)


@dataclass
class GuestCreditLedger:
    """Fake external system for phase 1.

    Replacing this with a real PMS/payment adapter later should not change the Ruhusa
    authorization boundary around it.
    """

    credits: list[dict[str, object]] = field(default_factory=list)

    def issue(self, *, reservation_id: str, amount: float, reason: str) -> dict[str, object]:
        credit = {
            "reservation_id": reservation_id,
            "amount": amount,
            "reason": reason,
            "status": "issued",
        }
        self.credits.append(credit)
        return credit


class SecuredGuestCreditTool:
    def __init__(self, security: AsanteSecurityRuntime, ledger: GuestCreditLedger) -> None:
        self.security = security
        self.ledger = ledger

    def issue_credit(
        self,
        *,
        reservation_id: str,
        amount: float,
        reason: str,
        task: TaskContext,
    ) -> dict[str, object]:
        """Authorize, fence, revalidate, then perform the protected side effect."""
        principal = Principal(principal_id=GUEST_SUPPORT_AGENT_ID, principal_type="agent")
        now = datetime.now(UTC)
        invocation_expiry = min(task.expires_at, now + timedelta(minutes=5))

        prepared = self.security.invocation_factory.create(
            invoking_principal_id=SUPERVISOR_AGENT_ID,
            executing_principal=principal,
            task=task,
            action="guest.credit.issue",
            resource=f"reservation:{reservation_id}",
            arguments={"amount": amount, "reason": reason},
            expires_at=invocation_expiry,
            tool_id=CREDIT_TOOL_ID,
            implementation_id=CREDIT_TOOL_IMPLEMENTATION,
        )

        admission = self.security.execution_controller.begin(prepared.request)
        if not admission.allowed:
            return {
                "status": "blocked",
                "effect": admission.authorization.effect.value,
                "reason": admission.authorization.reason,
            }

        permit = admission.permit
        if permit is None:
            return {"status": "blocked", "effect": "deny", "reason": "missing execution permit"}

        live = self.security.execution_controller.revalidate_before_execution(
            prepared.request,
            permit,
        )
        if not live.allowed:
            return {
                "status": "blocked",
                "effect": live.authorization.effect.value,
                "reason": live.authorization.reason,
            }

        try:
            result = self.ledger.issue(
                reservation_id=reservation_id,
                amount=amount,
                reason=reason,
            )
        except Exception:
            self.security.execution_controller.mark_unknown(permit)
            raise

        completed = self.security.execution_controller.complete(permit)
        if not completed:
            raise RuntimeError("credit executed but Ruhusa could not complete execution lifecycle")

        return {
            **result,
            "effect": DecisionEffect.ALLOW.value,
            "policy_id": live.authorization.policy_id,
        }
