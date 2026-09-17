"""Guest-credit tool with Ruhusa authorization around a fake ledger.

The ledger is a stand-in for a PMS or payment system. Replacing it later should
not change the identity, invocation, delegation, admission, revalidation, and
completion sequence that fences the side effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from ruhusa import DecisionEffect, DelegationGrant, Principal, TaskContext

from asante_secure_multi_agent.identity import GUEST_SUPPORT_WORKLOAD, SUPERVISOR_WORKLOAD
from asante_secure_multi_agent.security.runtime import (
    CREDIT_TOOL_ID,
    CREDIT_TOOL_IMPLEMENTATION,
    AsanteSecurityRuntime,
)


@dataclass
class GuestCreditLedger:
    """Fake external system for the current learning phase."""

    credits: list[dict[str, object]] = field(default_factory=list)

    def issue(self, *, reservation_id: str, amount: float, reason: str) -> dict[str, object]:
        """Record an issued credit and return the ledger row."""
        credit = {
            "reservation_id": reservation_id,
            "amount": amount,
            "reason": reason,
            "status": "issued",
        }
        self.credits.append(credit)
        return credit


class SecuredGuestCreditTool:
    """Issue guest credits only after Ruhusa admits and revalidates the action."""

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
        delegation_chain: tuple[DelegationGrant, ...],
    ) -> dict[str, object]:
        """Resolve trusted workload identities, authorize, fence, then execute."""
        supervisor_id = self.security.workload_identities.require(SUPERVISOR_WORKLOAD).principal_id
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
