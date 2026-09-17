"""Guest-credit tool with Ruhusa authorization around a fake ledger.

The ledger is a stand-in for a PMS or payment system. Replacing it later should
not change the invocation, delegation, admission, revalidation, and completion
sequence that fences the side effect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from ruhusa import DecisionEffect, DelegationGrant, Principal, TaskContext

from asante_secure_multi_agent.security.runtime import (
    CREDIT_TOOL_ID,
    CREDIT_TOOL_IMPLEMENTATION,
    GUEST_SUPPORT_AGENT_ID,
    SUPERVISOR_AGENT_ID,
    AsanteSecurityRuntime,
)


@dataclass
class GuestCreditLedger:
    """Fake external system for the current learning phase.

    Replacing this with a real PMS/payment adapter later should not change the Ruhusa
    authorization boundary around it.
    """

    credits: list[dict[str, object]] = field(default_factory=list)

    def issue(self, *, reservation_id: str, amount: float, reason: str) -> dict[str, object]:
        """Record an issued credit and return the ledger row.

        This method is the unprotected side effect. Callers must go through
        ``SecuredGuestCreditTool.issue_credit`` so Ruhusa can admit and complete
        the execution first.
        """
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
        """Authorize delegated authority, fence, revalidate, then execute.

        Flow:
            1. Receive the canonical human -> supervisor -> guest-support grants.
            2. Create trusted invocation provenance for supervisor -> guest-support.
            3. Ask Ruhusa to validate delegation, provenance, policy, and admission.
            4. Revalidate immediately before the ledger write (TOCTOU fence).
            5. Write the credit, then complete the execution lifecycle.

        The delegation chain is required. Agent orchestration by itself is not
        authority, so this tool has no direct/no-grant execution path.

        Returns:
            Issued credit plus policy metadata, or a ``blocked`` payload when
            Ruhusa denies or requires approval.

        Raises:
            RuntimeError: The ledger write succeeded but Ruhusa could not mark
                the execution complete.
        """
        principal = Principal(principal_id=GUEST_SUPPORT_AGENT_ID, principal_type="agent")
        now = datetime.now(UTC)
        # Cap invocation lifetime below the task expiry so a long-lived task
        # cannot reuse stale authority minutes later.
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
            # Ambiguous outcome: the side effect may or may not have landed.
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
