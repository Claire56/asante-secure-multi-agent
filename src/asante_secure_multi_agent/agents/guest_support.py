"""Guest-support specialist that can issue service-recovery credits.

The agent is allowed to call the credit tool, but Ruhusa still decides whether
the side effect may execute. Instructions tell the model to surface a blocked
or approval-required outcome instead of retrying with a different amount.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agents import Agent, RunContextWrapper, function_tool
from ruhusa import TaskContext

from asante_secure_multi_agent.tools.guest_credit import SecuredGuestCreditTool


def build_guest_support_agent(credit_tool: SecuredGuestCreditTool) -> Agent:
    """Create the guest-support agent bound to a secured credit tool.

    The nested ``issue_guest_credit`` function is registered as an OpenAI Agents
    SDK tool. It translates SDK run context into a Ruhusa ``TaskContext`` before
    calling the authorization-gated implementation.
    """

    @function_tool
    def issue_guest_credit(
        ctx: RunContextWrapper[dict[str, str]],
        reservation_id: str,
        amount: float,
        reason: str,
    ) -> dict[str, object]:
        """Issue a service-recovery credit to an Asante guest reservation.

        Args:
            ctx: SDK wrapper holding ``task_id`` and ``initiated_by`` from the API.
            reservation_id: Guest reservation to credit, for example ``R-1001``.
            amount: Credit in USD. Policy allows up to $25, requires approval
                through $100, and denies larger amounts.
            reason: Why the credit is being issued (outage, late check-in, etc.).

        Returns:
            Ledger result when authorized, or a blocked payload with the Ruhusa
            decision effect and reason.
        """
        task_id = ctx.context.get("task_id", "interactive-task")
        initiated_by = ctx.context.get("initiated_by", "user:asante-operator")
        # Task expiry is the outer bound; the tool still shortens invocation
        # lifetime so a stale grant cannot be reused later in the same task.
        task = TaskContext(
            task_id=task_id,
            initiated_by=initiated_by,
            purpose="guest service recovery",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        return credit_tool.issue_credit(
            reservation_id=reservation_id,
            amount=amount,
            reason=reason,
            task=task,
        )

    return Agent(
        name="Asante Guest Support Agent",
        handoff_description="Handles guest support and service-recovery requests.",
        instructions=(
            "You handle Asante guest-support requests. Use tools for real actions. "
            "Never claim a credit was issued unless the tool returns status='issued'. "
            "If Ruhusa blocks an action or requires approval, explain that outcome and "
            "do not try another tool or altered amount to bypass the decision."
        ),
        tools=[issue_guest_credit],
    )
