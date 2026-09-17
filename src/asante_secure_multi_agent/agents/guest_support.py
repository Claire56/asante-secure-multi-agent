"""Guest-support specialist that can issue service-recovery credits.

The agent is allowed to call the credit tool, but Ruhusa still decides whether
the side effect may execute. Phase 2 also requires a canonical delegation chain:
the SDK handoff alone does not transfer authority.
"""

from __future__ import annotations

from agents import Agent, RunContextWrapper, function_tool

from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.tools.guest_credit import SecuredGuestCreditTool


def build_guest_support_agent(credit_tool: SecuredGuestCreditTool) -> Agent:
    """Create the guest-support agent bound to a secured credit tool.

    The nested ``issue_guest_credit`` function is registered as an OpenAI Agents
    SDK tool. It translates SDK run context into the task and canonical Ruhusa
    delegation chain created by trusted application infrastructure.
    """

    @function_tool
    def issue_guest_credit(
        ctx: RunContextWrapper[AsanteRunContext],
        reservation_id: str,
        amount: float,
        reason: str,
    ) -> dict[str, object]:
        """Issue a service-recovery credit to an Asante guest reservation.

        Args:
            ctx: SDK wrapper holding trusted task and delegation state.
            reservation_id: Guest reservation to credit, for example ``R-1001``.
            amount: Credit in USD. Default delegated authority is capped at $25.
            reason: Why the credit is being issued (outage, late check-in, etc.).

        Returns:
            Ledger result when authorized, or a blocked payload with the Ruhusa
            decision effect and reason.
        """
        return credit_tool.issue_credit(
            reservation_id=reservation_id,
            amount=amount,
            reason=reason,
            task=ctx.context.task,
            delegation_chain=ctx.context.guest_support_delegation,
        )

    return Agent(
        name="Asante Guest Support Agent",
        handoff_description="Handles guest support and service-recovery requests.",
        instructions=(
            "You handle Asante guest-support requests. Use tools for real actions. "
            "Never claim a credit was issued unless the tool returns status='issued'. "
            "A handoff does not give you unlimited authority: Ruhusa enforces the "
            "delegation chain. If an action is blocked or requires approval, explain "
            "that outcome and do not alter the amount or retry to bypass it."
        ),
        tools=[issue_guest_credit],
    )
