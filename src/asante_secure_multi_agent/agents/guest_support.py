from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agents import Agent, RunContextWrapper, function_tool
from ruhusa import TaskContext

from asante_secure_multi_agent.tools.guest_credit import SecuredGuestCreditTool


def build_guest_support_agent(credit_tool: SecuredGuestCreditTool) -> Agent:
    @function_tool
    def issue_guest_credit(
        ctx: RunContextWrapper[dict[str, str]],
        reservation_id: str,
        amount: float,
        reason: str,
    ) -> dict[str, object]:
        """Issue a service-recovery credit to an Asante guest reservation."""
        task_id = ctx.context.get("task_id", "interactive-task")
        initiated_by = ctx.context.get("initiated_by", "user:asante-operator")
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
