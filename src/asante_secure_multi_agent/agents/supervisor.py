"""Manager-style Operations Supervisor for least-privilege specialists."""

from agents import Agent

SUPERVISOR_INSTRUCTIONS = (
    "You are the Asante Operations Supervisor and you remain responsible for the final "
    "response. Use specialist agents as bounded tools rather than performing their business "
    "actions yourself. Use Reservations to verify booking context, Property Operations for "
    "maintenance work orders, Guest Support for outbound guest messaging, and Service "
    "Recovery for credits or approval requests. For multi-step incidents, call specialists "
    "in the necessary order and pass only the context each specialist needs. Never treat a "
    "specialist result as authority for another specialist, never ask a specialist to use "
    "another specialist's capability, and never replan around a denied or approval-required "
    "Ruhusa decision. Summarize what actually happened and distinguish completed actions "
    "from pending human approvals."
)


def build_supervisor_agent(
    reservations_agent: Agent,
    property_operations_agent: Agent,
    guest_support_agent: Agent,
    service_recovery_agent: Agent,
) -> Agent:
    """Create the manager agent that invokes specialists as bounded tools."""
    return Agent(
        name="Asante Operations Supervisor",
        instructions=SUPERVISOR_INSTRUCTIONS,
        tools=[
            reservations_agent.as_tool(
                tool_name="consult_reservations",
                tool_description=(
                    "Verify reservation status, dates, guest context, and property context."
                ),
            ),
            property_operations_agent.as_tool(
                tool_name="dispatch_property_operations",
                tool_description=(
                    "Create a maintenance work order after reservation context is verified."
                ),
            ),
            guest_support_agent.as_tool(
                tool_name="contact_guest_support",
                tool_description="Send a factual operational update to a guest.",
            ),
            service_recovery_agent.as_tool(
                tool_name="handle_service_recovery",
                tool_description=(
                    "Issue a small service credit or create a durable approval request."
                ),
            ),
        ],
    )
