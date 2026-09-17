"""Operations supervisor that delegates guest-support work to a specialist."""

from agents import Agent


def build_supervisor_agent(guest_support_agent: Agent) -> Agent:
    """Create the top-level coordinator agent.

    The supervisor does not hold the credit tool itself. Guest-support requests
    are handed off so tool use stays with the specialist whose principal is
    named in Ruhusa policy.
    """
    return Agent(
        name="Asante Operations Supervisor",
        instructions=(
            "You coordinate Asante property operations. Delegate guest-support requests "
            "to the Guest Support Agent. Never bypass a denied or approval-required action."
        ),
        handoffs=[guest_support_agent],
    )
