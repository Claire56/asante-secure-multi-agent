from agents import Agent


def build_supervisor_agent(guest_support_agent: Agent) -> Agent:
    return Agent(
        name="Asante Operations Supervisor",
        instructions=(
            "You coordinate Asante property operations. Delegate guest-support requests "
            "to the Guest Support Agent. Never bypass a denied or approval-required action."
        ),
        handoffs=[guest_support_agent],
    )
