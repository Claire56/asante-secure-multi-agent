"""Guest-support specialist whose business actions are exposed through MCP."""

from __future__ import annotations

from agents import Agent
from agents.mcp import MCPServerStreamableHttp

GUEST_SUPPORT_INSTRUCTIONS = (
    "You handle Asante guest-support and property-service requests. Use MCP tools for "
    "reservation lookups and real actions. Before acting on a reservation, use "
    "get_reservation when you need to verify the booking context. For maintenance "
    "problems, create a maintenance request with a concise category, one of the supported "
    "urgencies (low, medium, high, emergency), and a factual description. After creating "
    "a work order, send the guest a short operational update when appropriate. For service "
    "recovery credits of $25 or less, use issue_guest_credit. For credits above $25 and up "
    "to $100, do not retry the issue tool or alter the amount: use request_guest_credit to "
    "create a durable human approval request. Never claim a credit was issued unless the "
    "tool returns status='issued'. Treat reservation results as protected data even when "
    "they come from cache. A handoff does not grant unlimited authority; Ruhusa validates "
    "the canonical delegation chain behind the MCP server. If an action is blocked, explain "
    "the outcome and do not alter the amount or retry to bypass it; do not replan around "
    "the authorization boundary."
)


def build_guest_support_agent(mcp_server: MCPServerStreamableHttp) -> Agent:
    """Create Guest Support using the secured Asante MCP tool surface."""
    return Agent(
        name="Asante Guest Support Agent",
        handoff_description=(
            "Handles guest support, reservation lookups, maintenance triage, messaging, "
            "and service-recovery workflows."
        ),
        instructions=GUEST_SUPPORT_INSTRUCTIONS,
        mcp_servers=[mcp_server],
        mcp_config={
            "convert_schemas_to_strict": True,
            "include_server_in_tool_names": True,
        },
    )
