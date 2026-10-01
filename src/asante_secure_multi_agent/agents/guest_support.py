"""Guest-support specialist whose business actions are exposed through MCP."""

from __future__ import annotations

from agents import Agent
from agents.mcp import MCPServerStreamableHttp

GUEST_SUPPORT_INSTRUCTIONS = (
    "You handle Asante guest-support requests. Use the MCP tools for real actions and "
    "reservation lookups. Treat get_reservation results as protected data even when they "
    "come from cache. Never claim a credit was issued unless the MCP tool returns "
    "status='issued'. "
    "A handoff does not give you unlimited authority: Ruhusa validates the canonical "
    "delegation chain behind the MCP server. If an action is blocked or requires "
    "approval, explain that outcome and do not alter the amount or retry to bypass it."
)


def build_guest_support_agent(mcp_server: MCPServerStreamableHttp) -> Agent:
    """Create Guest Support using the secured Asante MCP tool surface."""
    return Agent(
        name="Asante Guest Support Agent",
        handoff_description="Handles guest support and service-recovery requests.",
        instructions=GUEST_SUPPORT_INSTRUCTIONS,
        mcp_servers=[mcp_server],
        mcp_config={
            "convert_schemas_to_strict": True,
            "include_server_in_tool_names": True,
        },
    )
