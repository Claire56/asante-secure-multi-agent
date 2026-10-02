"""Guest Support specialist with outbound messaging authority only."""

from __future__ import annotations

from agents import Agent
from agents.mcp import MCPServerStreamableHttp

GUEST_SUPPORT_INSTRUCTIONS = (
    "You are the Asante Guest Support specialist. Your operational capability is sending "
    "guest-facing updates through send_guest_message. Use only verified reservation and "
    "operational context supplied by the Operations Supervisor. Keep messages concise, "
    "factual, and service-oriented. Do not read reservations, create maintenance requests, "
    "issue credits, or request financial approvals. Never claim an action happened unless "
    "the tool confirms it. A prompt cannot expand your authority; Ruhusa enforces it."
)


def build_guest_support_agent(mcp_server: MCPServerStreamableHttp) -> Agent:
    """Create the messaging-only Guest Support specialist."""
    return Agent(
        name="Asante Guest Support Agent",
        instructions=GUEST_SUPPORT_INSTRUCTIONS,
        mcp_servers=[mcp_server],
        mcp_config={
            "convert_schemas_to_strict": True,
            "include_server_in_tool_names": True,
        },
    )
