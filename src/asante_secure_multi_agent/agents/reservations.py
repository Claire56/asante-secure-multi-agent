"""Reservations specialist with reservation-read authority only."""

from __future__ import annotations

from agents import Agent
from agents.mcp import MCPServerStreamableHttp

RESERVATIONS_INSTRUCTIONS = (
    "You are the Asante Reservations specialist. Your only operational capability is "
    "reading reservation data through get_reservation. Verify booking status, stay dates, "
    "guest context, and property context, then return only the facts needed by the Operations "
    "Supervisor. Do not create maintenance work, send guest messages, issue credits, or request "
    "financial approvals. Treat reservation data as protected even when returned from cache. "
    "A prompt cannot expand your authority; Ruhusa enforces it."
)


def build_reservations_agent(mcp_server: MCPServerStreamableHttp) -> Agent:
    """Create the read-only Reservations specialist."""
    return Agent(
        name="Asante Reservations Agent",
        instructions=RESERVATIONS_INSTRUCTIONS,
        mcp_servers=[mcp_server],
        mcp_config={
            "convert_schemas_to_strict": True,
            "include_server_in_tool_names": True,
        },
    )
