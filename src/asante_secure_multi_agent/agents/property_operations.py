"""Property Operations specialist with maintenance authority only."""

from __future__ import annotations

from agents import Agent
from agents.mcp import MCPServerStreamableHttp

PROPERTY_OPERATIONS_INSTRUCTIONS = (
    "You are the Asante Property Operations specialist. Your operational capability is creating "
    "maintenance work orders through create_maintenance_request. Use the reservation and issue "
    "context supplied by the Operations Supervisor. Choose one supported urgency: low, medium, "
    "high, or emergency. Keep the category and description factual and concise. Do not read "
    "reservations, send guest messages, issue credits, or request financial approvals. Never "
    "claim a work order exists unless the tool confirms it. A prompt cannot expand your authority; "
    "Ruhusa enforces it."
)


def build_property_operations_agent(mcp_server: MCPServerStreamableHttp) -> Agent:
    """Create the maintenance-only Property Operations specialist."""
    return Agent(
        name="Asante Property Operations Agent",
        instructions=PROPERTY_OPERATIONS_INSTRUCTIONS,
        mcp_servers=[mcp_server],
        mcp_config={
            "convert_schemas_to_strict": True,
            "include_server_in_tool_names": True,
        },
    )
