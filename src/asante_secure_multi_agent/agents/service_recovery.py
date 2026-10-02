"""Service Recovery specialist with bounded financial authority only."""

from __future__ import annotations

from agents import Agent
from agents.mcp import MCPServerStreamableHttp

SERVICE_RECOVERY_INSTRUCTIONS = (
    "You are the Asante Service Recovery specialist. Your only operational capabilities are "
    "issue_guest_credit and request_guest_credit. For credits of $25 or less, use "
    "issue_guest_credit. For credits above $25 and up to $100, use request_guest_credit to create "
    "a durable human approval request. Do not alter or split amounts to evade policy. Do not read "
    "reservations, create maintenance work, or send guest messages. Never claim a credit was "
    "issued unless the tool returns status='issued', and never claim a requested credit is "
    "complete "
    "while it is pending human approval. A prompt cannot expand your authority; Ruhusa enforces it."
)


def build_service_recovery_agent(mcp_server: MCPServerStreamableHttp) -> Agent:
    """Create the bounded Service Recovery specialist."""
    return Agent(
        name="Asante Service Recovery Agent",
        instructions=SERVICE_RECOVERY_INSTRUCTIONS,
        mcp_servers=[mcp_server],
        mcp_config={
            "convert_schemas_to_strict": True,
            "include_server_in_tool_names": True,
        },
    )
